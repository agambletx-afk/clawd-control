import Database from 'better-sqlite3';
import { existsSync, readFileSync, statSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';
import { createHash } from 'crypto';

const DB_PATH = join(new URL('.', import.meta.url).pathname, 'tasks.db');

let db;
let taskTypeConfigCache = null;
let taskTypeConfigMtime = 0;

const VALID_STATUSES = new Set(['proposed', 'backlog', 'in_progress', 'review', 'done', 'archive', 'failed']);
const VALID_PRIORITIES = new Set(['critical', 'high', 'medium', 'low']);
const VALID_SOURCES = new Set(['dashboard', 'telegram', 'cron', 'agent']);
const VALID_GOAL_STATUSES = new Set(['active', 'paused', 'completed', 'archived']);
const VALID_GOAL_PERIODS = new Set(['day', 'week']);

function normalizeTransitionSource(source) {
  const raw = typeof source === 'string' && source.trim() ? source.trim().toLowerCase() : 'human';
  if (raw === 'human' || raw === 'dashboard') return 'human';
  if (raw === 'system') return 'system';
  return 'non_human';
}

export function validateTransition(currentStatus, newStatus, source) {
  if (!VALID_STATUSES.has(currentStatus) || !VALID_STATUSES.has(newStatus)) {
    return { valid: false, reason: 'invalid_status', validTransitions: [] };
  }

  const sourceKind = normalizeTransitionSource(source);
  const transitionRules = {
    proposed: [
      { to: 'backlog', allowed: new Set(['human']) },
      { to: 'archive', allowed: new Set(['human']) },
      { to: 'failed', allowed: new Set(['system']) },
    ],
    backlog: [
      { to: 'in_progress', allowed: new Set(['human', 'non_human', 'system']) },
      { to: 'failed', allowed: new Set(['system']) },
    ],
    in_progress: [
      { to: 'review', allowed: new Set(['human', 'non_human', 'system']) },
      { to: 'backlog', allowed: new Set(['human', 'non_human', 'system']) },
      { to: 'failed', allowed: new Set(['system']) },
    ],
    review: [
      { to: 'done', allowed: new Set(['human']) },
      { to: 'backlog', allowed: new Set(['human']) },
      { to: 'failed', allowed: new Set(['system']) },
    ],
    done: [
      { to: 'archive', allowed: new Set(['human', 'non_human', 'system']) },
      { to: 'failed', allowed: new Set(['system']) },
    ],
    archive: [
      { to: 'backlog', allowed: new Set(['human']) },
      { to: 'failed', allowed: new Set(['system']) },
    ],
    failed: [
      { to: 'backlog', allowed: new Set(['human', 'system']) },
      { to: 'failed', allowed: new Set(['system']) },
    ],
  };

  const validTransitions = (transitionRules[currentStatus] || []).map((rule) => rule.to);
  const matched = (transitionRules[currentStatus] || []).find((rule) => rule.to === newStatus);
  if (!matched) {
    return { valid: false, reason: 'invalid_transition', validTransitions };
  }
  if (!matched.allowed.has(sourceKind)) {
    return { valid: false, reason: 'source_not_allowed', validTransitions };
  }
  return { valid: true };
}

function parseDependsOn(value) {
  if (value == null) return [];
  if (typeof value !== 'string') return [];
  return [...new Set(value.split(',')
    .map((s) => Number.parseInt(s.trim(), 10))
    .filter((n) => Number.isInteger(n) && n > 0))];
}

function normalizeDependsOn(value) {
  const ids = parseDependsOn(value);
  return ids.length ? ids.join(',') : null;
}

function nowEpochSeconds() {
  return Math.floor(Date.now() / 1000);
}

function sanitizeCreateData(data = {}) {
  const out = {};
  if (typeof data.title === 'string') out.title = data.title.trim();
  if (typeof data.description === 'string') out.description = data.description;
  if (typeof data.status === 'string' && VALID_STATUSES.has(data.status)) out.status = data.status;
  if (typeof data.priority === 'string' && VALID_PRIORITIES.has(data.priority)) out.priority = data.priority;
  if (typeof data.assigned_agent === 'string') out.assigned_agent = data.assigned_agent.trim() || null;
  if (data.assigned_agent === null) out.assigned_agent = null;
  if (Object.hasOwn(data, 'depends_on')) out.depends_on = normalizeDependsOn(data.depends_on);
  if (Object.hasOwn(data, 'handoff_payload')) {
    out.handoff_payload = data.handoff_payload == null ? null : String(data.handoff_payload);
  }
  if (typeof data.created_by === 'string' && data.created_by.trim()) out.created_by = data.created_by.trim();
  if (typeof data.source === 'string' && VALID_SOURCES.has(data.source)) out.source = data.source;
  if (Object.hasOwn(data, 'token_estimate')) {
    out.token_estimate = data.token_estimate == null ? null : Number.parseInt(data.token_estimate, 10);
  }
  if (Object.hasOwn(data, 'token_actual')) {
    out.token_actual = data.token_actual == null ? null : Number.parseInt(data.token_actual, 10);
  }
  if (Object.hasOwn(data, 'max_retries')) {
    out.max_retries = data.max_retries == null ? null : Number.parseInt(data.max_retries, 10);
  }
  if (Object.hasOwn(data, 'goal_id')) {
    const goalId = data.goal_id == null ? null : Number.parseInt(data.goal_id, 10);
    out.goal_id = Number.isInteger(goalId) && goalId > 0 ? goalId : null;
  }
  if (Object.hasOwn(data, 'due_at')) {
    out.due_at = data.due_at == null ? null : String(data.due_at);
  }
  if (Object.hasOwn(data, 'delivery_channel')) {
    out.delivery_channel = data.delivery_channel == null ? null : String(data.delivery_channel).trim() || null;
  }
  if (Object.hasOwn(data, 'execution_mode')) {
    out.execution_mode = data.execution_mode == null ? null : String(data.execution_mode).trim() || null;
  }
  if (Object.hasOwn(data, 'requested_via')) {
    out.requested_via = data.requested_via == null ? null : String(data.requested_via).trim() || null;
  }
  if (Object.hasOwn(data, 'accepted_at')) {
    out.accepted_at = data.accepted_at == null ? null : String(data.accepted_at);
  }
  if (Object.hasOwn(data, 'user_notified_at')) {
    out.user_notified_at = data.user_notified_at == null ? null : String(data.user_notified_at);
  }
  if (Object.hasOwn(data, 'task_type')) {
    out.task_type = data.task_type == null ? null : String(data.task_type).trim() || null;
  }
  if (Object.hasOwn(data, 'original_intent')) {
    out.original_intent = data.original_intent == null ? null : String(data.original_intent);
  }
  if (Object.hasOwn(data, 'active_intent')) {
    out.active_intent = data.active_intent == null ? null : String(data.active_intent);
  }
  if (Object.hasOwn(data, 'acceptance_criteria')) {
    out.acceptance_criteria = data.acceptance_criteria == null ? null : String(data.acceptance_criteria);
  }
  if (Object.hasOwn(data, 'scoped_contribution')) {
    out.scoped_contribution = data.scoped_contribution == null ? null : String(data.scoped_contribution);
  }
  if (Object.hasOwn(data, 'non_goals')) {
    out.non_goals = data.non_goals == null ? null : String(data.non_goals);
  }
  return out;
}

function sanitizeUpdateData(data = {}) {
  const allowed = [
    'title',
    'description',
    'status',
    'priority',
    'assigned_agent',
    'depends_on',
    'handoff_payload',
    'token_estimate',
    'token_actual',
    'max_retries',
    'transitioned_by',
    'goal_id',
    'due_at',
    'delivery_channel',
    'execution_mode',
    'requested_via',
    'accepted_at',
    'user_notified_at',
  ];
  const out = {};
  for (const key of allowed) {
    if (!Object.hasOwn(data, key)) continue;
    if (key === 'title') {
      if (typeof data.title === 'string') out.title = data.title.trim();
    } else if (key === 'description') {
      out.description = data.description == null ? '' : String(data.description);
    } else if (key === 'status') {
      if (typeof data.status === 'string' && VALID_STATUSES.has(data.status)) out.status = data.status;
    } else if (key === 'priority') {
      if (typeof data.priority === 'string' && VALID_PRIORITIES.has(data.priority)) out.priority = data.priority;
    } else if (key === 'assigned_agent') {
      out.assigned_agent = data.assigned_agent == null ? null : String(data.assigned_agent).trim() || null;
    } else if (key === 'depends_on') {
      out.depends_on = normalizeDependsOn(data.depends_on);
    } else if (key === 'handoff_payload') {
      out.handoff_payload = data.handoff_payload == null ? null : String(data.handoff_payload);
    } else if (key === 'token_estimate') {
      out.token_estimate = data.token_estimate == null ? null : Number.parseInt(data.token_estimate, 10);
    } else if (key === 'token_actual') {
      out.token_actual = data.token_actual == null ? null : Number.parseInt(data.token_actual, 10);
    } else if (key === 'max_retries') {
      out.max_retries = data.max_retries == null ? null : Number.parseInt(data.max_retries, 10);
    } else if (key === 'transitioned_by') {
      out.transitioned_by = data.transitioned_by == null ? null : String(data.transitioned_by).trim() || null;
    } else if (key === 'goal_id') {
      const goalId = data.goal_id == null ? null : Number.parseInt(data.goal_id, 10);
      out.goal_id = Number.isInteger(goalId) && goalId > 0 ? goalId : null;
    } else if (key === 'due_at') {
      out.due_at = data.due_at == null ? null : String(data.due_at);
    } else if (key === 'delivery_channel') {
      out.delivery_channel = data.delivery_channel == null ? null : String(data.delivery_channel).trim() || null;
    } else if (key === 'execution_mode') {
      out.execution_mode = data.execution_mode == null ? null : String(data.execution_mode).trim() || null;
    } else if (key === 'requested_via') {
      out.requested_via = data.requested_via == null ? null : String(data.requested_via).trim() || null;
    } else if (key === 'accepted_at') {
      out.accepted_at = data.accepted_at == null ? null : String(data.accepted_at);
    } else if (key === 'user_notified_at') {
      out.user_notified_at = data.user_notified_at == null ? null : String(data.user_notified_at);
    }
  }
  return out;
}

function sanitizeGoalData(data = {}) {
  const out = {};
  if (typeof data.title === 'string') out.title = data.title.trim();
  if (Object.hasOwn(data, 'description')) out.description = data.description == null ? '' : String(data.description);
  if (typeof data.status === 'string' && VALID_GOAL_STATUSES.has(data.status)) out.status = data.status;
  if (Object.hasOwn(data, 'assigned_agents')) {
    out.assigned_agents = data.assigned_agents == null ? '[]' : String(data.assigned_agents);
  }
  if (Object.hasOwn(data, 'tasks_per_period')) {
    out.tasks_per_period = data.tasks_per_period == null ? null : Number.parseInt(data.tasks_per_period, 10);
  }
  if (typeof data.period === 'string' && VALID_GOAL_PERIODS.has(data.period)) out.period = data.period;
  if (Object.hasOwn(data, 'max_open_tasks')) {
    out.max_open_tasks = data.max_open_tasks == null ? null : Number.parseInt(data.max_open_tasks, 10);
  }
  return out;
}

function computeBlockedByIds(task, statusById) {
  const ids = parseDependsOn(task.depends_on);
  if (!ids.length) return [];
  return ids.filter((id) => {
    const depStatus = statusById.get(id);
    if (!depStatus) return true;
    return depStatus !== 'done' && depStatus !== 'archive';
  });
}

function getStatusByIdMap() {
  const conn = getDb();
  const rows = conn.prepare('SELECT id, status FROM tasks').all();
  return new Map(rows.map((row) => [row.id, row.status]));
}

function attachBlockedBy(tasks, statusById = getStatusByIdMap()) {
  return tasks.map((task) => ({
    ...task,
    blocked_by: computeBlockedByIds(task, statusById),
  }));
}

export function getDb() {
  if (db) return db;
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL CHECK(length(title) <= 100),
      description TEXT DEFAULT '' CHECK(length(description) <= 2000),
      status TEXT NOT NULL DEFAULT 'backlog' CHECK(status IN ('proposed','backlog','in_progress','review','done','archive','failed')),
      priority TEXT NOT NULL DEFAULT 'medium' CHECK(priority IN ('critical','high','medium','low')),
      assigned_agent TEXT DEFAULT NULL,
      depends_on TEXT DEFAULT NULL,
      handoff_payload TEXT DEFAULT NULL CHECK(handoff_payload IS NULL OR length(handoff_payload) <= 2000),
      created_by TEXT NOT NULL DEFAULT 'adam',
      source TEXT NOT NULL DEFAULT 'dashboard' CHECK(source IN ('dashboard','telegram','cron','agent')),
      token_estimate INTEGER DEFAULT NULL,
      token_actual INTEGER DEFAULT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      last_activity_at INTEGER DEFAULT (CAST(strftime('%s', 'now') AS INTEGER))
    );

    CREATE TABLE IF NOT EXISTS task_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
      actor TEXT NOT NULL,
      action TEXT NOT NULL,
      detail TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
    CREATE INDEX IF NOT EXISTS idx_tasks_priority ON tasks(priority);
    CREATE INDEX IF NOT EXISTS idx_tasks_assigned ON tasks(assigned_agent);
    CREATE INDEX IF NOT EXISTS idx_history_task ON task_history(task_id);

    CREATE TABLE IF NOT EXISTS goals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL CHECK(length(title) <= 200),
      description TEXT NOT NULL DEFAULT '' CHECK(length(description) <= 2000),
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','paused','completed','archived')),
      assigned_agents TEXT DEFAULT '[]',
      tasks_per_period INTEGER DEFAULT 1,
      period TEXT DEFAULT 'day' CHECK(period IN ('day','week')),
      max_open_tasks INTEGER DEFAULT 3,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_goals_status ON goals(status);
    CREATE INDEX IF NOT EXISTS idx_goals_created_at ON goals(created_at);

    CREATE TABLE IF NOT EXISTS task_artifacts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      task_id INTEGER NOT NULL,
      checkpoint_id TEXT,
      artifact_type TEXT NOT NULL,
      content TEXT NOT NULL,
      content_hash TEXT NOT NULL,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      transition TEXT NOT NULL,
      FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_artifacts_task ON task_artifacts(task_id);
    CREATE INDEX IF NOT EXISTS idx_artifacts_checkpoint ON task_artifacts(checkpoint_id);

    CREATE TABLE IF NOT EXISTS task_checkpoints (
      id TEXT PRIMARY KEY,
      task_id INTEGER NOT NULL,
      transition TEXT NOT NULL,
      artifact_ids TEXT NOT NULL,
      created_by TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      status TEXT DEFAULT 'active',
      superseded_by TEXT,
      superseded_at TEXT,
      FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_checkpoints_task ON task_checkpoints(task_id);
    CREATE INDEX IF NOT EXISTS idx_checkpoints_status ON task_checkpoints(status);

    CREATE TABLE IF NOT EXISTS task_intent_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      task_id INTEGER NOT NULL,
      version INTEGER NOT NULL,
      intent TEXT NOT NULL,
      acceptance_criteria TEXT,
      changed_by TEXT NOT NULL,
      changed_at TEXT NOT NULL DEFAULT (datetime('now')),
      change_reason TEXT NOT NULL,
      previous_version INTEGER,
      FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_intent_history_task ON task_intent_history(task_id);

    CREATE TABLE IF NOT EXISTS task_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      task_id INTEGER NOT NULL,
      action TEXT NOT NULL,
      from_status TEXT,
      to_status TEXT,
      actor TEXT NOT NULL,
      checkpoint_id TEXT,
      details TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_audit_task ON task_audit(task_id);
    CREATE INDEX IF NOT EXISTS idx_audit_created ON task_audit(created_at);
  `);


  const taskColumns = new Set(db.prepare('PRAGMA table_info(tasks)').all().map((row) => row.name));
  if (!taskColumns.has('failure_count')) {
    db.exec('ALTER TABLE tasks ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0');
  }
  if (!taskColumns.has('max_retries')) {
    db.exec('ALTER TABLE tasks ADD COLUMN max_retries INTEGER NOT NULL DEFAULT 2');
  }
  if (!taskColumns.has('last_failure_reason')) {
    db.exec('ALTER TABLE tasks ADD COLUMN last_failure_reason TEXT');
  }
  if (!taskColumns.has('last_activity_at')) {
    db.exec('ALTER TABLE tasks ADD COLUMN last_activity_at INTEGER');
  }
  if (!taskColumns.has('transitioned_by')) {
    db.exec('ALTER TABLE tasks ADD COLUMN transitioned_by TEXT');
  }
  if (!taskColumns.has('goal_id')) {
    db.exec('ALTER TABLE tasks ADD COLUMN goal_id INTEGER');
  }
  if (!taskColumns.has('due_at')) {
    db.exec('ALTER TABLE tasks ADD COLUMN due_at DATETIME');
  }
  if (!taskColumns.has('delivery_channel')) {
    db.exec('ALTER TABLE tasks ADD COLUMN delivery_channel TEXT');
  }
  if (!taskColumns.has('execution_mode')) {
    db.exec('ALTER TABLE tasks ADD COLUMN execution_mode TEXT');
  }
  if (!taskColumns.has('requested_via')) {
    db.exec('ALTER TABLE tasks ADD COLUMN requested_via TEXT');
  }
  if (!taskColumns.has('accepted_at')) {
    db.exec('ALTER TABLE tasks ADD COLUMN accepted_at DATETIME');
  }
  if (!taskColumns.has('user_notified_at')) {
    db.exec('ALTER TABLE tasks ADD COLUMN user_notified_at DATETIME');
  }
  try { db.exec('ALTER TABLE tasks ADD COLUMN task_type TEXT DEFAULT \'operational\''); } catch {}
  try { db.exec('ALTER TABLE tasks ADD COLUMN original_intent TEXT'); } catch {}
  try { db.exec('ALTER TABLE tasks ADD COLUMN active_intent TEXT'); } catch {}
  try { db.exec('ALTER TABLE tasks ADD COLUMN active_intent_version INTEGER DEFAULT 1'); } catch {}
  try { db.exec('ALTER TABLE tasks ADD COLUMN acceptance_criteria TEXT'); } catch {}
  try { db.exec('ALTER TABLE tasks ADD COLUMN scoped_contribution TEXT'); } catch {}
  try { db.exec('ALTER TABLE tasks ADD COLUMN non_goals TEXT'); } catch {}
  try { db.exec('ALTER TABLE tasks ADD COLUMN claimed_by TEXT'); } catch {}
  try { db.exec('ALTER TABLE tasks ADD COLUMN claimed_at TEXT'); } catch {}
  try { db.exec('ALTER TABLE tasks ADD COLUMN claim_expires_at TEXT'); } catch {}
  try { db.exec('ALTER TABLE tasks ADD COLUMN parent_checkpoint_id TEXT'); } catch {}
  try { db.exec('ALTER TABLE tasks ADD COLUMN parent_intent_version INTEGER'); } catch {}
  try { db.exec('ALTER TABLE tasks ADD COLUMN stale_dependency INTEGER DEFAULT 0'); } catch {}

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_tasks_last_activity ON tasks(last_activity_at);
    CREATE INDEX IF NOT EXISTS idx_tasks_goal_id ON tasks(goal_id);
    CREATE INDEX IF NOT EXISTS idx_tasks_due_at ON tasks(due_at);

    UPDATE tasks
    SET last_activity_at = COALESCE(
      (
        SELECT CAST(strftime('%s', MAX(created_at)) AS INTEGER)
        FROM task_history
        WHERE task_id = tasks.id
      ),
      CAST(strftime('%s', created_at) AS INTEGER)
    )
    WHERE last_activity_at IS NULL OR last_activity_at <= 0;
  `);

  return db;
}

function listTasksRaw(filters = {}) {
  const conn = getDb();
  let sql = 'SELECT * FROM tasks WHERE 1=1';
  const params = [];

  if (filters.status && VALID_STATUSES.has(filters.status)) {
    sql += ' AND status = ?';
    params.push(filters.status);
  }
  if (filters.assigned_agent) {
    sql += ' AND assigned_agent = ?';
    params.push(filters.assigned_agent);
  }
  if (filters.priority && VALID_PRIORITIES.has(filters.priority)) {
    sql += ' AND priority = ?';
    params.push(filters.priority);
  }

  sql += ` ORDER BY
    CASE status
      WHEN 'proposed' THEN 1
      WHEN 'backlog' THEN 2
      WHEN 'in_progress' THEN 3
      WHEN 'review' THEN 4
      WHEN 'done' THEN 5
      WHEN 'archive' THEN 6
      WHEN 'failed' THEN 7
      ELSE 8
    END,
    CASE priority
      WHEN 'critical' THEN 1
      WHEN 'high' THEN 2
      WHEN 'medium' THEN 3
      WHEN 'low' THEN 4
      ELSE 5
    END,
    datetime(created_at) ASC,
    id ASC`;

  return conn.prepare(sql).all(...params);
}

export function getAllTasks(filters = {}) {
  const rows = listTasksRaw(filters);
  return attachBlockedBy(rows);
}

export function getTaskById(id) {
  const conn = getDb();
  const task = conn.prepare('SELECT * FROM tasks WHERE id = ?').get(id);
  if (!task) return null;
  const statusById = getStatusByIdMap();
  return { ...task, blocked_by: computeBlockedByIds(task, statusById) };
}

export function getInProgressTask(agent) {
  const conn = getDb();
  let sql = "SELECT * FROM tasks WHERE status = 'in_progress'";
  const params = [];
  if (agent) {
    sql += ' AND assigned_agent = ?';
    params.push(agent);
  }
  sql += ' ORDER BY datetime(updated_at) DESC, id DESC LIMIT 1';
  const task = conn.prepare(sql).get(...params);
  if (!task) return null;
  const statusById = getStatusByIdMap();
  return { ...task, blocked_by: computeBlockedByIds(task, statusById) };
}

export function getNextTask(agent) {
  const tasks = getAllTasks({ status: 'backlog' })
    .filter((task) => !task.blocked_by.length)
    .filter((task) => !agent || task.assigned_agent == null || task.assigned_agent === agent);
  if (!tasks.length) return null;
  tasks.sort((a, b) => {
    const priorityOrder = { critical: 1, high: 2, medium: 3, low: 4 };
    const pa = priorityOrder[a.priority] || 5;
    const pb = priorityOrder[b.priority] || 5;
    if (pa !== pb) return pa - pb;
    const ca = Date.parse(a.created_at);
    const cb = Date.parse(b.created_at);
    if (ca !== cb) return ca - cb;
    return a.id - b.id;
  });
  return tasks[0];
}

export function addHistory(taskId, actor, action, detail = '') {
  const conn = getDb();
  const safeActor = actor && String(actor).trim() ? String(actor).trim() : 'system';
  const safeAction = action && String(action).trim() ? String(action).trim() : 'updated';
  const safeDetail = detail == null ? '' : String(detail);

  const tx = conn.transaction(() => {
    conn
      .prepare('INSERT INTO task_history (task_id, actor, action, detail) VALUES (?, ?, ?, ?)')
      .run(taskId, safeActor, safeAction, safeDetail);

    conn
      .prepare('UPDATE tasks SET last_activity_at = ? WHERE id = ?')
      .run(nowEpochSeconds(), taskId);

    const count = conn.prepare('SELECT COUNT(*) AS c FROM task_history WHERE task_id = ?').get(taskId).c;
    if (count > 50) {
      const overflow = count - 50;
      conn
        .prepare(`DELETE FROM task_history
                  WHERE id IN (
                    SELECT id FROM task_history WHERE task_id = ?
                    ORDER BY datetime(created_at) ASC, id ASC
                    LIMIT ?
                  )`)
        .run(taskId, overflow);
    }

    return conn.prepare('SELECT * FROM task_history WHERE task_id = ? ORDER BY id DESC LIMIT 1').get(taskId);
  });

  return tx();
}

export function getHistory(taskId) {
  const conn = getDb();
  return conn
    .prepare('SELECT * FROM task_history WHERE task_id = ? ORDER BY datetime(created_at) DESC, id DESC')
    .all(taskId);
}

export function createTask(data) {
  const conn = getDb();
  const payload = sanitizeCreateData(data);
  if (!payload.title) {
    throw new Error('title is required');
  }
  if (payload.original_intent && !payload.active_intent) {
    payload.active_intent = payload.original_intent;
  }

  const tx = conn.transaction(() => {
    const stmt = conn.prepare(`
      INSERT INTO tasks (
        title, description, status, priority, assigned_agent, depends_on,
        handoff_payload, created_by, source, token_estimate, token_actual, max_retries, last_activity_at, goal_id,
        due_at, delivery_channel, execution_mode, requested_via, accepted_at, user_notified_at,
        task_type, original_intent, active_intent, acceptance_criteria, scoped_contribution, non_goals
      ) VALUES (
        @title,
        @description,
        @status,
        @priority,
        @assigned_agent,
        @depends_on,
        @handoff_payload,
        @created_by,
        @source,
        @token_estimate,
        @token_actual,
        @max_retries,
        @last_activity_at,
        @goal_id,
        @due_at,
        @delivery_channel,
        @execution_mode,
        @requested_via,
        @accepted_at,
        @user_notified_at,
        @task_type,
        @original_intent,
        @active_intent,
        @acceptance_criteria,
        @scoped_contribution,
        @non_goals
      )
    `);

    const result = stmt.run({
      title: payload.title,
      description: payload.description ?? '',
      status: payload.status ?? 'backlog',
      priority: payload.priority ?? 'medium',
      assigned_agent: payload.assigned_agent ?? null,
      depends_on: payload.depends_on ?? null,
      handoff_payload: payload.handoff_payload ?? null,
      created_by: payload.created_by ?? 'adam',
      source: payload.source ?? 'dashboard',
      token_estimate: Number.isFinite(payload.token_estimate) ? payload.token_estimate : null,
      token_actual: Number.isFinite(payload.token_actual) ? payload.token_actual : null,
      max_retries: Number.isInteger(payload.max_retries) && payload.max_retries >= 0 ? payload.max_retries : 2,
      last_activity_at: nowEpochSeconds(),
      goal_id: Number.isInteger(payload.goal_id) && payload.goal_id > 0 ? payload.goal_id : null,
      due_at: payload.due_at ?? null,
      delivery_channel: payload.delivery_channel ?? null,
      execution_mode: payload.execution_mode ?? null,
      requested_via: payload.requested_via ?? null,
      accepted_at: payload.accepted_at ?? null,
      user_notified_at: payload.user_notified_at ?? null,
      task_type: payload.task_type ?? 'operational',
      original_intent: payload.original_intent ?? null,
      active_intent: payload.active_intent ?? null,
      acceptance_criteria: payload.acceptance_criteria ?? null,
      scoped_contribution: payload.scoped_contribution ?? null,
      non_goals: payload.non_goals ?? null,
    });

    addHistory(result.lastInsertRowid, payload.created_by ?? 'adam', 'created', '');
    return result.lastInsertRowid;
  });

  const id = tx();
  return getTaskById(id);
}

export function getOverdueTasks() {
  const conn = getDb();
  return conn.prepare(`
    SELECT
      id,
      title,
      assigned_agent,
      due_at,
      CAST((strftime('%s', 'now') - strftime('%s', due_at)) / 60 AS INTEGER) AS minutes_overdue,
      delivery_channel,
      user_notified_at
    FROM tasks
    WHERE due_at IS NOT NULL
      AND datetime(due_at) < datetime('now')
      AND status NOT IN ('done', 'archive', 'failed')
    ORDER BY datetime(due_at) ASC, id ASC
  `).all();
}

export function updateTask(id, data) {
  const conn = getDb();
  const current = conn.prepare('SELECT * FROM tasks WHERE id = ?').get(id);
  if (!current) return null;

  const payload = sanitizeUpdateData(data);
  const fields = Object.keys(payload);

  if (!fields.length) return getTaskById(id);

  const tx = conn.transaction(() => {
    const updatePayload = { id, ...payload };
    let setFields = [...fields];

    if (Object.hasOwn(payload, 'status') && payload.status !== current.status) {
      setFields.push('last_activity_at');
      updatePayload.last_activity_at = nowEpochSeconds();
    }

    const setClause = setFields.map((field) => `${field} = @${field}`).join(', ');
    const stmt = conn.prepare(`UPDATE tasks SET ${setClause}, updated_at = datetime('now') WHERE id = @id`);
    stmt.run(updatePayload);

    const detail = fields.join(', ');
    addHistory(id, 'system', 'updated', detail);
    return getTaskById(id);
  });

  return tx();
}

export function getTaskStats() {
  const conn = getDb();
  const all = conn.prepare('SELECT * FROM tasks').all();
  const total = all.length;

  const byStatus = {
    proposed: 0,
    backlog: 0,
    in_progress: 0,
    review: 0,
    done: 0,
    archive: 0,
    failed: 0,
  };
  const byPriority = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  const tokensByPriority = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };

  let totalTokensActual = 0;
  let completionCount = 0;
  let durationHoursTotal = 0;

  for (const task of all) {
    if (Object.hasOwn(byStatus, task.status)) byStatus[task.status] += 1;
    if (Object.hasOwn(byPriority, task.priority)) byPriority[task.priority] += 1;

    if (Number.isFinite(task.token_actual)) {
      totalTokensActual += task.token_actual;
      if (Object.hasOwn(tokensByPriority, task.priority)) {
        tokensByPriority[task.priority] += task.token_actual;
      }
    }

    if (task.status === 'done' || task.status === 'archive') {
      completionCount += 1;
      const created = Date.parse(task.created_at);
      const updated = Date.parse(task.updated_at);
      if (Number.isFinite(created) && Number.isFinite(updated) && updated >= created) {
        durationHoursTotal += (updated - created) / (1000 * 60 * 60);
      }
    }
  }

  const now = Date.now();
  const stuckTasks = all
    .filter((task) => task.status === 'in_progress')
    .map((task) => {
      const updated = Date.parse(task.updated_at);
      const ageHours = Number.isFinite(updated) ? (now - updated) / (1000 * 60 * 60) : 0;
      return {
        id: task.id,
        title: task.title,
        status: task.status,
        age_hours: Math.round(ageHours * 10) / 10,
      };
    })
    .filter((task) => task.age_hours > 24)
    .sort((a, b) => b.age_hours - a.age_hours);

  return {
    total,
    by_status: byStatus,
    by_priority: byPriority,
    avg_duration_hours: completionCount ? Math.round((durationHoursTotal / completionCount) * 10) / 10 : 0,
    total_tokens_actual: totalTokensActual,
    tokens_by_priority: tokensByPriority,
    completion_rate: total ? Math.round((byStatus.done / total) * 100) / 100 : 0,
    stuck_tasks: stuckTasks,
  };
}


function getIsoWeekBoundsUtc(now = new Date()) {
  const date = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const day = date.getUTCDay() || 7;
  date.setUTCDate(date.getUTCDate() + 4 - day);
  const weekStart = new Date(date);
  weekStart.setUTCDate(date.getUTCDate() - 3);
  weekStart.setUTCHours(0, 0, 0, 0);
  const weekEnd = new Date(weekStart);
  weekEnd.setUTCDate(weekStart.getUTCDate() + 7);
  return { start: weekStart.toISOString().slice(0, 19).replace('T', ' '), end: weekEnd.toISOString().slice(0, 19).replace('T', ' ') };
}

function getDayBoundsUtc(now = new Date()) {
  const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const end = new Date(start);
  end.setUTCDate(start.getUTCDate() + 1);
  return { start: start.toISOString().slice(0, 19).replace('T', ' '), end: end.toISOString().slice(0, 19).replace('T', ' ') };
}

export function createGoal(data) {
  const conn = getDb();
  const payload = sanitizeGoalData(data);
  if (!payload.title) throw new Error('title is required');

  const result = conn.prepare(`
    INSERT INTO goals (title, description, status, assigned_agents, tasks_per_period, period, max_open_tasks)
    VALUES (@title, @description, @status, @assigned_agents, @tasks_per_period, @period, @max_open_tasks)
  `).run({
    title: payload.title,
    description: payload.description ?? '',
    status: payload.status ?? 'active',
    assigned_agents: payload.assigned_agents ?? '[]',
    tasks_per_period: Number.isInteger(payload.tasks_per_period) && payload.tasks_per_period >= 0 ? payload.tasks_per_period : 1,
    period: payload.period ?? 'day',
    max_open_tasks: Number.isInteger(payload.max_open_tasks) && payload.max_open_tasks >= 0 ? payload.max_open_tasks : 3,
  });

  return getGoalById(result.lastInsertRowid);
}

export function getGoalById(id) {
  const conn = getDb();
  return conn.prepare('SELECT * FROM goals WHERE id = ?').get(id) || null;
}

export function getAllGoals(statusFilter) {
  const conn = getDb();
  if (statusFilter && VALID_GOAL_STATUSES.has(statusFilter)) {
    return conn.prepare('SELECT * FROM goals WHERE status = ? ORDER BY datetime(created_at) DESC, id DESC').all(statusFilter);
  }
  return conn.prepare('SELECT * FROM goals ORDER BY datetime(created_at) DESC, id DESC').all();
}

export function updateGoal(id, data) {
  const conn = getDb();
  const current = getGoalById(id);
  if (!current) return null;

  const payload = sanitizeGoalData(data);
  const allowed = ['title', 'description', 'status', 'assigned_agents', 'tasks_per_period', 'period', 'max_open_tasks'];
  const fields = allowed.filter((field) => Object.hasOwn(payload, field));
  if (!fields.length) return current;

  const stmt = conn.prepare(`UPDATE goals SET ${fields.map((f) => `${f} = @${f}`).join(', ')}, updated_at = datetime('now') WHERE id = @id`);
  const updateData = { id, ...payload };
  stmt.run(updateData);
  return getGoalById(id);
}

export function archiveGoal(id) {
  return updateGoal(id, { status: 'archived' });
}

export function getGoalTasks(goalId) {
  const conn = getDb();
  return conn.prepare('SELECT * FROM tasks WHERE goal_id = ? ORDER BY datetime(created_at) DESC, id DESC').all(goalId);
}

export function getGoalTaskStats(goalId) {
  const conn = getDb();
  const rows = conn.prepare('SELECT status, COUNT(*) AS count FROM tasks WHERE goal_id = ? GROUP BY status').all(goalId);
  const byStatus = {
    proposed: 0,
    backlog: 0,
    in_progress: 0,
    review: 0,
    done: 0,
    archive: 0,
    failed: 0,
  };
  for (const row of rows) {
    if (Object.hasOwn(byStatus, row.status)) byStatus[row.status] = row.count;
  }
  return byStatus;
}

export function goalNeedsTasks(goalId) {
  const conn = getDb();
  const goal = getGoalById(goalId);
  if (!goal) return null;

  const currentOpen = conn.prepare(`
    SELECT COUNT(*) AS c FROM tasks
    WHERE goal_id = ? AND status NOT IN ('done', 'archive', 'failed')
  `).get(goalId).c;

  const bounds = goal.period === 'week' ? getIsoWeekBoundsUtc() : getDayBoundsUtc();
  const currentPeriodCreated = conn.prepare(`
    SELECT COUNT(*) AS c FROM tasks
    WHERE goal_id = ?
      AND datetime(created_at) >= datetime(?)
      AND datetime(created_at) < datetime(?)
  `).get(goalId, bounds.start, bounds.end).c;

  const maxOpenTasks = Number.isInteger(goal.max_open_tasks) ? goal.max_open_tasks : 3;
  const tasksPerPeriod = Number.isInteger(goal.tasks_per_period) ? goal.tasks_per_period : 1;

  if (currentOpen >= maxOpenTasks) {
    return {
      needs_tasks: false,
      current_open: currentOpen,
      max_open_tasks: maxOpenTasks,
      current_period_created: currentPeriodCreated,
      tasks_per_period: tasksPerPeriod,
      reason: `${currentOpen} open tasks, limit is ${maxOpenTasks}`,
    };
  }

  if (currentPeriodCreated >= tasksPerPeriod) {
    return {
      needs_tasks: false,
      current_open: currentOpen,
      max_open_tasks: maxOpenTasks,
      current_period_created: currentPeriodCreated,
      tasks_per_period: tasksPerPeriod,
      reason: `${currentPeriodCreated} tasks created this ${goal.period}, limit is ${tasksPerPeriod}`,
    };
  }

  return {
    needs_tasks: true,
    current_open: currentOpen,
    max_open_tasks: maxOpenTasks,
    current_period_created: currentPeriodCreated,
    tasks_per_period: tasksPerPeriod,
    reason: `${currentPeriodCreated} tasks created this ${goal.period}, limit is ${tasksPerPeriod}`,
  };
}

export function getStaleTasks(softThreshold = 48, hardThreshold = 120) {
  const conn = getDb();
  const safeSoft = Number.isFinite(softThreshold) && softThreshold >= 1 ? Math.floor(softThreshold) : 48;
  const safeHardInput = Number.isFinite(hardThreshold) && hardThreshold >= 1 ? Math.floor(hardThreshold) : 120;
  const safeHard = Math.max(safeHardInput, safeSoft);
  const nowEpoch = nowEpochSeconds();
  const staleCutoff = nowEpoch - (safeSoft * 3600);

  const rows = conn.prepare(`
    SELECT id, title, assigned_agent, status, last_activity_at, failure_count, max_retries, depends_on
    FROM tasks
    WHERE status = 'in_progress'
      AND assigned_agent IS NOT NULL
      AND trim(assigned_agent) != ''
      AND assigned_agent != 'orchestrator'
      AND last_activity_at IS NOT NULL
      AND last_activity_at <= ?
    ORDER BY last_activity_at ASC, id ASC
  `).all(staleCutoff);

  const stale = rows.map((row) => {
    const hoursSinceUpdate = Math.floor((nowEpoch - row.last_activity_at) / 3600);
    const severity = hoursSinceUpdate >= safeHard ? 'hard' : 'soft';
    return {
      id: row.id,
      title: row.title,
      assignedTo: row.assigned_agent,
      status: row.status,
      hoursSinceUpdate,
      severity,
      lastUpdated: new Date(row.last_activity_at * 1000).toISOString(),
      failureCount: row.failure_count,
      maxRetries: row.max_retries,
      dependsOn: row.depends_on,
    };
  });

  const counts = stale.reduce((acc, item) => {
    acc[item.severity] += 1;
    acc.total += 1;
    return acc;
  }, { soft: 0, hard: 0, total: 0 });

  return { stale, counts };
}

export function getProposalCount(date) {
  const conn = getDb();
  return conn
    .prepare(`SELECT COUNT(*) AS c FROM tasks
              WHERE source = 'agent' AND status = 'proposed' AND date(datetime(created_at, '-6 hours')) = date(?)`)
    .get(date).c;
}

export function getCurrentTaskSummary(agent) {
  const task = getNextTask(agent) || getInProgressTask(agent);
  if (!task) return 'No active task.';
  return `Current task: #${task.id} - ${task.title} (${task.status}, ${task.priority})`;
}

export function computeBlockedByForTask(task) {
  const statusById = getStatusByIdMap();
  return computeBlockedByIds(task, statusById);
}

export function getTaskFailures(id) {
  const conn = getDb();
  return conn
    .prepare('SELECT failure_count, max_retries, last_failure_reason FROM tasks WHERE id = ?')
    .get(id) || null;
}

export function recordFailure(id, reason) {
  const conn = getDb();
  const task = conn.prepare('SELECT id, status, failure_count, max_retries FROM tasks WHERE id = ?').get(id);
  if (!task) return null;

  const safeReason = reason == null ? '' : String(reason).trim();
  const tx = conn.transaction(() => {
    const nextFailureCount = task.failure_count + 1;
    const nextStatus = nextFailureCount <= task.max_retries ? 'backlog' : 'failed';
    const transitionCheck = validateTransition(task.status, nextStatus, 'system');
    if (!transitionCheck.valid) {
      throw new Error(`Invalid failure transition: ${task.status} -> ${nextStatus}`);
    }

    conn
      .prepare(`UPDATE tasks
                SET failure_count = failure_count + 1,
                    last_failure_reason = @reason,
                    status = CASE
                      WHEN (failure_count + 1) <= max_retries THEN 'backlog'
                      ELSE 'failed'
                    END,
                    transitioned_by = 'system',
                    last_activity_at = @now_epoch,
                    updated_at = datetime('now')
                WHERE id = @id`)
      .run({ id, reason: safeReason || null, now_epoch: nowEpochSeconds() });

    const updated = conn
      .prepare('SELECT failure_count, max_retries, last_failure_reason, status FROM tasks WHERE id = ?')
      .get(id);

    addHistory(
      id,
      'system',
      'failure_recorded',
      `${safeReason || 'Task failed'} (attempt ${updated.failure_count}/${updated.max_retries})`,
    );

    return {
      retrying: updated.failure_count <= updated.max_retries,
      failure_count: updated.failure_count,
      max_retries: updated.max_retries,
      reason: updated.last_failure_reason || '',
    };
  });

  return tx();
}

export function resetTaskRetries(id) {
  const conn = getDb();
  const task = conn.prepare('SELECT id, max_retries FROM tasks WHERE id = ?').get(id);
  if (!task) return null;

  const tx = conn.transaction(() => {
    conn
      .prepare(`UPDATE tasks
                SET failure_count = 0,
                    last_failure_reason = NULL,
                    status = 'backlog',
                    last_activity_at = ?,
                    updated_at = datetime('now')
                WHERE id = ?`)
      .run(nowEpochSeconds(), id);

    addHistory(id, 'system', 'retries_reset', `Retries reset (max ${task.max_retries}) and moved to backlog`);
    return getTaskById(id);
  });

  return tx();
}

export function createArtifact(data) {
  const conn = getDb();
  const {
    task_id, artifact_type, content, created_by, transition, checkpoint_id,
  } = data;
  if (!task_id || !artifact_type || !content || !created_by || !transition) {
    throw new Error('Missing required artifact fields');
  }
  const hash = createHash('sha256').update(content).digest('hex');
  const stmt = conn.prepare(`
    INSERT INTO task_artifacts (task_id, artifact_type, content, content_hash, created_by, transition, checkpoint_id)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  const result = stmt.run(task_id, artifact_type, content, hash, created_by, transition, checkpoint_id || null);
  return conn.prepare('SELECT * FROM task_artifacts WHERE id = ?').get(result.lastInsertRowid);
}

export function getArtifacts(taskId, transition) {
  const conn = getDb();
  if (transition) {
    return conn.prepare('SELECT * FROM task_artifacts WHERE task_id = ? AND transition = ? ORDER BY created_at ASC').all(taskId, transition);
  }
  return conn.prepare('SELECT * FROM task_artifacts WHERE task_id = ? ORDER BY created_at ASC').all(taskId);
}

export function getArtifactsByCheckpoint(checkpointId) {
  const conn = getDb();
  return conn.prepare('SELECT * FROM task_artifacts WHERE checkpoint_id = ? ORDER BY created_at ASC').all(checkpointId);
}

export function addAuditEntry(data) {
  const conn = getDb();
  const {
    task_id, action, from_status, to_status, actor, checkpoint_id, details,
  } = data;
  const stmt = conn.prepare(`
    INSERT INTO task_audit (task_id, action, from_status, to_status, actor, checkpoint_id, details)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    task_id,
    action,
    from_status || null,
    to_status || null,
    actor,
    checkpoint_id || null,
    details ? JSON.stringify(details) : null,
  );
}

export function getAuditTrail(taskId) {
  const conn = getDb();
  return conn.prepare('SELECT * FROM task_audit WHERE task_id = ? ORDER BY created_at ASC').all(taskId);
}

export function checkArtifactGate(taskId, transition, taskType) {
  const config = getTaskTypeConfig(taskType);
  if (!config) return {
    passed: true, missing: [], required: [],
  };

  let requiredTypes = [];
  if (transition === 'in_progress->review') {
    requiredTypes = config.review_artifacts || [];
  } else if (transition === 'review->done') {
    requiredTypes = config.done_artifacts || [];
  }

  if (requiredTypes.length === 0) return {
    passed: true, missing: [], required: [],
  };

  const existing = getArtifacts(taskId, transition);
  const existingTypes = new Set(existing.map((a) => a.artifact_type));
  const missing = requiredTypes.filter((t) => !existingTypes.has(t));

  return {
    passed: missing.length === 0,
    missing,
    required: requiredTypes,
    submitted: [...existingTypes],
  };
}

export function createCheckpoint(data) {
  const conn = getDb();
  const {
    task_id, transition, artifact_ids, created_by,
  } = data;
  if (!task_id || !transition || !artifact_ids || !created_by) {
    throw new Error('Missing required checkpoint fields');
  }
  const id = `chk_${task_id}_${transition.replace('->', '_')}_${Date.now()}`;
  conn.prepare(`
    INSERT INTO task_checkpoints (id, task_id, transition, artifact_ids, created_by, status)
    VALUES (?, ?, ?, ?, ?, 'active')
  `).run(id, task_id, transition, JSON.stringify(artifact_ids), created_by);

  const updateArtifacts = conn.prepare('UPDATE task_artifacts SET checkpoint_id = ? WHERE id = ?');
  for (const artifactId of artifact_ids) {
    updateArtifacts.run(id, artifactId);
  }

  return conn.prepare('SELECT * FROM task_checkpoints WHERE id = ?').get(id);
}

export function getCheckpoints(taskId) {
  const conn = getDb();
  return conn.prepare('SELECT * FROM task_checkpoints WHERE task_id = ? ORDER BY created_at ASC').all(taskId);
}

export function supersedeCheckpoint(checkpointId, supersededById) {
  const conn = getDb();
  conn.prepare(`
    UPDATE task_checkpoints
    SET status = 'superseded', superseded_by = ?, superseded_at = datetime('now')
    WHERE id = ? AND status = 'active'
  `).run(supersededById || null, checkpointId);
  return conn.prepare('SELECT * FROM task_checkpoints WHERE id = ?').get(checkpointId);
}

export function flagStaleDependencies(taskId) {
  const conn = getDb();
  const taskIdStr = String(taskId);
  const allTasks = conn.prepare('SELECT id, depends_on, parent_checkpoint_id FROM tasks').all();
  const flagged = [];

  for (const task of allTasks) {
    let isDependent = false;
    if (task.depends_on) {
      const depIds = task.depends_on.split(',').map((s) => s.trim());
      if (depIds.includes(taskIdStr)) isDependent = true;
    }
    if (task.parent_checkpoint_id) {
      const checkpoint = conn.prepare('SELECT task_id FROM task_checkpoints WHERE id = ?').get(task.parent_checkpoint_id);
      if (checkpoint && checkpoint.task_id === taskId) isDependent = true;
    }
    if (isDependent && task.id !== taskId) {
      conn.prepare("UPDATE tasks SET stale_dependency = 1, updated_at = datetime('now') WHERE id = ?").run(task.id);
      flagged.push(task.id);
    }
  }
  return flagged;
}

export function clearStaleDependency(taskId) {
  const conn = getDb();
  conn.prepare("UPDATE tasks SET stale_dependency = 0, updated_at = datetime('now') WHERE id = ?").run(taskId);
}

export function claimTask(taskId, agentId, timeoutHours = 4) {
  const conn = getDb();
  const task = conn.prepare('SELECT id, claimed_by, claim_expires_at FROM tasks WHERE id = ?').get(taskId);
  if (!task) return { ok: false, error: 'Task not found' };
  if (task.claimed_by && task.claim_expires_at) {
    const expires = new Date(task.claim_expires_at).getTime();
    if (expires > Date.now()) {
      return {
        ok: false, error: 'Task already claimed', claimed_by: task.claimed_by, expires_at: task.claim_expires_at,
      };
    }
  }

  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + timeoutHours * 3600000).toISOString();
  conn.prepare(`
    UPDATE tasks SET claimed_by = ?, claimed_at = ?, claim_expires_at = ?, updated_at = datetime('now')
    WHERE id = ?
  `).run(agentId, now, expiresAt, taskId);

  return {
    ok: true, claimed_by: agentId, claimed_at: now, expires_at: expiresAt,
  };
}

export function refreshClaim(taskId, agentId, timeoutHours = 4) {
  const conn = getDb();
  const task = conn.prepare('SELECT id, claimed_by FROM tasks WHERE id = ?').get(taskId);
  if (!task) return { ok: false, error: 'Task not found' };
  if (task.claimed_by !== agentId) return { ok: false, error: 'Not claimed by this agent' };

  const expiresAt = new Date(Date.now() + timeoutHours * 3600000).toISOString();
  conn.prepare("UPDATE tasks SET claim_expires_at = ?, updated_at = datetime('now') WHERE id = ?").run(expiresAt, taskId);
  return { ok: true, claimed_by: agentId, expires_at: expiresAt };
}

export function releaseClaim(taskId, agentId) {
  const conn = getDb();
  const task = conn.prepare('SELECT id, claimed_by FROM tasks WHERE id = ?').get(taskId);
  if (!task) return { ok: false, error: 'Task not found' };
  if (task.claimed_by && task.claimed_by !== agentId) return { ok: false, error: 'Not claimed by this agent' };

  conn.prepare("UPDATE tasks SET claimed_by = NULL, claimed_at = NULL, claim_expires_at = NULL, updated_at = datetime('now') WHERE id = ?").run(taskId);
  return { ok: true };
}

export function updateIntent(taskId, data) {
  const conn = getDb();
  const {
    intent, acceptance_criteria, changed_by, change_reason,
  } = data;
  if (!intent || !changed_by || !change_reason) {
    throw new Error('Missing required intent fields: intent, changed_by, change_reason');
  }

  const task = conn.prepare('SELECT id, active_intent, active_intent_version FROM tasks WHERE id = ?').get(taskId);
  if (!task) throw new Error('Task not found');

  const newVersion = (task.active_intent_version || 1) + 1;
  const previousVersion = task.active_intent_version || 1;

  const tx = conn.transaction(() => {
    conn.prepare(`
      INSERT INTO task_intent_history (task_id, version, intent, acceptance_criteria, changed_by, change_reason, previous_version)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(taskId, newVersion, intent, acceptance_criteria || null, changed_by, change_reason, previousVersion);

    conn.prepare(`
      UPDATE tasks SET active_intent = ?, active_intent_version = ?, acceptance_criteria = ?, updated_at = datetime('now')
      WHERE id = ?
    `).run(intent, newVersion, acceptance_criteria || null, taskId);

    addHistory(taskId, changed_by, 'intent_updated', `Intent updated to v${newVersion}: ${change_reason}`);

    return {
      task_id: taskId,
      version: newVersion,
      previous_version: previousVersion,
      intent,
      acceptance_criteria: acceptance_criteria || null,
      changed_by,
      change_reason,
    };
  });

  return tx();
}

export function getIntentHistory(taskId) {
  const conn = getDb();
  return conn.prepare('SELECT * FROM task_intent_history WHERE task_id = ? ORDER BY version ASC').all(taskId);
}

export function getTaskTypeConfigs() {
  const configPath = join(homedir(), '.openclaw', 'workspace', 'task-type-configs.json');
  if (!existsSync(configPath)) return null;

  try {
    const stat = statSync(configPath);
    if (taskTypeConfigCache && stat.mtimeMs === taskTypeConfigMtime) {
      return taskTypeConfigCache;
    }
    const raw = readFileSync(configPath, 'utf8');
    taskTypeConfigCache = JSON.parse(raw);
    taskTypeConfigMtime = stat.mtimeMs;
    return taskTypeConfigCache;
  } catch {
    return null;
  }
}

export function getTaskTypeConfig(typeName) {
  const configs = getTaskTypeConfigs();
  if (!configs || !configs.types) return null;
  return configs.types[typeName] || null;
}
