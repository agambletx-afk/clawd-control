import Database from 'better-sqlite3';
import { join } from 'path';

const DB_PATH = join(new URL('.', import.meta.url).pathname, 'tasks.db');

let db;

const VALID_STATUSES = new Set(['proposed', 'backlog', 'in_progress', 'review', 'done', 'archive', 'failed']);
const VALID_PRIORITIES = new Set(['critical', 'high', 'medium', 'low']);
const VALID_SOURCES = new Set(['dashboard', 'telegram', 'cron', 'agent']);

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
    }
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
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
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

  const tx = conn.transaction(() => {
    const stmt = conn.prepare(`
      INSERT INTO tasks (
        title, description, status, priority, assigned_agent, depends_on,
        handoff_payload, created_by, source, token_estimate, token_actual, max_retries
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
        @max_retries
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
    });

    addHistory(result.lastInsertRowid, payload.created_by ?? 'adam', 'created', '');
    return result.lastInsertRowid;
  });

  const id = tx();
  return getTaskById(id);
}

export function updateTask(id, data) {
  const conn = getDb();
  const current = conn.prepare('SELECT * FROM tasks WHERE id = ?').get(id);
  if (!current) return null;

  const payload = sanitizeUpdateData(data);
  const fields = Object.keys(payload);

  if (!fields.length) return getTaskById(id);

  const tx = conn.transaction(() => {
    const setClause = fields.map((field) => `${field} = @${field}`).join(', ');
    const stmt = conn.prepare(`UPDATE tasks SET ${setClause}, updated_at = datetime('now') WHERE id = @id`);
    stmt.run({ id, ...payload });

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
  const task = conn.prepare('SELECT id, failure_count, max_retries FROM tasks WHERE id = ?').get(id);
  if (!task) return null;

  const safeReason = reason == null ? '' : String(reason).trim();
  const tx = conn.transaction(() => {
    conn
      .prepare(`UPDATE tasks
                SET failure_count = failure_count + 1,
                    last_failure_reason = @reason,
                    status = CASE
                      WHEN (failure_count + 1) <= max_retries THEN 'backlog'
                      ELSE 'failed'
                    END,
                    updated_at = datetime('now')
                WHERE id = @id`)
      .run({ id, reason: safeReason || null });

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
                    updated_at = datetime('now')
                WHERE id = ?`)
      .run(id);

    addHistory(id, 'system', 'retries_reset', `Retries reset (max ${task.max_retries}) and moved to backlog`);
    return getTaskById(id);
  });

  return tx();
}
