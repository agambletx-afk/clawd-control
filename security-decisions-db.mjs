import Database from 'better-sqlite3';
import { join } from 'path';

const DB_PATH = join(new URL('.', import.meta.url).pathname, 'security-decisions.db');
const DEFAULT_MAX_RECORD_BYTES = 4096;

let db;

function ensureSchema(conn) {
  conn.exec(`
    CREATE TABLE IF NOT EXISTS hook_decisions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      session_id TEXT,
      task_id TEXT,
      agent TEXT,
      tool_name TEXT NOT NULL,
      action TEXT NOT NULL,
      decision TEXT NOT NULL,
      rule_matched TEXT,
      risk_score INTEGER,
      detail TEXT,
      truncated INTEGER DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_hook_session ON hook_decisions(session_id);
    CREATE INDEX IF NOT EXISTS idx_hook_task ON hook_decisions(task_id);
    CREATE INDEX IF NOT EXISTS idx_hook_decision ON hook_decisions(decision);
    CREATE INDEX IF NOT EXISTS idx_hook_timestamp ON hook_decisions(timestamp);
  `);
}

export function getDecisionsDb() {
  if (db) return db;
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  ensureSchema(db);
  return db;
}

function normalizeDecision(input) {
  const value = String(input || '').trim();
  const allowed = new Set(['allowed', 'blocked', 'confirmed', 'rate_limited']);
  if (!allowed.has(value)) {
    throw new Error(`decision must be one of: ${Array.from(allowed).join(', ')}`);
  }
  return value;
}

function capRecordSize(record, maxBytes = DEFAULT_MAX_RECORD_BYTES) {
  const result = {
    ...record,
    action: String(record.action ?? ''),
    detail: record.detail == null ? null : String(record.detail),
    truncated: 0,
  };

  const sizeFor = (candidate) => Buffer.byteLength(JSON.stringify(candidate), 'utf8');
  if (sizeFor(result) <= maxBytes) {
    return result;
  }

  result.truncated = 1;
  const ellipsis = '…[truncated]';

  const shrinkField = (key) => {
    const current = result[key];
    if (current == null || current.length === 0) return;
    let low = 0;
    let high = current.length;
    let best = '';
    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      const candidate = `${current.slice(0, mid)}${ellipsis}`;
      const next = { ...result, [key]: candidate };
      if (sizeFor(next) <= maxBytes) {
        best = candidate;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    result[key] = best;
  };

  shrinkField('detail');
  if (sizeFor(result) > maxBytes) {
    shrinkField('action');
  }
  if (sizeFor(result) > maxBytes) {
    result.detail = null;
  }
  if (sizeFor(result) > maxBytes) {
    result.action = ellipsis;
  }

  return result;
}

export function insertDecision({
  timestamp,
  session_id = null,
  task_id = null,
  agent = null,
  tool_name,
  action,
  decision,
  rule_matched = null,
  risk_score = null,
  detail = null,
} = {}) {
  if (!timestamp || !tool_name || action == null || !decision) {
    throw new Error('timestamp, tool_name, action, and decision are required');
  }

  const normalized = capRecordSize({
    timestamp: String(timestamp),
    session_id: session_id == null ? null : String(session_id),
    task_id: task_id == null ? null : String(task_id),
    agent: agent == null ? null : String(agent),
    tool_name: String(tool_name),
    action: String(action),
    decision: normalizeDecision(decision),
    rule_matched: rule_matched == null ? null : String(rule_matched),
    risk_score: Number.isInteger(risk_score) ? risk_score : null,
    detail: detail == null ? null : String(detail),
  });

  const conn = getDecisionsDb();
  const stmt = conn.prepare(`
    INSERT INTO hook_decisions
      (timestamp, session_id, task_id, agent, tool_name, action, decision, rule_matched, risk_score, detail, truncated)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const result = stmt.run(
    normalized.timestamp,
    normalized.session_id,
    normalized.task_id,
    normalized.agent,
    normalized.tool_name,
    normalized.action,
    normalized.decision,
    normalized.rule_matched,
    normalized.risk_score,
    normalized.detail,
    normalized.truncated,
  );

  return result.lastInsertRowid;
}

function buildWhere({ session_id, task_id, agent, decision, after, before } = {}) {
  const clauses = [];
  const params = [];

  if (session_id) {
    clauses.push('session_id = ?');
    params.push(String(session_id));
  }
  if (task_id) {
    clauses.push('task_id = ?');
    params.push(String(task_id));
  }
  if (agent) {
    clauses.push('agent = ?');
    params.push(String(agent));
  }
  if (decision) {
    clauses.push('decision = ?');
    params.push(normalizeDecision(decision));
  }
  if (after) {
    clauses.push('timestamp >= ?');
    params.push(String(after));
  }
  if (before) {
    clauses.push('timestamp <= ?');
    params.push(String(before));
  }

  return {
    whereSql: clauses.length ? `WHERE ${clauses.join(' AND ')}` : '',
    params,
  };
}

export function queryDecisions({ session_id, task_id, agent, decision, after, before, limit = 50, offset = 0 } = {}) {
  const conn = getDecisionsDb();
  const safeLimit = Math.max(1, Math.min(200, Number.parseInt(limit, 10) || 50));
  const safeOffset = Math.max(0, Number.parseInt(offset, 10) || 0);
  const { whereSql, params } = buildWhere({ session_id, task_id, agent, decision, after, before });

  const rows = conn.prepare(`
    SELECT id, timestamp, session_id, task_id, agent, tool_name, action, decision, rule_matched, risk_score, detail, truncated, created_at
    FROM hook_decisions
    ${whereSql}
    ORDER BY datetime(timestamp) DESC, id DESC
    LIMIT ? OFFSET ?
  `).all(...params, safeLimit, safeOffset);

  const total = conn.prepare(`SELECT COUNT(*) AS total FROM hook_decisions ${whereSql}`).get(...params)?.total || 0;

  return { rows, total };
}

export function getDecisionStats({ after, before } = {}) {
  const conn = getDecisionsDb();
  const { whereSql, params } = buildWhere({ after, before });

  const total = conn.prepare(`SELECT COUNT(*) AS total FROM hook_decisions ${whereSql}`).get(...params)?.total || 0;
  const byDecisionRows = conn.prepare(`
    SELECT decision, COUNT(*) AS count
    FROM hook_decisions
    ${whereSql}
    GROUP BY decision
  `).all(...params);

  const byAgentRows = conn.prepare(`
    SELECT COALESCE(agent, 'unknown') AS agent, COUNT(*) AS count
    FROM hook_decisions
    ${whereSql}
    GROUP BY COALESCE(agent, 'unknown')
    ORDER BY count DESC, agent ASC
  `).all(...params);

  const by_decision = {
    allowed: 0,
    blocked: 0,
    confirmed: 0,
    rate_limited: 0,
  };

  for (const row of byDecisionRows) {
    if (Object.hasOwn(by_decision, row.decision)) {
      by_decision[row.decision] = Number(row.count || 0);
    }
  }

  const by_agent = {};
  for (const row of byAgentRows) {
    by_agent[String(row.agent)] = Number(row.count || 0);
  }

  return {
    total: Number(total || 0),
    by_decision,
    by_agent,
  };
}
