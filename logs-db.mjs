import Database from 'better-sqlite3';
import { existsSync, openSync, readSync, closeSync, statSync } from 'fs';
import { join } from 'path';
import { getDb as getTasksDb } from './tasks-db.mjs';
import { getOpsDb } from './ops-log-db.mjs';

const DB_PATH = join(new URL('.', import.meta.url).pathname, 'logs.db');
const SECURITY_HOOK_LOG_PATH = '/home/openclaw/.openclaw/logs/security-hook.log';
const WATCHER_DB_PATH = '/home/openclaw/.openclaw/workspace/watcher.db';
const CRON_HEALTH_URL = 'http://127.0.0.1:3100/api/cron/health';
const KNOWN_SOURCES = ['task_audit', 'ops_log', 'security_hook', 'cron_health', 'watcher'];

let db;

export function getLogsDb() {
  if (db) return db;

  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      source TEXT NOT NULL,
      agent TEXT,
      severity TEXT NOT NULL DEFAULT 'info',
      message TEXT NOT NULL,
      detail TEXT,
      session_id TEXT,
      task_id TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(source);
    CREATE INDEX IF NOT EXISTS idx_logs_agent ON logs(agent);
    CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity);

    CREATE TABLE IF NOT EXISTS ingest_cursors (
      source TEXT PRIMARY KEY,
      last_rowid INTEGER DEFAULT 0,
      last_inode INTEGER,
      last_offset INTEGER DEFAULT 0,
      last_ingest_at TEXT,
      error_state TEXT
    );
  `);

  return db;
}

function truncateDetail(detail) {
  if (detail == null) return null;
  const text = String(detail);
  return text.length > 4000 ? text.slice(0, 4000) : text;
}

export function insertLog({ timestamp, source, agent = null, severity = 'info', message, detail = null, session_id = null, task_id = null }) {
  if (!timestamp || !source || !message) {
    throw new Error('timestamp, source, and message are required');
  }

  const conn = getLogsDb();
  const stmt = conn.prepare(`
    INSERT INTO logs (timestamp, source, agent, severity, message, detail, session_id, task_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const result = stmt.run(
    String(timestamp),
    String(source),
    agent == null ? null : String(agent),
    severity == null ? 'info' : String(severity),
    String(message),
    truncateDetail(detail),
    session_id == null ? null : String(session_id),
    task_id == null ? null : String(task_id),
  );

  return result.lastInsertRowid;
}

function buildLogWhere({ source, agent, severity, after, before, task_id, session_id } = {}) {
  const clauses = [];
  const params = [];

  if (source) {
    clauses.push('source = ?');
    params.push(String(source));
  }
  if (agent) {
    clauses.push('agent = ?');
    params.push(String(agent));
  }
  if (severity) {
    clauses.push('severity = ?');
    params.push(String(severity));
  }
  if (after) {
    clauses.push('timestamp >= ?');
    params.push(String(after));
  }
  if (before) {
    clauses.push('timestamp <= ?');
    params.push(String(before));
  }
  if (task_id) {
    clauses.push('task_id = ?');
    params.push(String(task_id));
  }
  if (session_id) {
    clauses.push('session_id = ?');
    params.push(String(session_id));
  }

  return {
    whereSql: clauses.length ? `WHERE ${clauses.join(' AND ')}` : '',
    params,
  };
}

export function queryLogs({ source, agent, severity, after, before, task_id, session_id, limit = 50, offset = 0 } = {}) {
  const conn = getLogsDb();
  const safeLimit = Math.max(1, Math.min(200, Number.parseInt(limit, 10) || 50));
  const safeOffset = Math.max(0, Number.parseInt(offset, 10) || 0);
  const { whereSql, params } = buildLogWhere({ source, agent, severity, after, before, task_id, session_id });

  const rows = conn.prepare(`
    SELECT id, timestamp, source, agent, severity, message, detail, session_id, task_id, created_at
    FROM logs
    ${whereSql}
    ORDER BY datetime(timestamp) DESC, id DESC
    LIMIT ? OFFSET ?
  `).all(...params, safeLimit, safeOffset);

  const total = conn.prepare(`SELECT COUNT(*) AS total FROM logs ${whereSql}`).get(...params)?.total || 0;
  return { rows, total };
}

export function getCursor(source) {
  if (!source) return null;
  const conn = getLogsDb();
  return conn.prepare('SELECT * FROM ingest_cursors WHERE source = ?').get(String(source)) || null;
}

export function setCursor(source, updates = {}) {
  if (!source) throw new Error('source is required');

  const conn = getLogsDb();
  const current = getCursor(source) || { source: String(source) };
  const next = {
    source: String(source),
    last_rowid: Object.hasOwn(updates, 'last_rowid') ? updates.last_rowid : (current.last_rowid ?? 0),
    last_inode: Object.hasOwn(updates, 'last_inode') ? updates.last_inode : (current.last_inode ?? null),
    last_offset: Object.hasOwn(updates, 'last_offset') ? updates.last_offset : (current.last_offset ?? 0),
    last_ingest_at: Object.hasOwn(updates, 'last_ingest_at') ? updates.last_ingest_at : (current.last_ingest_at ?? null),
    error_state: Object.hasOwn(updates, 'error_state') ? updates.error_state : (current.error_state ?? null),
  };

  conn.prepare(`
    INSERT INTO ingest_cursors (source, last_rowid, last_inode, last_offset, last_ingest_at, error_state)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(source) DO UPDATE SET
      last_rowid = excluded.last_rowid,
      last_inode = excluded.last_inode,
      last_offset = excluded.last_offset,
      last_ingest_at = excluded.last_ingest_at,
      error_state = excluded.error_state
  `).run(
    next.source,
    next.last_rowid == null ? 0 : Number(next.last_rowid),
    next.last_inode == null ? null : Number(next.last_inode),
    next.last_offset == null ? 0 : Number(next.last_offset),
    next.last_ingest_at == null ? null : String(next.last_ingest_at),
    next.error_state == null ? null : String(next.error_state),
  );

  return getCursor(source);
}

export function pruneOldLogs(days = 30) {
  const conn = getLogsDb();
  const safeDays = Math.max(1, Number.parseInt(days, 10) || 30);
  const result = conn.prepare("DELETE FROM logs WHERE datetime(timestamp) < datetime('now', ?)").run(`-${safeDays} day`);
  return result.changes;
}

export function getIngestHealth() {
  const conn = getLogsDb();
  const bySource = new Map(
    conn.prepare(`
      SELECT c.source, c.last_ingest_at, c.error_state, COUNT(l.id) AS log_count
      FROM ingest_cursors c
      LEFT JOIN logs l ON l.source = c.source
      GROUP BY c.source, c.last_ingest_at, c.error_state
    `).all().map((row) => [row.source, row]),
  );

  return KNOWN_SOURCES.map((source) => {
    const row = bySource.get(source);
    return {
      source,
      last_ingest_at: row?.last_ingest_at || null,
      error_state: row?.error_state || null,
      log_count: Number(row?.log_count || 0),
    };
  });
}

function classifyTaskAuditSeverity(action) {
  const lower = String(action || '').toLowerCase();
  if (lower.includes('fail')) return 'error';
  if (lower.includes('reject') || lower.includes('reopen')) return 'warning';
  return 'info';
}

function classifyOpsSeverity(status) {
  const value = String(status || '').toLowerCase();
  if (value === 'warning') return 'warning';
  if (value === 'error' || value === 'failure') return 'error';
  return 'info';
}

export function ingestTaskAudit() {
  const source = 'task_audit';
  try {
    const cursor = getCursor(source);
    const lastRowid = Number(cursor?.last_rowid || 0);
    const tasksDb = getTasksDb();
    const rows = tasksDb.prepare('SELECT * FROM task_audit WHERE id > ? ORDER BY id ASC LIMIT 100').all(lastRowid);

    let highest = lastRowid;
    for (const row of rows) {
      insertLog({
        timestamp: row.created_at,
        source,
        agent: row.actor || null,
        severity: classifyTaskAuditSeverity(row.action),
        message: `[${row.action}] Task #${row.task_id}: ${row.from_status || ''} → ${row.to_status || ''}`,
        detail: row.details,
        task_id: row.task_id == null ? null : String(row.task_id),
      });
      highest = Math.max(highest, Number(row.id || 0));
    }

    setCursor(source, {
      last_rowid: highest,
      last_ingest_at: new Date().toISOString(),
      error_state: null,
    });

    return { ingested: rows.length, error: null };
  } catch (error) {
    setCursor(source, {
      last_ingest_at: new Date().toISOString(),
      error_state: String(error?.message || error),
    });
    return { ingested: 0, error: String(error?.message || error) };
  }
}

export function ingestOpsLog() {
  const source = 'ops_log';
  try {
    const cursor = getCursor(source);
    const lastRowid = Number(cursor?.last_rowid || 0);
    const opsDb = getOpsDb();
    const rows = opsDb.prepare('SELECT * FROM ops_log WHERE id > ? ORDER BY id ASC LIMIT 100').all(lastRowid);

    let highest = lastRowid;
    for (const row of rows) {
      insertLog({
        timestamp: row.timestamp,
        source,
        agent: 'system',
        severity: classifyOpsSeverity(row.status),
        message: `[${row.category}/${row.action}] ${row.target}: ${row.status}`,
        detail: row.detail,
      });
      highest = Math.max(highest, Number(row.id || 0));
    }

    setCursor(source, {
      last_rowid: highest,
      last_ingest_at: new Date().toISOString(),
      error_state: null,
    });

    return { ingested: rows.length, error: null };
  } catch (error) {
    setCursor(source, {
      last_ingest_at: new Date().toISOString(),
      error_state: String(error?.message || error),
    });
    return { ingested: 0, error: String(error?.message || error) };
  }
}

export function ingestSecurityHookLog() {
  const source = 'security_hook';
  try {
    if (!existsSync(SECURITY_HOOK_LOG_PATH)) {
      return { ingested: 0, error: null };
    }

    const stat = statSync(SECURITY_HOOK_LOG_PATH);
    if (!stat.size) {
      return { ingested: 0, error: null };
    }

    const cursor = getCursor(source);
    const inode = Number(stat.ino);
    let offset = Number(cursor?.last_offset || 0);
    const priorInode = cursor?.last_inode == null ? null : Number(cursor.last_inode);
    if (priorInode !== null && priorInode !== inode) {
      offset = 0;
    }
    if (offset > stat.size) {
      offset = 0;
    }

    const fd = openSync(SECURITY_HOOK_LOG_PATH, 'r');
    try {
      const bytesToRead = Math.max(0, stat.size - offset);
      if (!bytesToRead) {
        setCursor(source, {
          last_inode: inode,
          last_offset: offset,
          last_ingest_at: new Date().toISOString(),
          error_state: null,
        });
        return { ingested: 0, error: null };
      }

      const buffer = Buffer.alloc(bytesToRead);
      const readLen = readSync(fd, buffer, 0, bytesToRead, offset);
      const chunk = buffer.toString('utf8', 0, readLen);
      const lastNewlineIndex = chunk.lastIndexOf('\n');
      if (lastNewlineIndex === -1) {
        setCursor(source, {
          last_inode: inode,
          last_offset: offset,
          last_ingest_at: new Date().toISOString(),
          error_state: null,
        });
        return { ingested: 0, error: null };
      }

      const completeChunk = chunk.slice(0, lastNewlineIndex + 1);
      const lines = completeChunk.split('\n').filter(Boolean);
      let ingested = 0;

      for (const line of lines) {
        try {
          const parsed = JSON.parse(line);
          const tool = parsed.tool || parsed.tool_name || 'tool';
          const action = parsed.action || parsed.event || 'blocked';
          const reason = parsed.reason || parsed.blocked_reason || parsed.message || 'blocked';
          insertLog({
            timestamp: parsed.timestamp || new Date().toISOString(),
            source,
            agent: parsed.agent || 'unknown',
            severity: 'warning',
            message: `[${tool}] ${action}: ${reason}`,
            detail: JSON.stringify(parsed),
            session_id: parsed.sessionId || parsed.session_id || null,
          });
          ingested += 1;
        } catch {
          // Skip malformed lines.
        }
      }

      const consumedBytes = Buffer.byteLength(completeChunk, 'utf8');
      setCursor(source, {
        last_inode: inode,
        last_offset: offset + consumedBytes,
        last_ingest_at: new Date().toISOString(),
        error_state: null,
      });

      return { ingested, error: null };
    } finally {
      closeSync(fd);
    }
  } catch (error) {
    setCursor(source, {
      last_ingest_at: new Date().toISOString(),
      error_state: String(error?.message || error),
    });
    return { ingested: 0, error: String(error?.message || error) };
  }
}

export async function ingestCronHealth() {
  const source = 'cron_health';
  const nowIso = new Date().toISOString();
  try {
    const cursor = getCursor(source);
    let previousState = {};
    if (cursor?.error_state) {
      try {
        const parsed = JSON.parse(cursor.error_state);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          previousState = parsed;
        }
      } catch {
        previousState = {};
      }
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);

    let payload;
    try {
      const response = await fetch(CRON_HEALTH_URL, { signal: controller.signal });
      if (!response.ok) throw new Error(`cron health status ${response.status}`);
      payload = await response.json();
    } finally {
      clearTimeout(timeout);
    }

    const cronEntries = Array.isArray(payload?.crons)
      ? payload.crons
      : (Array.isArray(payload) ? payload : []);

    const nextState = {};
    let ingested = 0;

    for (const cron of cronEntries) {
      const cronId = String(cron?.name || cron?.id || cron?.cron_id || cron?.job || 'unknown');
      const newStatus = String(cron?.lastStatus || cron?.status || 'unknown');
      const oldStatus = Object.hasOwn(previousState, cronId) ? previousState[cronId] : null;
      nextState[cronId] = newStatus;

      if (oldStatus !== null && oldStatus !== newStatus) {
        let severity = 'warning';
        const normalized = newStatus.toLowerCase();
        if (normalized === 'failed' || normalized === 'error') severity = 'error';
        else if (normalized === 'healthy') severity = 'info';

        insertLog({
          timestamp: nowIso,
          source,
          agent: 'system',
          severity,
          message: `Cron ${cronId}: ${oldStatus} → ${newStatus}`,
          detail: cron?.message || null,
        });
        ingested += 1;
      }
    }

    setCursor(source, {
      last_ingest_at: nowIso,
      error_state: JSON.stringify(nextState),
    });

    return { ingested, error: null };
  } catch {
    setCursor(source, {
      last_ingest_at: nowIso,
      error_state: 'cron_health fetch failed',
    });
    return { ingested: 0, error: 'cron_health fetch failed' };
  }
}

function detectWatcherTable(conn) {
  const preferred = ['state_changes', 'watcher_events', 'events', 'runs', 'history'];
  const tables = conn.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((row) => row.name);
  if (!tables.length) return { tables, selected: null };

  for (const table of preferred) {
    if (tables.includes(table)) return { tables, selected: table };
  }

  return { tables, selected: tables[0] };
}

export function ingestWatcher() {
  const source = 'watcher';
  let watcherDb;
  try {
    if (!existsSync(WATCHER_DB_PATH)) {
      return { ingested: 0, error: null };
    }

    const cursor = getCursor(source);
    const lastRowid = Number(cursor?.last_rowid || 0);
    watcherDb = new Database(WATCHER_DB_PATH, { readonly: true, fileMustExist: true });

    const { tables, selected } = detectWatcherTable(watcherDb);
    if (!tables.length || !selected) {
      return { ingested: 0, error: null };
    }

    const columns = new Set(watcherDb.prepare(`PRAGMA table_info(${selected})`).all().map((row) => row.name));
    if (!columns.has('id')) {
      return { ingested: 0, error: null };
    }

    const rows = watcherDb.prepare(`SELECT * FROM ${selected} WHERE id > ? ORDER BY id ASC LIMIT 100`).all(lastRowid);

    let highest = lastRowid;
    for (const row of rows) {
      const action = row.action || row.event || row.state || 'state_change';
      const taskId = row.task_id || row.taskId || null;
      const fromStatus = row.from_status || row.previous_state || row.previousStatus || '';
      const toStatus = row.to_status || row.new_state || row.current_state || '';
      const actor = row.actor || row.agent || 'watcher';
      const ts = row.created_at || row.timestamp || row.updated_at || new Date().toISOString();
      const severity = classifyTaskAuditSeverity(action);

      insertLog({
        timestamp: ts,
        source,
        agent: actor,
        severity,
        message: `[${action}] Task #${taskId || 'n/a'}: ${fromStatus} → ${toStatus}`,
        detail: JSON.stringify(row),
        task_id: taskId == null ? null : String(taskId),
      });
      highest = Math.max(highest, Number(row.id || 0));
    }

    setCursor(source, {
      last_rowid: highest,
      last_ingest_at: new Date().toISOString(),
      error_state: null,
    });

    return { ingested: rows.length, error: null };
  } catch (error) {
    setCursor(source, {
      last_ingest_at: new Date().toISOString(),
      error_state: String(error?.message || error),
    });
    return { ingested: 0, error: String(error?.message || error) };
  } finally {
    if (watcherDb) watcherDb.close();
  }
}

export async function runIngestionCycle() {
  const started = Date.now();
  const sources = {
    task_audit: ingestTaskAudit(),
    ops_log: ingestOpsLog(),
    security_hook: ingestSecurityHookLog(),
    cron_health: await ingestCronHealth(),
    watcher: ingestWatcher(),
  };

  return {
    sources,
    duration_ms: Date.now() - started,
    completed_at: new Date().toISOString(),
  };
}
