import Database from 'better-sqlite3';
import { join } from 'path';

const DB_PATH = join(new URL('.', import.meta.url).pathname, 'ops-log.db');
let db;

export function getOpsDb() {
  if (db) return db;
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS ops_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL DEFAULT (datetime('now')),
      category TEXT NOT NULL,
      action TEXT NOT NULL,
      target TEXT NOT NULL,
      status TEXT NOT NULL,
      detail TEXT,
      duration_ms INTEGER
    );

    CREATE INDEX IF NOT EXISTS idx_ops_log_timestamp ON ops_log(timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_ops_log_category ON ops_log(category);
  `);
  return db;
}

function truncateDetail(detail) {
  if (detail == null) return null;
  const text = String(detail);
  return text.length > 2000 ? text.slice(0, 2000) : text;
}

export function logAction({ category, action, target, status, detail = null, duration_ms = null }) {
  if (!category || !action || !target || !status) {
    throw new Error('category, action, target, and status are required');
  }
  const conn = getOpsDb();
  const stmt = conn.prepare(`
    INSERT INTO ops_log (category, action, target, status, detail, duration_ms)
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  const result = stmt.run(
    String(category),
    String(action),
    String(target),
    String(status),
    truncateDetail(detail),
    Number.isInteger(duration_ms) ? duration_ms : null,
  );
  return conn.prepare('SELECT * FROM ops_log WHERE id = ?').get(result.lastInsertRowid);
}

export function getLog({ limit = 50, offset = 0, category = null } = {}) {
  const conn = getOpsDb();
  const safeLimit = Math.max(1, Math.min(200, Number.parseInt(limit, 10) || 50));
  const safeOffset = Math.max(0, Number.parseInt(offset, 10) || 0);

  let sql = 'SELECT * FROM ops_log';
  const params = [];
  if (typeof category === 'string' && category.trim()) {
    sql += ' WHERE category = ?';
    params.push(category.trim());
  }
  sql += ' ORDER BY datetime(timestamp) DESC, id DESC LIMIT ? OFFSET ?';
  params.push(safeLimit, safeOffset);

  const entries = conn.prepare(sql).all(...params);

  let totalSql = 'SELECT COUNT(*) AS total FROM ops_log';
  const totalParams = [];
  if (typeof category === 'string' && category.trim()) {
    totalSql += ' WHERE category = ?';
    totalParams.push(category.trim());
  }
  const total = conn.prepare(totalSql).get(...totalParams).total;

  return { entries, total };
}

export function getLogStats() {
  const conn = getOpsDb();
  const total = conn.prepare('SELECT COUNT(*) AS count FROM ops_log').get().count;
  const last24h = conn.prepare("SELECT COUNT(*) AS count FROM ops_log WHERE datetime(timestamp) >= datetime('now', '-1 day')").get().count;
  const last7d = conn.prepare("SELECT COUNT(*) AS count FROM ops_log WHERE datetime(timestamp) >= datetime('now', '-7 day')").get().count;
  const latest = conn.prepare('SELECT timestamp FROM ops_log ORDER BY datetime(timestamp) DESC, id DESC LIMIT 1').get();

  return {
    total,
    last_24h: last24h,
    last_7d: last7d,
    most_recent_timestamp: latest?.timestamp || null,
  };
}

export function pruneLog(retainDays = 90) {
  const conn = getOpsDb();
  const safeDays = Math.max(1, Number.parseInt(retainDays, 10) || 90);
  const result = conn.prepare("DELETE FROM ops_log WHERE datetime(timestamp) < datetime('now', ?)" ).run(`-${safeDays} day`);
  return result.changes;
}
