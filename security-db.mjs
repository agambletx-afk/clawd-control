import Database from 'better-sqlite3';
import { join } from 'path';

const DB_PATH = join(new URL('.', import.meta.url).pathname, 'security-checks.db');
let db;

function getDb() {
  if (db) return db;

  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS security_checks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      layer TEXT NOT NULL,
      name TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('green', 'yellow', 'red', 'unknown')),
      message TEXT,
      details TEXT,
      remediation TEXT,
      metadata TEXT,
      checked_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_security_layer ON security_checks(layer);
    CREATE INDEX IF NOT EXISTS idx_security_status ON security_checks(status);
    CREATE INDEX IF NOT EXISTS idx_security_time ON security_checks(checked_at);
  `);

  // Migrate: add metadata column if missing (added for Check 10: version currency)
  try {
    db.exec('ALTER TABLE security_checks ADD COLUMN metadata TEXT');
  } catch (e) {
    // Column already exists, ignore
  }

  return db;
}

export function storeChecks(checks) {
  if (!Array.isArray(checks) || checks.length === 0) return 0;

  const conn = getDb();
  const insert = conn.prepare(`
    INSERT INTO security_checks (layer, name, status, message, details, remediation, metadata, checked_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const nowIso = new Date().toISOString();
  const run = conn.transaction((rows) => {
    let inserted = 0;
    for (const check of rows) {
      if (!check || typeof check !== 'object') continue;
      if (!check.layer || !check.name || !check.status) continue;
      if (!['green', 'yellow', 'red', 'unknown'].includes(check.status)) continue;

      const safeStatus = check.status === 'unknown' ? 'yellow' : check.status;
      const metadata = check.metadata == null
        ? null
        : (typeof check.metadata === 'string' ? check.metadata : JSON.stringify(check.metadata));

      insert.run(
        String(check.layer),
        String(check.name),
        safeStatus,
        check.message == null ? null : String(check.message),
        check.details == null ? null : String(check.details),
        check.remediation == null ? null : String(check.remediation),
        metadata,
        check.checked_at ? String(check.checked_at) : nowIso,
      );
      inserted += 1;
    }
    return inserted;
  });

  const inserted = run(checks);
  pruneOld();
  return inserted;
}

export function getHistory(layer, limit = 50) {
  const conn = getDb();
  const safeLimit = Math.max(1, Math.min(200, Number.parseInt(limit, 10) || 50));
  if (!layer || typeof layer !== 'string') return [];

  return conn.prepare(`
    SELECT layer, name, status, message, details, remediation, metadata, checked_at
    FROM security_checks
    WHERE layer = ?
    ORDER BY datetime(checked_at) DESC, id DESC
    LIMIT ?
  `).all(layer, safeLimit);
}

export function getTransitions(limit = 50) {
  const conn = getDb();
  const safeLimit = Math.max(1, Math.min(200, Number.parseInt(limit, 10) || 50));

  return conn.prepare(`
    SELECT checked_at, layer, name, old_status, new_status, message
    FROM (
      SELECT
        id,
        checked_at,
        layer,
        name,
        status AS new_status,
        message,
        LAG(status) OVER (PARTITION BY layer ORDER BY datetime(checked_at), id) AS old_status
      FROM security_checks
    ) transitions
    WHERE old_status IS NULL OR old_status != new_status
    ORDER BY datetime(checked_at) DESC, id DESC
    LIMIT ?
  `).all(safeLimit);
}

export function pruneOld() {
  const conn = getDb();
  const result = conn.prepare("DELETE FROM security_checks WHERE checked_at < datetime('now', '-30 days')").run();
  return result.changes;
}
