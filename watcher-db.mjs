import Database from 'better-sqlite3';
import { join } from 'path';

const DB_PATH = join(new URL('.', import.meta.url).pathname, 'watcher.db');
let db;

function getDb() {
  if (db) return db;

  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS watcher_runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      job_id TEXT NOT NULL,
      job_type TEXT NOT NULL CHECK(job_type IN ('system', 'gateway')),
      status TEXT NOT NULL,
      started_at TEXT,
      finished_at TEXT,
      duration_ms INTEGER,
      exit_code INTEGER,
      heartbeat_version TEXT,
      message TEXT,
      recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_watcher_job_id ON watcher_runs(job_id);
    CREATE INDEX IF NOT EXISTS idx_watcher_recorded ON watcher_runs(recorded_at DESC);
    CREATE INDEX IF NOT EXISTS idx_watcher_job_time ON watcher_runs(job_id, recorded_at DESC);
  `);

  return db;
}

function isSignificantDurationDelta(prevDurationMs, nextDurationMs) {
  if (prevDurationMs == null && nextDurationMs == null) return false;
  if (!Number.isFinite(prevDurationMs) || !Number.isFinite(nextDurationMs)) return true;
  const denominator = Math.max(Math.abs(prevDurationMs), 1);
  return Math.abs(nextDurationMs - prevDurationMs) / denominator >= 0.1;
}

export function recordRun(run) {
  if (!run || typeof run !== 'object') return false;
  if (!run.job_id || !run.job_type || !run.status) return false;
  if (!['system', 'gateway'].includes(run.job_type)) return false;

  const conn = getDb();
  const latest = conn.prepare(`
    SELECT status, duration_ms
    FROM watcher_runs
    WHERE job_id = ?
    ORDER BY datetime(recorded_at) DESC, id DESC
    LIMIT 1
  `).get(String(run.job_id));

  const nextDuration = run.duration_ms == null ? null : Number.parseInt(run.duration_ms, 10);
  if (
    latest
    && latest.status === String(run.status)
    && !isSignificantDurationDelta(latest.duration_ms == null ? null : Number(latest.duration_ms), nextDuration)
  ) {
    return false;
  }

  conn.prepare(`
    INSERT INTO watcher_runs (
      job_id,
      job_type,
      status,
      started_at,
      finished_at,
      duration_ms,
      exit_code,
      heartbeat_version,
      message
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    String(run.job_id),
    String(run.job_type),
    String(run.status),
    run.started_at == null ? null : String(run.started_at),
    run.finished_at == null ? null : String(run.finished_at),
    Number.isFinite(nextDuration) ? nextDuration : null,
    run.exit_code == null ? null : Number.parseInt(run.exit_code, 10),
    run.heartbeat_version == null ? null : String(run.heartbeat_version),
    run.message == null ? null : String(run.message),
  );

  return true;
}

export function getHistory(jobId, limit = 20) {
  if (!jobId || typeof jobId !== 'string') return [];
  const conn = getDb();
  const safeLimit = Math.max(1, Math.min(100, Number.parseInt(limit, 10) || 20));

  return conn.prepare(`
    SELECT status, started_at, finished_at, duration_ms, exit_code, recorded_at
    FROM watcher_runs
    WHERE job_id = ?
    ORDER BY datetime(recorded_at) DESC, id DESC
    LIMIT ?
  `).all(jobId, safeLimit);
}

export function getTrends(jobId, hours = 168) {
  if (!jobId || typeof jobId !== 'string') return [];
  const conn = getDb();
  const safeHours = Math.max(1, Math.min(720, Number.parseInt(hours, 10) || 168));

  return conn.prepare(`
    SELECT recorded_at, status, duration_ms
    FROM watcher_runs
    WHERE job_id = ?
      AND datetime(recorded_at) >= datetime('now', '-' || ? || ' hours')
    ORDER BY datetime(recorded_at) ASC, id ASC
  `).all(jobId, safeHours);
}

export function getFlapping(jobId, hours = 24) {
  const trends = getTrends(jobId, hours);
  let transitions = 0;
  let prevStatus = null;

  for (const row of trends) {
    const status = String(row.status || '');
    if (prevStatus != null && status !== prevStatus) transitions += 1;
    prevStatus = status;
  }

  return transitions;
}

export function pruneOldRuns(days = 7) {
  const conn = getDb();
  const safeDays = Math.max(1, Math.min(365, Number.parseInt(days, 10) || 7));
  const result = conn.prepare(`
    DELETE FROM watcher_runs
    WHERE datetime(recorded_at) < datetime('now', '-' || ? || ' days')
  `).run(safeDays);
  return result.changes;
}

export function getJobStats(jobId) {
  if (!jobId || typeof jobId !== 'string') {
    return {
      total_runs: 0,
      success_count: 0,
      failure_count: 0,
      avg_duration_ms: null,
      p95_duration_ms: null,
      last_failure_at: null,
      consecutive_current_status: 0,
      flap_count_24h: 0,
    };
  }

  const conn = getDb();
  const rows = conn.prepare(`
    SELECT status, duration_ms, recorded_at
    FROM watcher_runs
    WHERE job_id = ?
    ORDER BY datetime(recorded_at) DESC, id DESC
  `).all(jobId);

  const totalRuns = rows.length;
  const successCount = rows.filter((r) => /healthy/i.test(r.status)).length;
  const failureRows = rows.filter((r) => !/healthy/i.test(r.status));
  const durations = rows
    .map((r) => (r.duration_ms == null ? null : Number(r.duration_ms)))
    .filter((n) => Number.isFinite(n))
    .sort((a, b) => a - b);

  const avgDuration = durations.length
    ? Math.round(durations.reduce((sum, d) => sum + d, 0) / durations.length)
    : null;
  const p95Duration = durations.length
    ? durations[Math.max(0, Math.ceil(durations.length * 0.95) - 1)]
    : null;

  let consecutiveCurrentStatus = 0;
  if (rows[0]?.status) {
    const currentStatus = rows[0].status;
    for (const row of rows) {
      if (row.status !== currentStatus) break;
      consecutiveCurrentStatus += 1;
    }
  }

  return {
    total_runs: totalRuns,
    success_count: successCount,
    failure_count: failureRows.length,
    avg_duration_ms: avgDuration,
    p95_duration_ms: p95Duration,
    last_failure_at: failureRows[0]?.recorded_at || null,
    consecutive_current_status: consecutiveCurrentStatus,
    flap_count_24h: getFlapping(jobId, 24),
  };
}
