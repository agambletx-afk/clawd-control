import {
  existsSync,
  mkdirSync,
  readdirSync,
  statSync,
  copyFileSync,
  mkdtempSync,
  rmSync,
  unlinkSync,
  writeFileSync,
  readFileSync,
  cpSync,
} from 'fs';
import { join, dirname, extname } from 'path';
import { tmpdir } from 'os';
import { execFileSync } from 'child_process';
import { logAction } from './ops-log-db.mjs';

const BACKUP_DIR = '/home/openclaw/backups';
const OPENCLAW_ROOT = '/home/openclaw/.openclaw';
const WORKSPACE_ROOT = join(OPENCLAW_ROOT, 'workspace');
const OPENCLAW_CONFIG = join(OPENCLAW_ROOT, 'openclaw.json');
const EXTENSIONS_ROOT = join(OPENCLAW_ROOT, 'extensions');
const MEMORY_ROOT = join(OPENCLAW_ROOT, 'memory');
const AGENT_ROOT = join(OPENCLAW_ROOT, 'agents/main/agent');
const CRON_ROOT = join(OPENCLAW_ROOT, 'cron');
const BACKUP_NAME_RE = /^backup-\d{8}-\d{6}\.tar\.gz$/;
const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB
const SKIP_DIRS = new Set(['node_modules', 'sessions']);

function nowStamp(date = new Date()) {
  const pad = (n) => String(n).padStart(2, '0');
  return `${date.getFullYear()}${pad(date.getMonth() + 1)}${pad(date.getDate())}-${pad(date.getHours())}${pad(date.getMinutes())}${pad(date.getSeconds())}`;
}

function ensureBackupDir() {
  if (!existsSync(BACKUP_DIR)) mkdirSync(BACKUP_DIR, { recursive: true });
}

function validateFilename(filename) {
  if (typeof filename !== 'string' || !BACKUP_NAME_RE.test(filename) || filename.includes('/') || filename.includes('..')) {
    throw new Error('Invalid backup filename');
  }
}

function safeDetail(text) {
  if (text == null) return null;
  const str = String(text);
  return str.length > 2000 ? str.slice(0, 2000) : str;
}

/**
 * Back up a SQLite database using `sqlite3 .backup` for consistency.
 * Falls back to raw copyFileSync if sqlite3 is unavailable or fails.
 * Returns true if the safe backup was used, false if fell back to raw copy.
 */
function safeSqliteBackup(srcDb, destDb) {
  try {
    mkdirSync(dirname(destDb), { recursive: true });
    execFileSync('sqlite3', [srcDb, `.backup ${destDb}`], { timeout: 60000, stdio: 'pipe' });
    return true;
  } catch {
    // Fall back to raw file copy
    mkdirSync(dirname(destDb), { recursive: true });
    copyFileSync(srcDb, destDb);
    return false;
  }
}

/**
 * Recursively collect files from a directory, respecting SKIP_DIRS and MAX_FILE_SIZE.
 * Returns { files: string[], skippedLarge: string[] } where paths are relative to base.
 */
function collectFiles(base, relative = '') {
  const target = relative ? join(base, relative) : base;
  if (!existsSync(target)) return { files: [], skippedLarge: [] };
  const entries = readdirSync(target, { withFileTypes: true });
  const files = [];
  const skippedLarge = [];
  for (const entry of entries) {
    const rel = relative ? `${relative}/${entry.name}` : entry.name;
    if (SKIP_DIRS.has(entry.name)) continue;
    if (entry.isDirectory()) {
      const sub = collectFiles(base, rel);
      files.push(...sub.files);
      skippedLarge.push(...sub.skippedLarge);
      continue;
    }
    if (!entry.isFile()) continue;
    try {
      const st = statSync(join(base, rel));
      if (st.size > MAX_FILE_SIZE) {
        skippedLarge.push(rel);
        continue;
      }
    } catch { continue; }
    files.push(rel);
  }
  return { files, skippedLarge };
}

/**
 * Collect top-level .json and .env config files from OPENCLAW_ROOT.
 */
function collectRootConfigs() {
  const files = [];
  if (!existsSync(OPENCLAW_ROOT)) return files;
  const entries = readdirSync(OPENCLAW_ROOT, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    if (entry.name === '.env' || extname(entry.name) === '.json') {
      files.push(entry.name);
    }
  }
  return files;
}

function parseBackupTimestamp(name) {
  const match = name.match(/^backup-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})\.tar\.gz$/);
  if (!match) return null;
  const [, y, m, d, hh, mm, ss] = match;
  return new Date(`${y}-${m}-${d}T${hh}:${mm}:${ss}Z`).toISOString();
}

/**
 * Stage files from a source directory into a staging subdirectory.
 * Uses safeSqliteBackup for .db files. Returns staging stats.
 */
function stageSection(sectionName, sourceRoot, stagingBase, fileList) {
  const stagingDir = join(stagingBase, sectionName);
  mkdirSync(stagingDir, { recursive: true });
  const manifestFiles = [];
  const sqliteFallbacks = [];
  let totalSize = 0;

  for (const rel of fileList) {
    const src = join(sourceRoot, rel);
    const dest = join(stagingDir, rel);
    mkdirSync(dirname(dest), { recursive: true });

    let st;
    try { st = statSync(src); } catch { continue; }

    if (extname(rel) === '.db') {
      const usedSafe = safeSqliteBackup(src, dest);
      if (!usedSafe) sqliteFallbacks.push(rel);
    } else {
      copyFileSync(src, dest);
    }

    // Use actual copied size for manifest
    try {
      const destSt = statSync(dest);
      totalSize += destSt.size;
      manifestFiles.push({ path: `${sectionName}/${rel}`, size_bytes: destSt.size });
    } catch {
      totalSize += st.size;
      manifestFiles.push({ path: `${sectionName}/${rel}`, size_bytes: st.size });
    }
  }

  return { manifestFiles, totalSize, sqliteFallbacks };
}

export function createSnapshot() {
  ensureBackupDir();
  const started = Date.now();
  const timestamp = new Date().toISOString();
  const filename = `backup-${nowStamp()}.tar.gz`;
  const backupPath = join(BACKUP_DIR, filename);
  const tempDir = mkdtempSync(join(tmpdir(), 'ops-backup-'));
  try {
    let totalSize = 0;
    const manifestFiles = [];
    const sections = [];
    const allSkippedLarge = [];
    const allSqliteFallbacks = [];

    // ── Section: workspace ──
    const ws = collectFiles(WORKSPACE_ROOT);
    if (ws.files.length) {
      const staged = stageSection('workspace', WORKSPACE_ROOT, tempDir, ws.files);
      manifestFiles.push(...staged.manifestFiles);
      totalSize += staged.totalSize;
      allSqliteFallbacks.push(...staged.sqliteFallbacks);
      sections.push('workspace');
    }
    allSkippedLarge.push(...ws.skippedLarge.map((f) => `workspace/${f}`));

    // ── Section: extensions ──
    const ext = collectFiles(EXTENSIONS_ROOT);
    if (ext.files.length) {
      const staged = stageSection('extensions', EXTENSIONS_ROOT, tempDir, ext.files);
      manifestFiles.push(...staged.manifestFiles);
      totalSize += staged.totalSize;
      allSqliteFallbacks.push(...staged.sqliteFallbacks);
      sections.push('extensions');
    }
    allSkippedLarge.push(...ext.skippedLarge.map((f) => `extensions/${f}`));

    // ── Section: memory ──
    const mem = collectFiles(MEMORY_ROOT);
    if (mem.files.length) {
      const staged = stageSection('memory', MEMORY_ROOT, tempDir, mem.files);
      manifestFiles.push(...staged.manifestFiles);
      totalSize += staged.totalSize;
      allSqliteFallbacks.push(...staged.sqliteFallbacks);
      sections.push('memory');
    }
    allSkippedLarge.push(...mem.skippedLarge.map((f) => `memory/${f}`));

    // ── Section: agents ──
    const ag = collectFiles(AGENT_ROOT);
    if (ag.files.length) {
      const staged = stageSection('agents', AGENT_ROOT, tempDir, ag.files);
      manifestFiles.push(...staged.manifestFiles);
      totalSize += staged.totalSize;
      allSqliteFallbacks.push(...staged.sqliteFallbacks);
      sections.push('agents');
    }
    allSkippedLarge.push(...ag.skippedLarge.map((f) => `agents/${f}`));

    // ── Section: crons ──
    const cr = collectFiles(CRON_ROOT);
    if (cr.files.length) {
      const staged = stageSection('crons', CRON_ROOT, tempDir, cr.files);
      manifestFiles.push(...staged.manifestFiles);
      totalSize += staged.totalSize;
      allSqliteFallbacks.push(...staged.sqliteFallbacks);
      sections.push('crons');
    }
    allSkippedLarge.push(...cr.skippedLarge.map((f) => `crons/${f}`));

    // ── Section: config (top-level .json and .env from ~/.openclaw/) ──
    const configFiles = collectRootConfigs();
    if (configFiles.length) {
      const stagingConfig = join(tempDir, 'config');
      mkdirSync(stagingConfig, { recursive: true });
      for (const name of configFiles) {
        const src = join(OPENCLAW_ROOT, name);
        const dest = join(stagingConfig, name);
        try {
          copyFileSync(src, dest);
          const st = statSync(dest);
          totalSize += st.size;
          manifestFiles.push({ path: `config/${name}`, size_bytes: st.size });
        } catch { /* skip unreadable files */ }
      }
      sections.push('config');
    }

    const manifest = {
      timestamp,
      sections,
      file_count: manifestFiles.length,
      total_size_bytes: totalSize,
      skipped_large_files: allSkippedLarge.length ? allSkippedLarge : undefined,
      sqlite_raw_fallbacks: allSqliteFallbacks.length ? allSqliteFallbacks : undefined,
      files: manifestFiles,
    };
    writeFileSync(join(tempDir, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf8');

    execFileSync('tar', ['-czf', backupPath, '-C', tempDir, '.'], { timeout: 300000, stdio: 'pipe' });
    const archiveSize = statSync(backupPath).size;
    const duration = Date.now() - started;
    logAction({
      category: 'backup',
      action: 'snapshot',
      target: sections.join(','),
      status: 'success',
      detail: `Created ${filename} (${sections.length} sections, ${manifest.file_count} files)`,
      duration_ms: duration,
    });
    return { filename, path: backupPath, size_bytes: archiveSize, file_count: manifest.file_count, timestamp, sections };
  } catch (error) {
    logAction({
      category: 'backup',
      action: 'snapshot',
      target: 'workspace',
      status: 'failed',
      detail: safeDetail(error.message),
      duration_ms: Date.now() - started,
    });
    throw error;
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

export function listSnapshots() {
  ensureBackupDir();
  const now = Date.now();
  return readdirSync(BACKUP_DIR)
    .filter((f) => BACKUP_NAME_RE.test(f))
    .map((filename) => {
      const fullPath = join(BACKUP_DIR, filename);
      const st = statSync(fullPath);
      const ts = parseBackupTimestamp(filename) || st.mtime.toISOString();
      return {
        filename,
        size_bytes: st.size,
        timestamp: ts,
        age_days: Math.max(0, Math.floor((now - new Date(ts).getTime()) / 86400000)),
      };
    })
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
}

export function getSnapshotManifest(filename) {
  validateFilename(filename);
  const backupPath = join(BACKUP_DIR, filename);
  if (!existsSync(backupPath)) throw new Error('Backup not found');
  const output = execFileSync('tar', ['-xOf', backupPath, './manifest.json'], { timeout: 120000, encoding: 'utf8' });
  return JSON.parse(output);
}

export function restoreSnapshot(filename) {
  validateFilename(filename);
  const started = Date.now();
  const backupPath = join(BACKUP_DIR, filename);
  if (!existsSync(backupPath)) throw new Error('Backup not found');

  const tempDir = mkdtempSync(join(tmpdir(), 'ops-restore-'));
  try {
    execFileSync('tar', ['-xzf', backupPath, '-C', tempDir], { timeout: 120000, stdio: 'pipe' });
    let restored = 0;

    const extractedWorkspace = join(tempDir, 'workspace');
    if (existsSync(extractedWorkspace)) {
      cpSync(extractedWorkspace, WORKSPACE_ROOT, { recursive: true, force: true });
      restored += collectFiles(extractedWorkspace).files.length;
    }

    const configPath = join(tempDir, 'openclaw.json');
    if (existsSync(configPath)) {
      mkdirSync(join(OPENCLAW_CONFIG, '..'), { recursive: true });
      copyFileSync(configPath, OPENCLAW_CONFIG);
      restored += 1;
    }

    const duration = Date.now() - started;
    logAction({
      category: 'backup',
      action: 'restore',
      target: filename,
      status: 'success',
      detail: `Restored ${restored} files`,
      duration_ms: duration,
    });
    return { restored_files: restored, timestamp: new Date().toISOString() };
  } catch (error) {
    logAction({
      category: 'backup',
      action: 'restore',
      target: filename,
      status: 'failed',
      detail: safeDetail(error.message),
      duration_ms: Date.now() - started,
    });
    throw error;
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

export function deleteSnapshot(filename) {
  validateFilename(filename);
  const started = Date.now();
  const backupPath = join(BACKUP_DIR, filename);
  if (!existsSync(backupPath)) throw new Error('Backup not found');
  try {
    unlinkSync(backupPath);
    logAction({ category: 'backup', action: 'delete', target: filename, status: 'success', detail: 'Deleted backup', duration_ms: Date.now() - started });
    return { deleted: true, filename };
  } catch (error) {
    logAction({ category: 'backup', action: 'delete', target: filename, status: 'failed', detail: safeDetail(error.message), duration_ms: Date.now() - started });
    throw error;
  }
}

export function enforceRetention(maxBackups = 10, maxAgeDays = 30) {
  ensureBackupDir();
  const safeMax = Math.max(1, Number.parseInt(maxBackups, 10) || 10);
  const safeAge = Math.max(1, Number.parseInt(maxAgeDays, 10) || 30);
  const snapshots = listSnapshots().sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
  const now = Date.now();

  const deleteSet = new Set();
  for (const snap of snapshots) {
    const ageDays = Math.floor((now - new Date(snap.timestamp).getTime()) / 86400000);
    if (ageDays > safeAge) deleteSet.add(snap.filename);
  }

  const remaining = snapshots.filter((s) => !deleteSet.has(s.filename));
  if (remaining.length > safeMax) {
    const extra = remaining.length - safeMax;
    for (let i = 0; i < extra; i += 1) deleteSet.add(remaining[i].filename);
  }

  const deletedFiles = [];
  for (const filename of snapshots.map((s) => s.filename)) {
    if (!deleteSet.has(filename)) continue;
    try {
      unlinkSync(join(BACKUP_DIR, filename));
      deletedFiles.push(filename);
      logAction({ category: 'cleanup', action: 'delete', target: filename, status: 'success', detail: 'Retention cleanup deleted backup' });
    } catch (error) {
      logAction({ category: 'cleanup', action: 'delete', target: filename, status: 'failed', detail: safeDetail(error.message) });
    }
  }

  return { deleted_count: deletedFiles.length, deleted_files: deletedFiles };
}
