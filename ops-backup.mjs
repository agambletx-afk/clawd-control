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
import { join } from 'path';
import { tmpdir } from 'os';
import { execFileSync } from 'child_process';
import { logAction } from './ops-log-db.mjs';

const BACKUP_DIR = '/home/openclaw/backups';
const WORKSPACE_ROOT = '/home/openclaw/.openclaw/workspace';
const OPENCLAW_CONFIG = '/home/openclaw/.openclaw/openclaw.json';
const BACKUP_NAME_RE = /^backup-\d{8}-\d{6}\.tar\.gz$/;

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

function collectWorkspaceFiles(base, relative = '') {
  const target = relative ? join(base, relative) : base;
  const entries = readdirSync(target, { withFileTypes: true });
  const out = [];
  for (const entry of entries) {
    const rel = relative ? `${relative}/${entry.name}` : entry.name;
    if (entry.name === 'sessions' || entry.name === 'node_modules') continue;
    if (entry.isDirectory()) {
      out.push(...collectWorkspaceFiles(base, rel));
      continue;
    }
    if (!entry.isFile()) continue;
    out.push(rel);
  }
  return out;
}

function parseBackupTimestamp(name) {
  const match = name.match(/^backup-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})\.tar\.gz$/);
  if (!match) return null;
  const [, y, m, d, hh, mm, ss] = match;
  return new Date(`${y}-${m}-${d}T${hh}:${mm}:${ss}Z`).toISOString();
}

export function createSnapshot() {
  ensureBackupDir();
  const started = Date.now();
  const timestamp = new Date().toISOString();
  const filename = `backup-${nowStamp()}.tar.gz`;
  const backupPath = join(BACKUP_DIR, filename);
  const tempDir = mkdtempSync(join(tmpdir(), 'ops-backup-'));
  try {
    const workspaceFiles = existsSync(WORKSPACE_ROOT) ? collectWorkspaceFiles(WORKSPACE_ROOT) : [];
    let totalSize = 0;
    const manifestFiles = [];

    const stagingWorkspace = join(tempDir, 'workspace');
    mkdirSync(stagingWorkspace, { recursive: true });
    for (const rel of workspaceFiles) {
      const src = join(WORKSPACE_ROOT, rel);
      const dest = join(stagingWorkspace, rel);
      mkdirSync(join(dest, '..'), { recursive: true });
      copyFileSync(src, dest);
      const st = statSync(src);
      totalSize += st.size;
      manifestFiles.push({ path: `workspace/${rel}`, size_bytes: st.size });
    }

    if (existsSync(OPENCLAW_CONFIG)) {
      const configDest = join(tempDir, 'openclaw.json');
      copyFileSync(OPENCLAW_CONFIG, configDest);
      const st = statSync(OPENCLAW_CONFIG);
      totalSize += st.size;
      manifestFiles.push({ path: 'openclaw.json', size_bytes: st.size });
    }

    const manifest = {
      timestamp,
      file_count: manifestFiles.length,
      total_size_bytes: totalSize,
      files: manifestFiles,
    };
    writeFileSync(join(tempDir, 'manifest.json'), JSON.stringify(manifest, null, 2), 'utf8');

    execFileSync('tar', ['-czf', backupPath, '-C', tempDir, '.'], { timeout: 120000, stdio: 'pipe' });
    const archiveSize = statSync(backupPath).size;
    const duration = Date.now() - started;
    logAction({
      category: 'backup',
      action: 'snapshot',
      target: 'workspace',
      status: 'success',
      detail: `Created ${filename}`,
      duration_ms: duration,
    });
    return { filename, path: backupPath, size_bytes: archiveSize, file_count: manifest.file_count, timestamp };
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
  const output = execFileSync('tar', ['-xOf', backupPath, 'manifest.json'], { timeout: 120000, encoding: 'utf8' });
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
      restored += collectWorkspaceFiles(extractedWorkspace).length;
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
