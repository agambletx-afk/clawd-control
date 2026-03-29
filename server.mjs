#!/usr/bin/env node
/**
 * Clawd Control — Server
 * 
 * HTTP server with REST API + SSE for live dashboard updates.
 * Aggregates data from AgentCollector.
 */

import http from 'http';
const { createServer } = http;
import { readFileSync, existsSync, writeFileSync, copyFileSync, readdirSync, statSync, unlinkSync, renameSync, createReadStream } from 'fs';
import { join, extname, resolve, sep } from 'path';
import { createInterface } from 'readline';
import { gzipSync } from 'zlib';
import { exec, execFileSync, execSync, spawn, spawnSync } from 'child_process';
import { AgentCollector } from './collector.mjs';
import { createAgent } from './create-agent.mjs';
import { discoverAgents } from './discover.mjs';
import {
  getDb,
  getAllTasks,
  getTaskById,
  getNextTask,
  createTask,
  updateTask,
  addHistory,
  getHistory,
  getTaskStats,
  getProposalCount,
  getCurrentTaskSummary,
  recordFailure,
  getTaskFailures,
  resetTaskRetries,
  createArtifact,
  getArtifacts,
  addAuditEntry,
  getAuditTrail,
  checkArtifactGate,
  createCheckpoint,
  getCheckpoints,
  supersedeCheckpoint,
  flagStaleDependencies,
  clearStaleDependency,
  claimTask,
  refreshClaim,
  releaseClaim,
  updateIntent,
  getIntentHistory,
  getGoalCompositionStatus,
  createHandoff,
  getHandoffs,
  resolveHandoff,
  getStaleTasks,
  getOverdueTasks,
  validateTransition,
  getTaskTypeConfigs,
  getTaskTypeConfig,
  createGoal,
  getGoalById,
  getAllGoals,
  updateGoal,
  archiveGoal,
  getGoalTasks,
  goalNeedsTasks,
  createTemplate,
  getTemplateById,
  getAllTemplates,
  updateTemplate,
  deleteTemplate,
  instantiatePipeline,
  getPipelineInstance,
  listPipelineInstances,
  updatePipelineInstance,
  createTaskSession,
  getTaskSessions,
  tryAutoAdvance,
  getKillSwitches,
} from './tasks-db.mjs';

import { createHash, randomBytes, timingSafeEqual } from 'crypto';

import { logAction, getLog, getLogStats, pruneLog } from './ops-log-db.mjs';
import { queryLogs, getIngestHealth, pruneOldLogs, runIngestionCycle } from './logs-db.mjs';
import { queryDecisions, getDecisionStats } from './security-decisions-db.mjs';
import { storeChecks, getHistory as getSecurityHistory, getTransitions } from './security-db.mjs';
import { recordRun, getHistory as getWatcherHistory, getTrends as getWatcherTrends, getJobStats, pruneOldRuns } from './watcher-db.mjs';
import { createSnapshot, listSnapshots, getSnapshotManifest, restoreSnapshot, deleteSnapshot, enforceRetention } from './ops-backup.mjs';
import { ChatGatewayClient, getChatMessages, getLatestMessage } from './chat-api.mjs';

const PORT = parseInt(process.argv.find((_, i, a) => a[i - 1] === '--port') || '3100');
const DIR = new URL('.', import.meta.url).pathname;
const AUTH_DISABLED = String(process.env.AUTH_DISABLED || '').toLowerCase() === 'true';
const APIS_CONFIG_PATH = join(DIR, 'apis-config.json');
const HEALTH_RESULTS_PATH = '/tmp/api-health-results.json';
const CLI_USAGE_PATH = '/tmp/cli-usage.json';
const COST_SENTINEL_STATUS_PATH = join(process.env.HOME || '/home/openclaw', '.openclaw', 'workspace', 'cost-sentinel-status.json');
const CORTEX_SENTINEL_STATUS_PATH = join(process.env.HOME || '/home/openclaw', '.openclaw', 'workspace', 'cortex-sentinel-status.json');
const CORTEX_QUOTA_STATE_PATH = join(process.env.HOME || '/home/openclaw', '.openclaw', 'workspace', 'cortex', 'quota-state.json');
const BUDGET_CONFIG_PATH = join(process.env.HOME || '/home/openclaw', '.openclaw', 'workspace', 'budget.json');
const SENTINEL_CONFIG_PATH = join(process.env.HOME || '/home/openclaw', '.openclaw', 'workspace', 'sentinel-config.json');
const RATE_LIMITS_CONFIG_PATH = join(process.env.HOME || '/home/openclaw', '.openclaw', 'workspace', 'rate-limits.json');
const KILL_SWITCHES_PATH = '/home/openclaw/.openclaw/workspace/kill-switches.json';
const PROXY_API_BASE_URL = 'https://gw.dataimpulse.com:777';
const PROXY_PLAN_TOTAL_BYTES = 25 * 1024 * 1024 * 1024;
const PROXY_FETCH_TIMEOUT_MS = 10000;
const PROXY_STATS_CACHE_MS = 5 * 60 * 1000;
const PROXY_HISTORY_CACHE_MS = 15 * 60 * 1000;
const PROXY_ERRORS_CACHE_MS = 15 * 60 * 1000;
const PROXY_TOP_HOSTS_CACHE_MS = 15 * 60 * 1000;
const MEMORY_FACTS_DB_PATH = '/home/openclaw/.openclaw/memory/facts.db';
const MEMORY_TELEMETRY_PATH = '/tmp/openclaw/memory-telemetry.jsonl';
const MEMORY_CAPTURE_TELEMETRY_PATH = '/tmp/openclaw/capture-telemetry.jsonl';
const MEMORY_INGEST_LOG_PATH = '/home/openclaw/.openclaw/memory/ingest.log';
const MEMORY_PRUNE_LOG_PATH = '/home/openclaw/.openclaw/memory/prune.log';
const MEMORY_FILES_DIR_PATH = '/home/openclaw/.openclaw/workspace/memory';
const OPENCLAW_CONFIG_PATH = '/home/openclaw/.openclaw/openclaw.json';
const MEMORY_CAPTURE_REPO_PATH = join(DIR, 'extensions/graph-memory/capture.js');
const MEMORY_CAPTURE_RUNTIME_PATH = '/home/openclaw/.openclaw/extensions/graph-memory/capture.js';
const OPENCLAW_DIR = join(homedir(), '.openclaw');
const OPENCLAW_WORKSPACE = join(OPENCLAW_DIR, 'workspace');
const CORTEX_CONFIG_PATH = join(OPENCLAW_WORKSPACE, 'cortex/cortex.json');
const OUTCOME_DB_PATH = join(OPENCLAW_WORKSPACE, 'cortex', 'outcome.db');
const CORTEX_LOG_PATH = join(OPENCLAW_DIR, 'logs/cortex.log');
const CRON_JOBS_PATH = join(homedir(), '.openclaw', 'cron', 'jobs.json');
const PRIMARY_ENV_PATH = join(DIR, '.env');
const SECONDARY_ENV_PATH = join(process.env.HOME || '/home/openclaw', '.openclaw', 'workspace', '.env');
const LOCAL_HEALTH_SCRIPT_PATH = join(DIR, 'scripts', 'check-system-health.sh');
const SYSTEM_HEALTH_SCRIPT_PATH = '/usr/local/bin/check-system-health.sh';
const SECURITY_HEALTH_RESULTS_PATH = '/tmp/security-health-results.json';
const SECURITY_CHECK_SCRIPT_PATH = '/usr/local/bin/check-security-health.sh';
const SECURITY_TEST_RESULTS_PATH = '/tmp/security-test-results.json';
const SECURITY_TEST_SCRIPT_PATH = '/usr/local/bin/run-security-test.sh';
const SECURITY_TEST_LOCK_PATH = '/tmp/security-test.lock';
const API_LIVENESS_PATH = '/tmp/openclaw-api-liveness.json';
const API_LIVENESS_LOG_PATH = '/var/log/openclaw-liveness.log';
const VERSION_CHECK_RESULTS_PATH = '/tmp/openclaw-version-check.json';
const VERSION_CHECK_SCRIPT_PATH = '/usr/local/bin/check-openclaw-version.sh';
const VERIFY_RESULTS_PATH = '/tmp/verify-deployment-results.json';
const VERIFY_SCRIPT_PATH = '/usr/local/bin/verify-deployment.sh';
const SOUL_MD_PATH = '/home/openclaw/.openclaw/workspace/SOUL.md';
const SOUL_HASH_PATH = '/home/openclaw/.openclaw/.soul-hash';
const CONFIG_DRIFT_BASELINE_PATH = '/var/tmp/config-drift-baseline.json';
const CREDENTIAL_ALLOWLIST_PATH = '/home/openclaw/.openclaw/workspace/credential-allowlist.json';
const WATCHER_STATUS_PATH = '/home/openclaw/.openclaw/workspace/watcher-status.json';
const WATCHER_CONFIG_PATH = '/etc/jarvis/watcher.json';
const OPS_PULSE_STATE_PATH = join(OPENCLAW_WORKSPACE, '.pulse-state.json');
const OPS_SWEEP_STATUS_PATH = join(OPENCLAW_WORKSPACE, 'sweep-status.json');
const OPS_AUDIT_STATUS_PATH = join(OPENCLAW_WORKSPACE, 'audit-status.json');
const OPS_KILL_SWITCHES_PATH = join(OPENCLAW_WORKSPACE, '.kill-switches.json');
const OPS_RECOVERY_LOG_PATH = join(OPENCLAW_WORKSPACE, '.recovery-log.jsonl');
const OPS_DOCTOR_STATUS_PATH = join(OPENCLAW_WORKSPACE, '.doctor-status.json');
const OPS_DOCTOR_SUPPRESSED_PATH = join(OPENCLAW_WORKSPACE, '.doctor-suppressed.json');
const OPS_CRITICAL_HASHES_PATH = join(OPENCLAW_WORKSPACE, '.critical-file-hashes.json');
const OPS_KILL_SWITCH_NAMES = new Set(['heartbeat_injection', 'outbound_telegram', 'compaction', 'autonomous_cron_rerun']);
const doctorRepairTokens = new Map();
let lastStoredSecurityGeneratedAt = null;
let verificationRunning = false;
let lastWatcherPruneAt = 0;
const proxyApiCache = {
  stats: { timestamp: 0, data: null },
  history: new Map(),
  errors: new Map(),
  topHosts: new Map(),
};

const memoryApiCache = new Map();
let lastLogsIngestionCycle = null;

function getMemoryCached(cacheKey, ttlMs, computeFn) {
  const now = Date.now();
  const cached = memoryApiCache.get(cacheKey);
  if (cached && (now - cached.ts) < ttlMs) {
    return cached.data;
  }
  const data = computeFn();
  memoryApiCache.set(cacheKey, { ts: now, data });
  return data;
}

function readOpenClawConfig() {
  try {
    if (!existsSync(OPENCLAW_CONFIG_PATH)) return null;
    return JSON.parse(readFileSync(OPENCLAW_CONFIG_PATH, 'utf8'));
  } catch {
    return null;
  }
}

function writeOpenClawConfig(config) {
  const bakPath = `${OPENCLAW_CONFIG_PATH}.bak`;
  const tmpPath = `${OPENCLAW_CONFIG_PATH}.tmp`;
  if (existsSync(OPENCLAW_CONFIG_PATH)) {
    copyFileSync(OPENCLAW_CONFIG_PATH, bakPath);
  }
  writeFileSync(tmpPath, JSON.stringify(config, null, 2), 'utf8');
  renameSync(tmpPath, OPENCLAW_CONFIG_PATH);
}

function getByPath(obj, path) {
  return path.reduce((acc, key) => (acc && typeof acc === 'object') ? acc[key] : undefined, obj);
}

function openFactsDb() {
  return openSqlite(MEMORY_FACTS_DB_PATH, { readonly: true, fileMustExist: true });
}

function openFactsDbWrite() {
  return openSqlite(MEMORY_FACTS_DB_PATH, { readonly: false, fileMustExist: true });
}

function flattenConfigForDrift(input) {
  const out = {};
  const walk = (value, path = '') => {
    if (Array.isArray(value)) {
      if (value.length > 10) {
        out[path] = JSON.stringify(value);
        return;
      }
      if (value.length === 0) {
        out[path] = JSON.stringify([]);
        return;
      }
      value.forEach((entry, i) => walk(entry, path ? `${path}.${i}` : String(i)));
      return;
    }

    if (value && typeof value === 'object') {
      const keys = Object.keys(value);
      if (keys.length === 0) {
        out[path] = JSON.stringify({});
        return;
      }
      keys.forEach((key) => walk(value[key], path ? `${path}.${key}` : key));
      return;
    }

    out[path] = value;
  };

  walk(input, '');
  if (Object.prototype.hasOwnProperty.call(out, '')) {
    delete out[''];
  }
  return out;
}

function readCredentialAllowlist() {
  if (!existsSync(CREDENTIAL_ALLOWLIST_PATH)) {
    writeFileSync(CREDENTIAL_ALLOWLIST_PATH, '[]\n', 'utf8');
    return new Set();
  }

  try {
    const parsed = JSON.parse(readFileSync(CREDENTIAL_ALLOWLIST_PATH, 'utf8'));
    if (!Array.isArray(parsed)) return new Set();
    return new Set(parsed.map((value) => Number.parseInt(value, 10)).filter(Number.isInteger));
  } catch {
    return new Set();
  }
}

function writeCredentialAllowlist(ids) {
  writeFileSync(CREDENTIAL_ALLOWLIST_PATH, `${JSON.stringify(Array.from(ids).sort((a, b) => a - b), null, 2)}\n`, 'utf8');
}

function maskCredentialValue(value) {
  const text = String(value || '');
  if (text.length < 12) return text;
  return `${text.slice(0, 4)}...${text.slice(-4)}`;
}

function detectLikelyCredential(value = '') {
  const text = String(value || '');
  return /\bsk-[A-Za-z0-9]{20,}\b/.test(text)
    || /\bghp_[A-Za-z0-9]{36}\b/.test(text)
    || /(?:^|\s)[A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD)\s*=\s*[A-Za-z0-9_\-+/=]{16,}/i.test(text)
    || /[A-Za-z0-9+/]{32,}={0,2}/.test(text);
}

function getCredentialReviewRows() {
  const allowlist = readCredentialAllowlist();
  const db = openFactsDb();
  try {
    const rows = db.prepare(`
      SELECT id, entity, key, value
      FROM facts
      WHERE
        value GLOB 'sk-[A-Za-z0-9]*'
        OR value GLOB 'ghp_[A-Za-z0-9]*'
        OR lower(COALESCE(key, '')) IN ('password', 'api_key', 'secret', 'token')
      ORDER BY id DESC
      LIMIT 250
    `).all();

    return rows
      .filter((row) => !allowlist.has(Number(row.id)))
      .map((row) => {
        const value = String(row.value || '');
        const skMatch = value.match(/\bsk-[A-Za-z0-9]{20,}\b/);
        const ghMatch = value.match(/\bghp_[A-Za-z0-9]{36}\b/);
        const exactValue = skMatch?.[0] || ghMatch?.[0] || value;
        const likelyReal = detectLikelyCredential(exactValue);
        return {
          id: Number(row.id),
          entity: row.entity || '',
          key: row.key || '',
          masked_value: likelyReal ? maskCredentialValue(exactValue) : value,
          full_value_length: value.length,
          is_likely_real: likelyReal,
        };
      });
  } finally {
    db.close();
  }
}

function safeReadLines(filePath, maxLines = 4000) {
  if (!existsSync(filePath)) return [];
  try {
    const lines = readFileSync(filePath, 'utf8').split('\n').filter(Boolean);
    return lines.slice(Math.max(0, lines.length - maxLines));
  } catch {
    return [];
  }
}

function parseIsoSafe(value) {
  if (!value) return null;
  const t = Date.parse(value);
  return Number.isFinite(t) ? t : null;
}

function statusLevel(ok, warn) {
  if (ok) return 'green';
  if (warn) return 'yellow';
  return 'red';
}

function readJsonlWindow(filePath, cutoffMs, maxLines = 8000) {
  const lines = safeReadLines(filePath, maxLines);
  const rows = [];
  for (const line of lines) {
    try {
      const entry = JSON.parse(line);
      const ts = parseIsoSafe(entry.timestamp || entry.ts || entry.time);
      if (!ts || ts < cutoffMs) continue;
      rows.push(entry);
    } catch {
      // ignore malformed lines
    }
  }
  return rows;
}

function getLastLogTimestampMs(lines) {
  for (let i = lines.length - 1; i >= 0; i--) {
    const match = lines[i].match(/\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}/);
    const parsed = parseIsoSafe(match ? match[0].replace(' ', 'T') : null);
    if (parsed) return parsed;
  }
  return null;
}

function getFileHash(path) {
  if (!existsSync(path)) return null;
  try {
    return createHash('md5').update(readFileSync(path)).digest('hex');
  } catch {
    return null;
  }
}

function getCaptureDriftDetails() {
  const repoExists = existsSync(MEMORY_CAPTURE_REPO_PATH);
  const runtimeExists = existsSync(MEMORY_CAPTURE_RUNTIME_PATH);
  const repoStat = repoExists ? statSync(MEMORY_CAPTURE_REPO_PATH) : null;
  const runtimeStat = runtimeExists ? statSync(MEMORY_CAPTURE_RUNTIME_PATH) : null;
  const repoHash = getFileHash(MEMORY_CAPTURE_REPO_PATH);
  const runtimeHash = getFileHash(MEMORY_CAPTURE_RUNTIME_PATH);
  const drifted = Boolean(repoHash && runtimeHash && repoHash !== runtimeHash);
  return {
    drifted,
    filePairs: [{
      key: 'capture.js',
      repoPath: MEMORY_CAPTURE_REPO_PATH,
      runtimePath: MEMORY_CAPTURE_RUNTIME_PATH,
      repoHash,
      runtimeHash,
      repoSize: repoStat?.size ?? null,
      runtimeSize: runtimeStat?.size ?? null,
      repoModified: repoStat?.mtime?.toISOString?.() || null,
      runtimeModified: runtimeStat?.mtime?.toISOString?.() || null,
    }],
  };
}

function queryCountSafe(db, sql, params = []) {
  try {
    return Number(db.prepare(sql).get(...params)?.count || 0);
  } catch {
    return 0;
  }
}

function parseNumberOrNull(value) {
  if (value == null || value === '') return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function readJsonSafe(filePath, fallback = {}) {
  try {
    if (!existsSync(filePath)) return fallback;
    return JSON.parse(readFileSync(filePath, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJsonAtomic(filePath, payload) {
  const tmpPath = `${filePath}.tmp`;
  writeFileSync(tmpPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  renameSync(tmpPath, filePath);
}

function ageSecondsFromIso(value) {
  const ts = parseIsoSafe(value);
  if (!ts) return null;
  return Math.max(0, Math.floor((Date.now() - ts) / 1000));
}

function stripAnsiAndBoxChars(text = '') {
  const ansi = /\x1b\[[0-9;?]*[ -/]*[@-~]/g;
  const box = /[┌┐└┘├┤┬┴┼│─╮╯╰╭]+/g;
  return String(text || '')
    .split('\n')
    .map((line) => line.replace(ansi, '').replace(box, '').trim())
    .filter((line) => line && !line.startsWith('[plugins]'));
}

function parseDoctorSectionsFromLines(lines = []) {
  const sections = [];
  const sectionPattern = /^\s*◇\s*(.+?)\s*$/;
  let current = null;
  for (const line of lines) {
    const m = line.match(sectionPattern);
    if (m) {
      current = { name: m[1].trim(), findings: [] };
      sections.push(current);
      continue;
    }
    if (line.startsWith('- ')) {
      const finding = line.slice(2).trim();
      if (!finding) continue;
      if (/^(No .+ detected|Run:|Eligible:|Missing requirements:|Blocked by allowlist:|Loaded:|Disabled:|agent:main:cron:)/i.test(finding)) continue;
      if (/^(No .+ warnings detected|Run:|Eligible:|Missing requirements:|Blocked by|Loaded:|Disabled:)/i.test(finding)) continue;
      if (!current) {
        current = { name: 'General', findings: [] };
        sections.push(current);
      }
      current.findings.push(finding);
    }
  }
  return sections;
}

function mergeDoctorSuppressions(statusPayload, suppressedMap) {
  const rawSections = Array.isArray(statusPayload?.sections) ? statusPayload.sections : [];
  const suppressed = (suppressedMap && typeof suppressedMap === 'object') ? suppressedMap : {};
  const sections = rawSections.map((section) => {
    const findings = Array.isArray(section?.findings) ? section.findings : [];
    return {
      name: section?.name || 'General',
      findings: findings.map((text) => ({
        text,
        suppressed: !!suppressed[text],
        suppression: suppressed[text] || null,
      })),
    };
  });
  return {
    generated_at: statusPayload?.generated_at || null,
    exit_code: Number.isFinite(Number(statusPayload?.exit_code)) ? Number(statusPayload.exit_code) : null,
    sections,
  };
}

function runOpenclawDoctor(commandArgs, timeoutMs) {
  const run = spawnSync(commandArgs[0], commandArgs.slice(1), {
    encoding: 'utf8',
    timeout: timeoutMs,
    shell: false,
  });
  const lines = stripAnsiAndBoxChars(`${run.stdout || ''}\n${run.stderr || ''}`);
  const sections = parseDoctorSectionsFromLines(lines);
  return {
    generated_at: new Date().toISOString(),
    exit_code: Number.isFinite(run.status) ? run.status : 1,
    sections,
    output_lines: lines,
    timed_out: run.error?.code === 'ETIMEDOUT',
  };
}

// ── Security constants ──
const MAX_BODY_SIZE = 1024 * 1024; // 1MB max POST body
const RATE_LIMIT_WINDOW = 60000;   // 1 minute window
const RATE_LIMIT_MAX = 5;          // 5 attempts per window
const loginAttempts = new Map();   // ip → [timestamps]
const PUBLIC_API_PATHS = new Set(['/api/health', '/api/ops/services/status']);

// ── Auth ─────────────────────────────────────────────
// Password stored in auth.json. On first run, generates a random one.
const AUTH_PATH = join(DIR, 'auth.json');
let AUTH = AUTH_DISABLED ? { sessionTtlHours: 24 } : loadAuth();

function loadAuth() {
  if (existsSync(AUTH_PATH)) {
    try { return JSON.parse(readFileSync(AUTH_PATH, 'utf8')); } catch {}
  }
  // Generate default password on first run — store hash, show plaintext once
  const pw = randomBytes(12).toString('base64url');
  const hash = createHash('sha256').update(pw).digest('hex');
  const auth = { passwordHash: hash, sessionTtlHours: 24 };
  writeFileSync(AUTH_PATH, JSON.stringify(auth, null, 2), { encoding: 'utf8', mode: 0o600 });
  console.log(`🔐 Generated password (shown once, not stored): ${pw}`);
  console.log(`   Hash stored in: ${AUTH_PATH}`);
  return auth;
}

// Session tokens (in-memory, survive until server restart)
const sessions = new Map();

// (rate limiting constants defined above)

function hashPassword(pw) {
  return createHash('sha256').update(pw).digest('hex');
}

function createSession() {
  const token = randomBytes(32).toString('hex');
  sessions.set(token, { created: Date.now() });
  return token;
}

function isValidSession(token) {
  const sess = sessions.get(token);
  if (!sess) return false;
  const maxAge = (AUTH.sessionTtlHours || 24) * 3600000;
  if (Date.now() - sess.created > maxAge) { sessions.delete(token); return false; }
  return true;
}

function getSessionToken(req) {
  // Check cookie first
  const cookies = req.headers.cookie || '';
  const match = cookies.match(/fmc_session=([a-f0-9]+)/);
  if (match) return match[1];
  // Check Authorization header (for API calls)
  const authHeader = req.headers.authorization || '';
  if (authHeader.startsWith('Bearer ')) return authHeader.slice(7);
  return null;
}

function requireAuth(req, res) {
  if (AUTH_DISABLED) return true;

  const token = getSessionToken(req);
  if (token && isValidSession(token)) return true;

  const url = new URL(req.url, `http://${req.headers.host}`);

  // Keep non-privileged pages/APIs public
  if (url.pathname === '/login' || url.pathname === '/api/login') return true;
  if (PUBLIC_API_PATHS.has(url.pathname)) return true;

  // For API calls, return 401
  if (url.pathname.startsWith('/api/')) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return false;
  }

  // For pages, redirect to login
  res.writeHead(302, { Location: '/login' });
  res.end();
  return false;
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > MAX_BODY_SIZE) {
        reject(new Error('Payload too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', (err) => reject(err));
  });
}

function parseEnvFile(filePath) {
  if (!existsSync(filePath)) return {};
  const env = {};
  for (const rawLine of readFileSync(filePath, 'utf8').split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const cleaned = line.startsWith('export ') ? line.slice(7).trim() : line;
    const eqIndex = cleaned.indexOf('=');
    if (eqIndex <= 0) continue;
    const key = cleaned.slice(0, eqIndex).trim();
    let value = cleaned.slice(eqIndex + 1).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    env[key] = value;
  }
  return env;
}

function getMergedEnvMap() {
  return {
    ...parseEnvFile(SECONDARY_ENV_PATH),
    ...parseEnvFile(PRIMARY_ENV_PATH),
    ...process.env,
  };
}


function getProxyCredentials() {
  const env = getMergedEnvMap();
  const username = String(env.PROXY_USERNAME || '').trim();
  const password = String(env.PROXY_PASSWORD || '').trim();
  if (!username || !password) {
    return { available: false, reason: 'proxy credentials not configured' };
  }
  return { available: true, username, password };
}

function bytesToGb(bytes) {
  return Number(bytes || 0) / (1024 * 1024 * 1024);
}

function computeProxyStats(raw) {
  const totalBytes = Number(raw?.total_traffic || PROXY_PLAN_TOTAL_BYTES);
  const usedBytes = Number(raw?.traffic_used || 0);
  const leftBytes = Number(raw?.traffic_left ?? Math.max(totalBytes - usedBytes, 0));
  const totalGb = bytesToGb(totalBytes);
  const usedGb = bytesToGb(usedBytes);
  const remainingGb = bytesToGb(leftBytes);
  const usedPct = totalBytes > 0 ? (usedBytes / totalBytes) * 100 : 0;
  let status = 'ok';
  if (remainingGb < 0.25) status = 'critical';
  else if (remainingGb < 1.0) status = 'warn';
  return {
    total_gb: Number(totalGb.toFixed(6)),
    used_gb: Number(usedGb.toFixed(6)),
    remaining_gb: Number(remainingGb.toFixed(6)),
    used_pct: Number(usedPct.toFixed(2)),
    status,
  };
}

async function fetchProxyApi(pathname, credentials, queryParams = null) {
  const endpoint = new URL(pathname, PROXY_API_BASE_URL);
  if (queryParams) {
    for (const [k, v] of Object.entries(queryParams)) {
      if (v !== undefined && v !== null) endpoint.searchParams.set(k, String(v));
    }
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), PROXY_FETCH_TIMEOUT_MS);
  try {
    const auth = Buffer.from(`${credentials.username}:${credentials.password}`).toString('base64');
    const response = await fetch(endpoint, {
      method: 'GET',
      headers: {
        Authorization: `Basic ${auth}`,
        Accept: 'application/json',
      },
      signal: controller.signal,
    });
    if (!response.ok) {
      const body = await response.text();
      throw new Error(`HTTP ${response.status}: ${body.slice(0, 200)}`);
    }
    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

async function getProxyCached(cacheEntry, ttlMs, fetchFn) {
  const now = Date.now();
  if (cacheEntry.data && (now - cacheEntry.timestamp) < ttlMs) {
    return { payload: cacheEntry.data, stale: false };
  }
  try {
    const fresh = await fetchFn();
    cacheEntry.timestamp = now;
    cacheEntry.data = fresh;
    return { payload: fresh, stale: false };
  } catch (error) {
    if (cacheEntry.data) {
      return { payload: cacheEntry.data, stale: true };
    }
    throw error;
  }
}

function formatDateKey(date) {
  return date.toISOString().slice(0, 10);
}

function extractLogMessage(entry) {
  if (!entry || typeof entry !== 'object') return '';
  if (typeof entry['1'] === 'string') return entry['1'];
  if (typeof entry.message === 'string') return entry.message;
  if (typeof entry.msg === 'string') return entry.msg;
  return '';
}

function extractLogTimestamp(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const keys = ['timestamp', 'time', 'ts', '@timestamp', '0'];
  for (const key of keys) {
    const value = entry[key];
    if (!value) continue;
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
  }
  return null;
}

async function computeTopProxyHosts(days) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const logPaths = [];
  for (let i = 0; i < days; i += 1) {
    const day = new Date(today.getTime() - (i * 86400000));
    const filePath = `/tmp/openclaw/openclaw-${formatDateKey(day)}.log`;
    if (existsSync(filePath)) logPaths.push(filePath);
  }

  if (!logPaths.length) {
    return { available: false };
  }

  const hostStats = new Map();
  const urlRegex = /https?:\/\/[^\s"']+/gi;
  const excludedHosts = new Set(['localhost', '127.0.0.1', 'api.ipify.org']);

  for (const logPath of logPaths) {
    const lineReader = createInterface({
      input: createReadStream(logPath, { encoding: 'utf8' }),
      crlfDelay: Infinity,
    });

    for await (const line of lineReader) {
      if (!line || !line.includes('camofox')) continue;

      const extractedUrls = line.match(urlRegex) || [];
      if (!extractedUrls.length) continue;

      let timestampIso = null;
      let message = '';
      try {
        const parsed = JSON.parse(line);
        message = extractLogMessage(parsed);
        timestampIso = extractLogTimestamp(parsed);
      } catch {
        // Skip malformed JSON parsing and continue using raw-line fallback.
      }

      const textToCheck = message || line;
      if (!textToCheck.includes('camofox')) continue;

      for (const rawUrl of extractedUrls) {
        try {
          const parsedUrl = new URL(rawUrl);
          const host = parsedUrl.hostname.toLowerCase();
          if (!host || excludedHosts.has(host)) continue;
          const previous = hostStats.get(host) || { requests: 0, last_seen: null };
          previous.requests += 1;
          if (timestampIso && (!previous.last_seen || timestampIso > previous.last_seen)) {
            previous.last_seen = timestampIso;
          }
          hostStats.set(host, previous);
        } catch {
          // Ignore invalid URL fragments.
        }
      }
    }
  }

  const allHosts = [...hostStats.entries()]
    .map(([host, meta]) => ({ host, requests: meta.requests, last_seen: meta.last_seen }))
    .sort((a, b) => b.requests - a.requests);

  const hosts = allHosts.slice(0, 20);

  const totalRequests = allHosts.reduce((sum, item) => sum + item.requests, 0);
  return {
    available: true,
    days,
    total_requests: totalRequests,
    hosts,
  };
}

function loadApisConfig() {
  const raw = readFileSync(APIS_CONFIG_PATH, 'utf8');
  const parsed = JSON.parse(raw);
  if (!parsed || !Array.isArray(parsed.services)) {
    throw new Error('Invalid apis-config.json (missing services[])');
  }
  return parsed;
}

function loadHealthResults() {
  if (!existsSync(HEALTH_RESULTS_PATH)) {
    return { checked_at: null, results: {} };
  }
  const parsed = JSON.parse(readFileSync(HEALTH_RESULTS_PATH, 'utf8'));
  return {
    checked_at: parsed.checked_at || null,
    results: parsed.results && typeof parsed.results === 'object' ? parsed.results : {},
  };
}

function loadCliUsage() {
  if (!existsSync(CLI_USAGE_PATH)) {
    return {
      checked_at: null,
      providers: {
        codex: {
          name: 'Codex CLI',
          session_pct: null,
          session_reset: null,
          weekly_pct: null,
          weekly_reset: null,
          credits: null,
          status: 'not_connected',
          error: 'Usage data not available yet',
        },
        claude: {
          name: 'Claude Code',
          session_pct: null,
          session_reset: null,
          weekly_pct: null,
          weekly_reset: null,
          credits: null,
          status: 'not_connected',
          error: 'Usage data not available yet',
        },
      },
    };
  }

  const parsed = JSON.parse(readFileSync(CLI_USAGE_PATH, 'utf8'));
  return {
    checked_at: parsed.checked_at || null,
    providers: parsed.providers && typeof parsed.providers === 'object' ? parsed.providers : {},
  };
}

function calculateApiKeyStatus(service, envMap) {
  const apiKey = service.api_key;
  if (!apiKey) {
    return {
      configured: false,
      env_var: null,
      last_rotated: null,
      age_days: null,
      rotation_warning: false,
      rotation_warning_days: null,
    };
  }

  const configured = Boolean(envMap[apiKey.env_var] || process.env[apiKey.env_var]);
  let ageDays = null;
  if (typeof apiKey.last_rotated === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(apiKey.last_rotated)) {
    const then = Date.parse(`${apiKey.last_rotated}T00:00:00Z`);
    if (!Number.isNaN(then)) {
      ageDays = Math.floor((Date.now() - then) / 86400000);
    }
  }
  const warningDays = Number.isFinite(apiKey.rotation_warning_days) ? apiKey.rotation_warning_days : null;

  return {
    configured,
    env_var: apiKey.env_var || null,
    last_rotated: apiKey.last_rotated ?? null,
    age_days: ageDays,
    rotation_warning: ageDays != null && warningDays != null ? ageDays > warningDays : false,
    rotation_warning_days: warningDays,
  };
}

function serviceStatusPriority(status) {
  if (status === 'down') return 0;
  if (status === 'error') return 1;
  if (status === 'not_checked') return 2;
  if (status === 'healthy') return 3;
  return 4;
}

function mergeHealthData() {
  const config = loadApisConfig();
  const health = loadHealthResults();
  const envMap = getMergedEnvMap();
  const services = config.services.map((svc) => {
    const result = health.results[svc.id] || null;
    const status = result?.status || 'not_checked';
    return {
      id: svc.id,
      name: svc.name,
      provider: svc.provider,
      description: svc.description,
      capabilities: Array.isArray(svc.capabilities) ? svc.capabilities : [],
      status,
      response_ms: Number.isFinite(result?.response_ms) ? result.response_ms : null,
      http_status: Number.isFinite(result?.http_status) ? result.http_status : null,
      checked_at: result?.checked_at || null,
      error: result?.error ?? null,
      health_check: svc.health_check || null,
      api_key_status: calculateApiKeyStatus(svc, envMap),
    };
  });

  services.sort((a, b) => {
    const statusCmp = serviceStatusPriority(a.status) - serviceStatusPriority(b.status);
    if (statusCmp !== 0) return statusCmp;
    return a.name.localeCompare(b.name);
  });

  const total = services.length;
  const healthy = services.filter((s) => s.status === 'healthy').length;
  const down = services.filter((s) => s.status === 'down' || s.status === 'error').length;
  const notChecked = services.filter((s) => s.status === 'not_checked').length;
  const totalCapabilities = services.reduce((sum, svc) => sum + svc.capabilities.length, 0);

  let overallStatus = 'NOT CHECKED';
  if (!existsSync(HEALTH_RESULTS_PATH)) {
    overallStatus = 'NOT CHECKED';
  } else if (down > 0) {
    overallStatus = 'DEGRADED';
  } else if (total > 0 && healthy === total) {
    overallStatus = 'ALL OK';
  } else {
    overallStatus = 'NOT CHECKED';
  }

  return {
    checked_at: health.checked_at,
    summary: {
      total,
      healthy,
      down,
      not_checked: notChecked,
      total_capabilities: totalCapabilities,
      overall_status: overallStatus,
    },
    services,
  };
}


const OPS_SERVICES = ['openclaw', 'clawd-control', 'clawmetry', 'cloudflared', 'tailscaled'];

function truncateOutput(value, max = 2000) {
  if (value == null) return '';
  const text = String(value);
  return text.length > max ? text.slice(0, max) : text;
}

function parseSystemctlShow(raw) {
  const out = {};
  for (const line of String(raw || '').split('\n')) {
    const idx = line.indexOf('=');
    if (idx <= 0) continue;
    out[line.slice(0, idx)] = line.slice(idx + 1);
  }
  return out;
}

function parseMemoryMb(value) {
  const bytes = Number.parseInt(value, 10);
  if (!Number.isFinite(bytes) || bytes <= 0) return null;
  return Math.round((bytes / (1024 * 1024)) * 10) / 10;
}

function formatCronTime(hourRaw, minuteRaw) {
  const hour = Number.parseInt(hourRaw, 10);
  const minute = Number.parseInt(minuteRaw, 10);
  if (!Number.isInteger(hour) || !Number.isInteger(minute) || hour < 0 || hour > 23 || minute < 0 || minute > 59) return null;
  const suffix = hour >= 12 ? 'PM' : 'AM';
  const hour12 = hour % 12 || 12;
  return `${hour12}:${String(minute).padStart(2, '0')} ${suffix}`;
}

function describeCron(schedule) {
  if (!schedule) return '';
  if (schedule === '@reboot') return 'On reboot';
  if (schedule === '@hourly') return 'Every hour';
  if (schedule === '@daily' || schedule === '@midnight') return 'Daily at midnight';
  if (schedule === '@weekly') return 'Weekly (Sunday midnight)';
  if (schedule === '@monthly') return 'Monthly (1st at midnight)';

  const everyNMinutes = schedule.match(/^\*\/(\d+) \* \* \* \*$/);
  if (everyNMinutes) return `Every ${Number.parseInt(everyNMinutes[1], 10)} minutes`;
  const everyNHours = schedule.match(/^(\d+) \*\/(\d+) \* \* \*$/);
  if (everyNHours) return `Every ${Number.parseInt(everyNHours[2], 10)} hours at :${String(Number.parseInt(everyNHours[1], 10)).padStart(2, '0')}`;
  if (schedule === '* * * * *') return 'Every minute';

  const parts = schedule.trim().split(/\s+/);
  if (parts.length !== 5) return schedule;

  const [minute, hour, dayOfMonth, month, dayOfWeek] = parts;
  if (/^\d+$/.test(minute) && hour === '*' && dayOfMonth === '*' && month === '*' && dayOfWeek === '*') {
    return `Once per hour at :${String(Number.parseInt(minute, 10)).padStart(2, '0')}`;
  }

  if (/^\d+$/.test(minute) && /^\d+$/.test(hour) && dayOfMonth === '*' && month === '*') {
    const time = formatCronTime(hour, minute);
    if (!time) return schedule;
    if (dayOfWeek === '0' || dayOfWeek === '7') return `Sundays at ${time}`;
    if (dayOfWeek === '1') return `Mondays at ${time}`;
    if (dayOfWeek === '1-5') return `Weekdays at ${time}`;
    if (dayOfWeek === '*') return `Daily at ${time}`;
  }

  if (/^\d+$/.test(minute) && /^\d+$/.test(hour) && /^\d+$/.test(dayOfMonth) && month === '*' && dayOfWeek === '*') {
    const time = formatCronTime(hour, minute);
    if (!time) return schedule;
    return `Monthly on day ${Number.parseInt(dayOfMonth, 10)} at ${time}`;
  }

  return schedule;
}

function parseCronLine(line, { source, defaultUser, fileName, expectsUserColumn, purpose }) {
  const parts = line.split(/\s+/);
  let schedule = '';
  let user = defaultUser;
  let command = '';

  if (line.startsWith('@')) {
    if (expectsUserColumn) {
      if (parts.length < 3) return null;
      schedule = parts[0];
      user = parts[1];
      command = parts.slice(2).join(' ');
    } else {
      if (parts.length < 2) return null;
      schedule = parts[0];
      command = parts.slice(1).join(' ');
    }
  } else if (expectsUserColumn) {
    if (parts.length < 7) return null;
    schedule = parts.slice(0, 5).join(' ');
    user = parts[5];
    command = parts.slice(6).join(' ');
  } else {
    if (parts.length < 6) return null;
    schedule = parts.slice(0, 5).join(' ');
    command = parts.slice(5).join(' ');
  }

  const suffix = command.split('/').pop() || command.split(' ')[0] || 'job';
  const rawName = fileName ? `${fileName.replace(/\.[^.]+$/, '')}:${suffix}` : `user:${suffix}`;
  const name = purpose || rawName;
  return {
    name,
    schedule,
    description: describeCron(schedule),
    purpose: purpose || null,
    command,
    source,
    user,
    last_run: null,
  };
}

const CRON_TRIGGER_ALLOWLIST = new Map([
  [
    '/usr/local/bin/check-api-health.sh > /dev/null 2>&1',
    { command: '/usr/local/bin/check-api-health.sh', args: [] },
  ],
  [
    '. /home/openclaw/.profile && python3 /home/openclaw/.openclaw/scripts/graph-ingest-daily.py --days 1 >> /home/openclaw/.openclaw/memory/ingest.log 2>&1',
    { command: 'python3', args: ['/home/openclaw/.openclaw/scripts/graph-ingest-daily.py', '--days', '1'] },
  ],
]);

function parseCronEntries() {
  const jobs = [];
  const cronDir = '/etc/cron.d';
  try {
    const files = readdirSync(cronDir, { withFileTypes: true }).filter((d) => d.isFile());
    for (const file of files) {
      const fullPath = join(cronDir, file.name);
      const lines = readFileSync(fullPath, 'utf8').split('\n');
      let pendingPurpose = null;
      for (const raw of lines) {
        const line = raw.trim();
        if (!line || /^[A-Za-z_][A-Za-z0-9_]*=/.test(line)) continue;
        if (line.startsWith('#')) {
          const descMatch = line.match(/^#\s*Description:\s*(.+)/i);
          if (descMatch) pendingPurpose = descMatch[1].trim();
          continue;
        }
        const job = parseCronLine(line, { source: 'system', fileName: file.name, expectsUserColumn: true, purpose: pendingPurpose });
        if (job) jobs.push(job);
        pendingPurpose = null;
      }
    }
  } catch {}
  try {
    const lines = readFileSync('/etc/crontab', 'utf8').split('\n');
    let pendingPurpose = null;
    for (const raw of lines) {
      const line = raw.trim();
      if (!line || /^[A-Za-z_][A-Za-z0-9_]*=/.test(line)) continue;
      if (line.startsWith('#')) {
        const descMatch = line.match(/^#\s*Description:\s*(.+)/i);
        if (descMatch) pendingPurpose = descMatch[1].trim();
        continue;
      }
      const job = parseCronLine(line, { source: 'system', fileName: 'crontab', expectsUserColumn: true, purpose: pendingPurpose });
      if (job) jobs.push(job);
      pendingPurpose = null;
    }
  } catch {}
  try {
    const result = spawnSync('crontab', ['-u', 'openclaw', '-l'], { encoding: 'utf8', timeout: 10000 });
    if (result.status === 0) {
      const lines = result.stdout.split('\n');
      let pendingPurpose = null;
      for (const raw of lines) {
        const line = raw.trim();
        if (!line) continue;
        if (line.startsWith('#')) {
          const descMatch = line.match(/^#\s*Description:\s*(.+)/i);
          if (descMatch) pendingPurpose = descMatch[1].trim();
          continue;
        }
        const job = parseCronLine(line, { source: 'user', defaultUser: 'openclaw', expectsUserColumn: false, purpose: pendingPurpose });
        if (job) jobs.push(job);
        pendingPurpose = null;
      }
    }
  } catch {}
  try {
    const result = spawnSync('crontab', ['-u', 'root', '-l'], { encoding: 'utf8', timeout: 10000 });
    if (result.status === 0) {
      const lines = result.stdout.split('\n');
      let pendingPurpose = null;
      for (const raw of lines) {
        const line = raw.trim();
        if (!line) continue;
        if (line.startsWith('#')) {
          const descMatch = line.match(/^#\s*Description:\s*(.+)/i);
          if (descMatch) pendingPurpose = descMatch[1].trim();
          continue;
        }
        const job = parseCronLine(line, { source: 'system', defaultUser: 'root', expectsUserColumn: false, purpose: pendingPurpose });
        if (job) jobs.push(job);
        pendingPurpose = null;
      }
    }
  } catch {}
  const systemPackageFiles = new Set(["e2scrub_all", "sysstat", "crontab"]);
  return jobs.filter(j => !systemPackageFiles.has((j.name || "").split(":")[0]));
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.json': 'application/json',
  '.js': 'application/javascript',
  '.mjs': 'application/javascript',
  '.css': 'text/css',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

// ── Collector ───────────────────────────────────────

// Auto-discover agents if agents.json doesn't exist
const agentsJsonPath = join(DIR, 'agents.json');
if (!existsSync(agentsJsonPath)) {
  console.log('🔍 agents.json not found, auto-discovering...');
  const discovered = discoverAgents();
  writeFileSync(agentsJsonPath, JSON.stringify(discovered, null, 2), 'utf8');
  console.log(`✅ Created agents.json with ${discovered.agents.length} agent(s)`);
}

const collector = new AgentCollector(agentsJsonPath);
const chatGatewayClient = new ChatGatewayClient({ configPath: agentsJsonPath });
chatGatewayClient.start().catch((error) => {
  console.warn('⚠️ Chat gateway init failed:', error.message);
});
const sseClients = new Set();

collector.on('update', ({ id, state, removed }) => {
  broadcast({ type: 'agent', id, data: state, removed: !!removed });
});

collector.on('hostMetrics', (metrics) => {
  broadcast({ type: 'host', data: metrics });
});

function broadcast(event) {
  const msg = `data: ${JSON.stringify(event)}\n\n`;
  for (const res of sseClients) {
    try { res.write(msg); } catch { sseClients.delete(res); }
  }
}

collector.start();
console.log('📡 Collector started');

// ── Agent Actions ──
async function handleAgentAction(agentId, action) {
  try {
    switch (action) {
      case 'heartbeat-enable': {
        // Runtime toggle
        execFileSync('clawdbot', ['system', 'heartbeat', 'enable'], { encoding: 'utf8', stdio: 'pipe' });
        // Also persist via gateway config.patch
        try {
          execFileSync('clawdbot', ['gateway', 'config.patch', '--json', JSON.stringify({
            agents: { defaults: { heartbeat: { every: '55m' } } }
          })], { encoding: 'utf8', stdio: 'pipe' });
        } catch (_) { /* best effort */ }
        return { ok: true, message: `Heartbeat enabled for ${agentId}` };
      }
      case 'heartbeat-disable': {
        // Runtime toggle
        execFileSync('clawdbot', ['system', 'heartbeat', 'disable'], { encoding: 'utf8', stdio: 'pipe' });
        // Also persist via gateway config.patch
        try {
          execFileSync('clawdbot', ['gateway', 'config.patch', '--json', JSON.stringify({
            agents: { defaults: { heartbeat: { every: 'off' } } }
          })], { encoding: 'utf8', stdio: 'pipe' });
        } catch (_) { /* best effort */ }
        return { ok: true, message: `Heartbeat disabled for ${agentId}` };
      }
      case 'heartbeat-trigger': {
        execFileSync('clawdbot', ['system', 'event', '--mode', 'now', '--text', 'Manual heartbeat trigger from Clawd Control'], { encoding: 'utf8', stdio: 'pipe' });
        return { ok: true, message: `Heartbeat triggered for ${agentId}` };
      }
      case 'session-new': {
        // Clear only the main session to start fresh (keeps other sessions)
        const mainAgentId = agentId === 'gandalf' ? 'main' : agentId;
        const sessPath = join(process.env.HOME, '.openclaw', 'agents', mainAgentId, 'sessions', 'sessions.json');
        if (existsSync(sessPath)) {
          const sessions = JSON.parse(readFileSync(sessPath, 'utf8'));
          const mainKey = `agent:${mainAgentId}:main`;
          if (sessions[mainKey]) {
            // Backup the session transcript before clearing
            const sid = sessions[mainKey].sessionId;
            if (sid) {
              const transcript = join(process.env.HOME, '.openclaw', 'agents', mainAgentId, 'sessions', `${sid}.jsonl`);
              if (existsSync(transcript)) {
                const bak = transcript.replace('.jsonl', `.archived.${Date.now()}.jsonl`);
                copyFileSync(transcript, bak);
              }
            }
            delete sessions[mainKey];
            writeFileSync(sessPath, JSON.stringify(sessions, null, 2), 'utf8');
          }
        }
        return { ok: true, message: `New session started for ${agentId}. Old conversation archived.` };
      }
      case 'session-reset': {
        // Delete ALL sessions (nuclear option)
        const agentIdForPath = agentId === 'gandalf' ? 'main' : agentId;
        const sessionPath = join(process.env.HOME, '.openclaw', 'agents', agentIdForPath, 'sessions', 'sessions.json');
        if (existsSync(sessionPath)) {
          const backup = sessionPath + '.bak.' + Date.now();
          copyFileSync(sessionPath, backup);
          writeFileSync(sessionPath, '{}', 'utf8');
        }
        return { ok: true, message: `All sessions reset for ${agentId}. Backup created.` };
      }
      case 'clear-cooldowns': {
        // Clear API rate limit cooldowns for this agent
        const agentIdForCooldown = agentId === 'gandalf' ? 'main' : agentId;
        const authProfilePath = join(process.env.HOME, '.openclaw', 'agents', agentIdForCooldown, 'agent', 'auth-profiles.json');
        if (existsSync(authProfilePath)) {
          const profiles = JSON.parse(readFileSync(authProfilePath, 'utf8'));
          let cleared = 0;
          if (profiles.usageStats) {
            for (const [k, v] of Object.entries(profiles.usageStats)) {
              if (v.cooldownUntil || v.lastFailureAt) {
                delete v.cooldownUntil;
                delete v.lastFailureAt;
                v.errorCount = 0;
                v.failureCounts = {};
                cleared++;
              }
            }
          }
          writeFileSync(authProfilePath, JSON.stringify(profiles, null, 2), 'utf8');
          return { ok: true, message: `Cleared ${cleared} cooldown(s) for ${agentId}. Restart gateway to apply.` };
        }
        return { ok: false, error: `No auth-profiles.json found for ${agentId}` };
      }
      case 'clear-all-cooldowns': {
        // Clear cooldowns for ALL agents
        const agentsDir = join(process.env.HOME, '.openclaw', 'agents');
        let totalCleared = 0;
        const agentNames = [];
        if (existsSync(agentsDir)) {
          for (const dir of readdirSync(agentsDir)) {
            const ap = join(agentsDir, dir, 'agent', 'auth-profiles.json');
            if (existsSync(ap)) {
              const profiles = JSON.parse(readFileSync(ap, 'utf8'));
              if (profiles.usageStats) {
                for (const [k, v] of Object.entries(profiles.usageStats)) {
                  if (v.cooldownUntil || v.lastFailureAt) {
                    delete v.cooldownUntil;
                    delete v.lastFailureAt;
                    v.errorCount = 0;
                    v.failureCounts = {};
                    totalCleared++;
                    if (!agentNames.includes(dir)) agentNames.push(dir);
                  }
                }
                writeFileSync(ap, JSON.stringify(profiles, null, 2), 'utf8');
              }
            }
          }
        }
        return { ok: true, message: totalCleared > 0 ? `Cleared ${totalCleared} cooldown(s) for: ${agentNames.join(', ')}. Restart gateway to apply.` : 'No cooldowns found.' };
      }
      default:
        return { ok: false, error: `Unknown action: ${action}` };
    }
  } catch (e) {
    console.error(`[API] agent action error:`, e.message);
    return { ok: false, error: 'Action failed' };
  }
}

// ── Security Audit (Frodo's checks) ─────────────────
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const openSqlite = require('better-sqlite3');

function runSecurityAudit() {
  const secDir = join(DIR, 'security-lib', 'checks');
  const os = require('os');
  const config = {
    workspace: join(os.homedir(), 'clawd'),
    secretsDir: join(os.homedir(), 'clawd', 'secrets'),
    logsDir: join(os.homedir(), 'clawd', 'logs'),
    auditLog: join(os.homedir(), 'clawd', 'logs', 'dashboard-access.log'),
    maxLogSizeMB: 5,
  };

  const { checkSecrets } = require(join(secDir, 'secrets.js'));
  const { checkExposedCredentials } = require(join(secDir, 'credentials.js'));
  const { checkNetwork } = require(join(secDir, 'network.js'));
  const { checkSystem } = require(join(secDir, 'system.js'));
  const { checkGatewayConfig } = require(join(secDir, 'gateway.js'));
  const { checkAccounts } = require(join(secDir, 'accounts.js'));

  const dummyTokenInfo = () => ({ expired: false, remainingHours: 24, ageHours: 0, maxAgeDays: 7 });

  return {
    timestamp: new Date().toISOString(),
    sections: [
      { title: '🔐 Secrets Management', checks: safeRun(() => checkSecrets(config)) },
      { title: '🔍 Credential Exposure', checks: safeRun(() => checkExposedCredentials(config)) },
      { title: '🌐 Network & Ports', checks: safeRun(() => checkNetwork(config, dummyTokenInfo)) },
      { title: '🖥️ System Security', checks: safeRun(() => checkSystem()) },
      { title: '⚙️ Gateway Config', checks: safeRun(() => checkGatewayConfig()) },
      { title: '📋 Account Inventory', checks: safeRun(() => checkAccounts(config)) },
    ],
  };
}

function safeRun(fn) {
  try { return fn(); }
  catch (e) { return [{ name: 'Check failed', status: 'fail', detail: e.message }]; }
}

// ── Skills Counter (lightweight, for snapshot) ─────────
function getSkillsCount(agentId) {
  const agentConfig = collector.config?.agents?.find(a => a.id === agentId);
  if (!agentConfig) return 0;
  
  const ws = agentConfig.workspace;
  const homeDir = process.env.HOME || '/Users/openclaw';
  
  const countSkillsDir = (dir) => {
    if (!existsSync(dir)) return 0;
    try {
      return readdirSync(dir).filter(f => {
        try { return statSync(join(dir, f)).isDirectory(); } catch { return false; }
      }).length;
    } catch { return 0; }
  };
  
  const localCount = countSkillsDir(join(ws, 'skills'));
  const globalCount = countSkillsDir(join(homeDir, '.openclaw', 'skills'));
  
  // Return unique count (some skills might be in both)
  const localSkills = new Set();
  const globalSkills = new Set();
  
  try {
    const localDir = join(ws, 'skills');
    if (existsSync(localDir)) {
      readdirSync(localDir).forEach(f => {
        try { if (statSync(join(localDir, f)).isDirectory()) localSkills.add(f); } catch {}
      });
    }
  } catch {}
  
  try {
    const globalDir = join(homeDir, '.openclaw', 'skills');
    if (existsSync(globalDir)) {
      readdirSync(globalDir).forEach(f => {
        try { if (statSync(join(globalDir, f)).isDirectory()) globalSkills.add(f); } catch {}
      });
    }
  } catch {}
  
  // Combine both sets for unique count
  const allSkills = new Set([...localSkills, ...globalSkills]);
  return allSkills.size;
}

// ── Agent Detail Reader ─────────────────────────────
function getAgentDetail(agentId) {
  const agentConfig = collector.config?.agents?.find(a => a.id === agentId);
  if (!agentConfig) return null;

  const ws = agentConfig.workspace;
  const safeRead = (file, maxBytes = 8192) => {
    const p = join(ws, file);
    if (!existsSync(p)) return null;
    try {
      const content = readFileSync(p, 'utf8');
      return content.length > maxBytes ? content.substring(0, maxBytes) + '\n\n...(truncated)' : content;
    } catch { return null; }
  };

  const listDir = (dir) => {
    const p = join(ws, dir);
    if (!existsSync(p)) return [];
    try {
      const { readdirSync, statSync } = require('fs');
      return readdirSync(p).filter(f => !f.startsWith('.')).map(f => {
        const fp = join(p, f);
        const st = statSync(fp);
        return { name: f, size: st.size, modified: st.mtime.toISOString(), isDir: st.isDirectory() };
      });
    } catch { return []; }
  };

  // Read workspace files
  const soul = safeRead('SOUL.md');
  const identity = safeRead('IDENTITY.md');
  const memory = safeRead('MEMORY.md');
  const tasks = safeRead('TASKS.md');
  const tools = safeRead('TOOLS.md');
  const heartbeat = safeRead('HEARTBEAT.md');
  const agents = safeRead('AGENTS.md');
  const user = safeRead('USER.md');
  const activeWork = safeRead('ACTIVE_WORK.md');
  const bootstrap = safeRead('BOOTSTRAP.md');

  // List skills (local + global user + global system)
  const readSkillsDir = (dir, source) => {
    if (!existsSync(dir)) return [];
    try {
      return readdirSync(dir).filter(f => {
        try { return statSync(join(dir, f)).isDirectory(); } catch { return false; }
      }).map(name => {
        const skillMd = join(dir, name, 'SKILL.md');
        let description = null;
        let content = null;
        let scripts = [];
        if (existsSync(skillMd)) {
          const raw = readFileSync(skillMd, 'utf8');
          content = raw.length > 8192 ? raw.slice(0, 8192) + '\n...(truncated)' : raw;
          const descMatch = raw.match(/description:\s*["']?(.+?)["']?\s*$/m);
          if (descMatch) description = descMatch[1].trim().replace(/^["']|["']$/g, '');
        }
        const scriptsDir = join(dir, name, 'scripts');
        if (existsSync(scriptsDir)) {
          try { scripts = readdirSync(scriptsDir).filter(f => !f.startsWith('.')); } catch {}
        }
        return { name, description, source, content, scripts };
      });
    } catch { return []; }
  };

  const homeDir = process.env.HOME || '/Users/openclaw';
  const localSkills = readSkillsDir(join(ws, 'skills'), 'local');
  const globalUserSkills = readSkillsDir(join(homeDir, '.openclaw', 'skills'), 'global');

  // Only show active skills: local (agent workspace) + global user-installed
  // System skills are the available catalog — not shown unless installed
  const skillMap = new Map();
  for (const s of globalUserSkills) skillMap.set(s.name, s);
  for (const s of localSkills) skillMap.set(s.name, s);
  const skills = [...skillMap.values()].sort((a, b) => a.name.localeCompare(b.name));

  // List credentials (names + sizes only, NEVER contents)
  let credentials = [];
  const credsDir = join(ws, '.credentials');
  if (existsSync(credsDir)) {
    try {
      credentials = readdirSync(credsDir)
        .filter(f => f.endsWith('.json') && !f.startsWith('.'))
        .map(f => {
          const st = statSync(join(credsDir, f));
          return { name: f.replace('.json', ''), size: st.size, modified: st.mtime.toISOString() };
        })
        .sort((a, b) => a.name.localeCompare(b.name));
    } catch {}
  }

  // List memory files
  let memoryFiles = [];
  const memDir = join(ws, 'memory');
  if (existsSync(memDir)) {
    try {
      memoryFiles = readdirSync(memDir)
        .filter(f => f.endsWith('.md') || f.endsWith('.json'))
        .map(f => {
          const st = statSync(join(memDir, f));
          return { name: f, size: st.size, modified: st.mtime.toISOString() };
        })
        .sort((a, b) => b.modified.localeCompare(a.modified));
    } catch {}
  }

  // Get recent daily notes (last 3)
  const recentNotes = memoryFiles
    .filter(f => /^\d{4}-\d{2}-\d{2}\.md$/.test(f.name))
    .slice(0, 3)
    .map(f => ({ ...f, content: safeRead(`memory/${f.name}`, 4096) }));

  // Gateway state for this agent
  const liveState = collector.state.get(agentId) || {};

  return {
    id: agentId,
    config: agentConfig,
    workspace: {
      path: ws,
      soul, identity, memory, tasks, tools, heartbeat,
      agents, user, activeWork, bootstrap,
    },
    skills,
    credentials,
    memoryFiles,
    recentNotes,
    live: liveState,
  };
}

// ── Analytics Aggregator ────────────────────────────
import { homedir } from 'os';

// CST (UTC-6) timezone offset in milliseconds
const CST_OFFSET_MS = -6 * 60 * 60 * 1000;

// Simple cache for analytics (60s TTL)
const analyticsCache = new Map();
const ANALYTICS_CACHE_TTL = 60000;
const COSTS_CACHE_TTL = 30000; // 30 seconds for costs

// Cache for computed cost data
let cachedCostsData = null;
let lastCostsComputeTime = 0;
const sessionFilesMtimes = new Map(); // path -> mtimeMs
const MODEL_PRICING = {
  // [inputPer1M, outputPer1M, cacheReadPer1M, cacheWritePer1M]
  'gemini-2.5-flash': [0.15, 0.60, 0.0375, 0.15],
  'gemini-2.0-flash': [0.10, 0.40, 0.025, 0.10],
  'claude-opus-4-5': [15.00, 75.00, 1.50, 15.00],
  'claude-sonnet-4-5': [3.00, 15.00, 0.30, 3.00],
  'claude-haiku-4-5': [0.80, 4.00, 0.08, 0.80],
  'gpt-4o': [2.50, 10.00, 1.25, 2.50],
  'gpt-4o-mini': [0.15, 0.60, 0.075, 0.15],
};
const DEFAULT_PRICING = [1.00, 3.00, 0.10, 1.00];
const MODEL_PRICING_PATH = join(process.env.HOME || '/home/openclaw', '.openclaw', 'workspace', 'model-pricing.json');
let mergedModelPricing = null;

function normalizeModelName(model) {
  return String(model || '').replace('anthropic/', '').replace('openai/', '').replace('google/', '');
}

function getMergedModelPricing() {
  if (mergedModelPricing) return mergedModelPricing;
  const merged = { ...MODEL_PRICING };
  try {
    if (existsSync(MODEL_PRICING_PATH)) {
      const raw = JSON.parse(readFileSync(MODEL_PRICING_PATH, 'utf8'));
      for (const [model, rates] of Object.entries(raw || {})) {
        if (!rates || typeof rates !== 'object') continue;
        const input = Number(rates.input);
        const output = Number(rates.output);
        const cacheRead = Number(rates.cacheRead);
        const cacheWrite = Number(rates.cacheWrite);
        if ([input, output, cacheRead, cacheWrite].every(Number.isFinite)) {
          merged[normalizeModelName(model)] = [input, output, cacheRead, cacheWrite];
        }
      }
    }
  } catch (e) {
    console.warn('[analytics] failed to read model-pricing.json:', e.message);
  }
  mergedModelPricing = merged;
  return mergedModelPricing;
}


function getCachedOrCompute(cacheKey, computeFn) {
  const cached = analyticsCache.get(cacheKey);
  if (cached && Date.now() - cached.ts < ANALYTICS_CACHE_TTL) return cached.data;
  const data = computeFn();
  analyticsCache.set(cacheKey, { data, ts: Date.now() });
  // Prune old entries
  if (analyticsCache.size > 20) {
    for (const [k, v] of analyticsCache) {
      if (Date.now() - v.ts > ANALYTICS_CACHE_TTL) analyticsCache.delete(k);
    }
  }
  return data;
}

function toCstDate(isoString) {
  const d = new Date(isoString);
  return new Date(d.getTime() + CST_OFFSET_MS).toISOString().split('T')[0];
}

function writeKillSwitches(payload) {
  const tmpPath = `${KILL_SWITCHES_PATH}.tmp`;
  writeFileSync(tmpPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  renameSync(tmpPath, KILL_SWITCHES_PATH);
}


function parseDependsOnIds(value) {
  if (typeof value !== 'string' || !value.trim()) return [];
  return [...new Set(value.split(',')
    .map((part) => Number.parseInt(part.trim(), 10))
    .filter((id) => Number.isInteger(id) && id > 0))];
}

function computeCostsData() {
  const now = Date.now();
  const AGENTS_DIR = join(homedir(), '.openclaw', 'agents');

  // Check cache validity (30 seconds TTL and file mtimes)
  if (cachedCostsData && (now - lastCostsComputeTime < COSTS_CACHE_TTL)) {
    let filesChanged = false;
    try {
      const agentIds = readdirSync(AGENTS_DIR, { withFileTypes: true })
        .filter(d => d.isDirectory())
        .map(d => d.name);
      for (const agentId of agentIds) {
        const sessDir = join(AGENTS_DIR, agentId, 'sessions');
        if (!existsSync(sessDir)) continue;
        const files = readdirSync(sessDir).filter(
          f => f.endsWith('.jsonl') && !f.includes('.deleted.') && !f.includes('.archived.')
        );
        for (const file of files) {
          const sessionPath = join(sessDir, file);
          const stat = statSync(sessionPath);
          if (sessionFilesMtimes.get(sessionPath) !== stat.mtimeMs) {
            filesChanged = true;
            break;
          }
        }
        if (filesChanged) break;
      }
    } catch (e) {
      console.warn('Error checking session file mtimes, forcing recompute:', e.message);
      filesChanged = true; // Force recompute on error
    }
    if (!filesChanged) {
      // console.log('Serving costs data from cache.');
      return cachedCostsData;
    }
    // console.log('Session files changed or cache expired, recomputing costs data.');
  }

  const dailyCosts = new Map(); // date -> { total: 0, byModel: { modelId: cost } }
  const sessionCosts = []; // [{ id, started, model, messages, tokens, cost, source }]
  const modelTotalCosts = new Map(); // modelId -> totalCost
  const modelTotalTokens = new Map(); // modelId -> totalTokens

  // Quota tracking
  const todayCST = toCstDate(new Date().toISOString());
  let rpdUsed = 0; // Requests per Day
  let rpmUsed = 0; // Requests per Minute
  const currentMinuteStartCST = new Date(new Date().getTime() + CST_OFFSET_MS);
  currentMinuteStartCST.setSeconds(0, 0);

  const AGENTS_SUBDIR = join(homedir(), '.openclaw', 'agents'); // Corrected path based on previous issue
  let agentIds = [];
  try {
    agentIds = readdirSync(AGENTS_SUBDIR, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => d.name);
  } catch { /* no agents dir */ }

  sessionFilesMtimes.clear(); // Clear previous mtimes

  for (const agentId of agentIds) {
    const sessDir = join(AGENTS_SUBDIR, agentId, 'sessions');
    if (!existsSync(sessDir)) continue;

    try {
      const files = readdirSync(sessDir).filter(
        f => f.endsWith('.jsonl') && !f.includes('.deleted.') && !f.includes('.archived.')
      );

      for (const file of files) {
        const sessionPath = join(sessDir, file);
        const stat = statSync(sessionPath);
        sessionFilesMtimes.set(sessionPath, stat.mtimeMs); // Store mtime

        let currentModel = 'unknown';
        let sessionStartTime = null;
        let sessionMessageCount = 0;
        let sessionTotalTokens = 0;
        let sessionTotalCost = 0;
        let isHeartbeatSession = false;

        try {
          const content = readFileSync(sessionPath, 'utf8');
          const lines = content.split('\n').filter(l => l.trim());

          for (const line of lines) {
            try {
              const data = JSON.parse(line);

              if (data.type === 'session') {
                sessionStartTime = data.timestamp;
              } else if (data.type === 'model_change' && data.modelId) {
                currentModel = data.modelId;
              } else if (data.type === 'custom' && data.customType === 'model-snapshot' && data.data?.modelId) {
                currentModel = data.data.modelId;
              }

              if (data.type === 'message' && data.message) {
                sessionMessageCount++;
                const msg = data.message;
                if (!isHeartbeatSession && msg.role === 'user') {
                  // Spec: heartbeat identified by first user message containing conversation_label=heartbeat
                  if (line.includes('\"conversation_label\"') && line.toLowerCase().includes('heartbeat')) {
                    isHeartbeatSession = true;
                  }
                }
                const usage = msg.usage || {};
                const cost = usage.cost?.total || 0;
                const tokens = (usage.input || 0) + (usage.output || 0) + (usage.cacheRead || 0);

                // Aggregate costs by day
                const cstDate = toCstDate(data.timestamp);
                if (!dailyCosts.has(cstDate)) {
                  dailyCosts.set(cstDate, { total: 0, byModel: {} });
                }
                const dayEntry = dailyCosts.get(cstDate);
                dayEntry.total += cost;
                dayEntry.byModel[currentModel] = (dayEntry.byModel[currentModel] || 0) + cost;

                // Aggregate total model costs/tokens
                modelTotalCosts.set(currentModel, (modelTotalCosts.get(currentModel) || 0) + cost);
                modelTotalTokens.set(currentModel, (modelTotalTokens.get(currentModel) || 0) + tokens);

                sessionTotalTokens += tokens;
                sessionTotalCost += cost;

                // Gemini Flash quota tracking (assuming 'google' provider for Flash)
                if (msg.provider === 'google' && cstDate === todayCST) {
                  rpdUsed++;
                  const msgTime = new Date(new Date(data.timestamp).getTime() + CST_OFFSET_MS);
                  if (msgTime >= currentMinuteStartCST) {
                    rpmUsed++;
                  }
                }
              }
            } catch (jsonErr) {
              // console.warn(`Skipping malformed line in ${file}:`, jsonErr.message);
            }
          }
        } catch (readErr) {
          // console.warn(`Skipping broken file ${file}:`, readErr.message);
        }

        if (sessionStartTime) {
          sessionCosts.push({
            id: file.replace('.jsonl', ''),
            started: sessionStartTime,
            model: currentModel,
            messages: sessionMessageCount,
            tokens: sessionTotalTokens,
            cost: sessionTotalCost,
            source: isHeartbeatSession ? 'Heartbeat' : 'Telegram', // Simple source detection
          });
        }
      }
    } catch (dirErr) {
      // console.warn(`Skipping agent session directory ${agentId}:`, dirErr.message);
    }
  }

  // Convert maps to arrays for final output
  const dailyCostsArray = Array.from(dailyCosts.entries())
    .map(([date, data]) => ({ date, ...data }))
    .sort((a, b) => a.date.localeCompare(b.date));

  const modelCostsArray = Array.from(modelTotalCosts.entries())
    .map(([modelId, cost]) => ({ modelId, totalCost: cost, totalTokens: modelTotalTokens.get(modelId) || 0 }))
    .sort((a, b) => b.totalCost - a.totalCost);

  cachedCostsData = {
    daily: dailyCostsArray,
    sessions: sessionCosts.sort((a, b) => new Date(b.started) - new Date(a.started)), // Sort by most recent
    models: modelCostsArray,
    quota: {
      rpd: { used: rpdUsed, limit: 250 },
      rpm: { used: rpmUsed, limit: 10 },
    }
  };
  lastCostsComputeTime = now;
  return cachedCostsData;
}

// Cache for agent metrics data
let cachedAgentMetrics = null;
let lastAgentMetricsComputeTime = 0;
const AGENT_METRICS_CACHE_TTL = 30000; // 30 seconds for agent metrics

function computeAgentMetrics() {
  const now = Date.now();
  const AGENTS_DIR = join(homedir(), '.openclaw', 'agents');

  // Check cache validity
  if (cachedAgentMetrics && (now - lastAgentMetricsComputeTime < AGENT_METRICS_CACHE_TTL)) {
    return cachedAgentMetrics;
  }

  const agentsData = {};
  let agentIds = [];
  try {
    agentIds = readdirSync(AGENTS_DIR, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => d.name);
  } catch { /* no agents dir */ }

  for (const agentId of agentIds) {
    let currentModel = 'N/A';
    let activeSessionId = null;
    let activeSessionStarted = null;
    let todayTokens = 0;
    let todaySpend = 0;
    let sessionCount = 0;
    let workspaceSize = 0;

    const agentConfig = collector.config?.agents?.find(a => a.id === agentId);
    const workspacePath = agentConfig?.workspace || null;
    const todayCST = toCstDate(new Date().toISOString());

    // Calculate workspace size
    if (workspacePath && existsSync(workspacePath)) {
      try {
        const files = readdirSync(workspacePath, { withFileTypes: true });
        for (const file of files) {
          const filePath = join(workspacePath, file.name);
          try {
            const stat = statSync(filePath);
            workspaceSize += stat.size;
          } catch (e) { /* ignore inaccessible files */ }
        }
      } catch (e) { /* ignore inaccessible workspace */ }
    }

    const sessDir = join(AGENTS_DIR, agentId, 'sessions');
    if (existsSync(sessDir)) {
      try {
        const files = readdirSync(sessDir).filter(
          f => f.endsWith('.jsonl') && !f.includes('.deleted.') && !f.includes('.archived.')
        );
        sessionCount = files.length;

        // Find active session (most recently updated session.json entry)
        const sessionsJsonPath = join(AGENTS_DIR, agentId, 'sessions', 'sessions.json');
        if (existsSync(sessionsJsonPath)) {
          const sessionsMetadata = JSON.parse(readFileSync(sessionsJsonPath, 'utf8'));
          let latestUpdatedAt = 0;
          for (const key in sessionsMetadata) {
            const sess = sessionsMetadata[key];
            if (sess.updatedAt && sess.updatedAt > latestUpdatedAt) {
              latestUpdatedAt = sess.updatedAt;
              activeSessionId = sess.sessionId;
              activeSessionStarted = sess.startedAt || sess.timestamp; // Use startedAt if available, fallback to timestamp
            }
          }
        }

        for (const file of files) {
          const sessionPath = join(sessDir, file);
          try {
            const content = readFileSync(sessionPath, 'utf8');
            const lines = content.split('\n').filter(l => l.trim());

            for (const line of lines) {
              try {
                const data = JSON.parse(line);

                if (data.type === 'model_change' && data.modelId) {
                  currentModel = data.modelId;
                } else if (data.type === 'custom' && data.customType === 'model-snapshot' && data.data?.modelId) {
                  currentModel = data.data.modelId;
                }

                if (data.type === 'message' && data.message) {
                  const msg = data.message;
                  const cstDate = toCstDate(data.timestamp);
                  if (cstDate === todayCST) {
                    const usage = msg.usage || {};
                    todayTokens += (usage.input || 0) + (usage.output || 0) + (usage.cacheRead || 0);
                    todaySpend += usage.cost?.total || 0;
                  }
                }
              } catch (jsonErr) { /* ignore malformed lines */ }
            }
          } catch (readErr) { /* ignore broken files */ }
        }
      } catch (dirErr) { /* ignore inaccessible sessions dir */ }
    }

    agentsData[agentId] = {
      id: agentId,
      name: collector.state.get(agentId)?.name || agentId, // Get name from collector.state
      emoji: collector.state.get(agentId)?.emoji || '🤖',
      model: currentModel,
      workspacePath: workspacePath,
      workspaceSize: workspaceSize,
      activeSessionId: activeSessionId,
      activeSessionStarted: activeSessionStarted,
      todayTokens: todayTokens,
      todaySpend: todaySpend,
      sessionCount: sessionCount,
    };
  }

  cachedAgentMetrics = agentsData;
  lastAgentMetricsComputeTime = now;
  return agentsData;
}

function getAnalytics(rangeStr, agentFilter) {
  const AGENTS_DIR = join(homedir(), '.openclaw', 'agents');
  const pricingTable = getMergedModelPricing();
  const pricedModelsUsed = new Set();
  const missingModelsUsed = new Set();
  const computeComponentCosts = (model, input, output, cacheRead, cacheWrite) => {
    const cleanModel = normalizeModelName(model);
    const rates = pricingTable[cleanModel];
    if (!rates) {
      if (cleanModel) missingModelsUsed.add(cleanModel);
      return null;
    }
    pricedModelsUsed.add(cleanModel);
    return {
      input: (input / 1e6) * rates[0],
      output: (output / 1e6) * rates[1],
      cacheRead: (cacheRead / 1e6) * rates[2],
      cacheWrite: (cacheWrite / 1e6) * rates[3],
    };
  };
  const range = rangeStr === 'all' ? Infinity : parseInt(rangeStr);
  const cutoffDate = rangeStr === 'all' ? 0 : Date.now() - (range * 86400000);

  // Aggregate data structures
  let totalCost = 0;
  let totalTokens = 0;
  let inputTokens = 0;
  let outputTokens = 0;
  let cacheReadTokens = 0;
  let cacheWriteTokens = 0;
  let costInput = 0;
  let costOutput = 0;
  let costCacheRead = 0;
  let costCacheWrite = 0;
  let apiCalls = 0;
  let totalSessions = 0;
  let totalMessages = 0;

  const byAgent = new Map(); // agentId -> {cost, tokens}
  const byDate = new Map(); // date -> {cost, tokens}
  const byModel = new Map(); // model -> {cost, tokens}
  const bySource = new Map(); // source -> {cost, tokens, sessions}
  const sessions = []; // [{agentId, sessionId, cost, tokens}]

  // Discover all agents
  let agentIds = [];
  try {
    agentIds = readdirSync(AGENTS_DIR, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => d.name);
  } catch {
    // No agents dir
  }

  // Filter agents if needed
  if (agentFilter !== 'all') {
    agentIds = agentIds.filter(id => id === agentFilter);
  }

  // Parse sessions for each agent
  for (const agentId of agentIds) {
    const sessDir = join(AGENTS_DIR, agentId, 'sessions');
    if (!existsSync(sessDir)) continue;

    try {
      const files = readdirSync(sessDir).filter(
        f => f.endsWith('.jsonl') && !f.includes('.deleted.') && !f.includes('.archived.')
      );

      for (const file of files) {
        const sessionId = file.replace('.jsonl', '');
        const sessionPath = join(sessDir, file);
        
        // Check file mtime - skip if too old
        try {
          const stat = statSync(sessionPath);
          if (stat.mtimeMs < cutoffDate) continue;
        } catch {
          continue;
        }

        // Parse session efficiently (read only what we need)
        let sessionCost = 0;
        let sessionTokens = 0;
        let sessionInput = 0;
        let sessionOutput = 0;
        let sessionCache = 0;
        let sessionCacheWrite = 0;
        let sessionCalls = 0;
        let sessionMessages = 0;
        let sessionModel = null;
        let isHeartbeatSession = false;
        let maxMsgInput = 0;
        let maxMsgOutput = 0;
        const toolNames = new Map();

        const trackToolUse = (name) => {
          if (!name || typeof name !== 'string') return;
          toolNames.set(name, (toolNames.get(name) || 0) + 1);
        };

        try {
          const content = readFileSync(sessionPath, 'utf8');
          const lines = content.split('\n').filter(l => l.trim());

          for (const line of lines) {
            try {
              const data = JSON.parse(line);

              // Model tracking
              if (data.type === 'model_change' && data.modelId) {
                sessionModel = data.modelId;
              }

              if (data.type === 'tool_use') {
                trackToolUse(data.name || data.tool_name || data.toolName || data.tool?.name);
              }

              if (Array.isArray(data.message?.content)) {
                for (const block of data.message.content) {
                  if (block?.type === 'tool_use') {
                    trackToolUse(block.name || block.tool_name || block.toolName || block.tool?.name);
                  }
                }
              }

              // Message cost extraction
              if (data.type === 'message' && data.message) {
                const msg = data.message;
                const usage = msg.usage || {};

                // Check timestamp
                const ts = data.timestamp || msg.timestamp;
                if (ts && ts < cutoffDate) continue;

                // Track costs
                const input = usage.input || 0;
                const output = usage.output || 0;
                const cache = usage.cacheRead || 0;
                const cacheWrite = usage.cacheWrite || 0;
                if (input > maxMsgInput) maxMsgInput = input;
                if (output > maxMsgOutput) maxMsgOutput = output;
                const modelForMsg = normalizeModelName(sessionModel || msg.model);
                const hasPricing = Boolean(pricingTable[modelForMsg]);
                if (hasPricing) {
                  pricedModelsUsed.add(modelForMsg);
                } else if (modelForMsg) {
                  missingModelsUsed.add(modelForMsg);
                }

                let cost = null;

                if (!isHeartbeatSession && msg.role === 'user') {
                  if (line.includes('"conversation_label"') && line.toLowerCase().includes('heartbeat')) {
                    isHeartbeatSession = true;
                  }
                }

                if ((input + output + cache + cacheWrite) > 0) sessionMessages++;

                const hasCostComponents = usage.cost && typeof usage.cost === 'object' && (
                  usage.cost.input !== undefined ||
                  usage.cost.output !== undefined ||
                  usage.cost.cacheRead !== undefined ||
                  usage.cost.cacheWrite !== undefined
                );
                if (hasPricing) {
                  if (hasCostComponents) {
                    costInput += usage.cost?.input || 0;
                    costOutput += usage.cost?.output || 0;
                    costCacheRead += usage.cost?.cacheRead || 0;
                    costCacheWrite += usage.cost?.cacheWrite || 0;
                    cost = (usage.cost?.input || 0) + (usage.cost?.output || 0) + (usage.cost?.cacheRead || 0) + (usage.cost?.cacheWrite || 0);
                  } else {
                    const parts = computeComponentCosts(modelForMsg, input, output, cache, cacheWrite);
                    if (parts) {
                      costInput += parts.input;
                      costOutput += parts.output;
                      costCacheRead += parts.cacheRead;
                      costCacheWrite += parts.cacheWrite;
                      cost = parts.input + parts.output + parts.cacheRead + parts.cacheWrite;
                    }
                  }
                }

                if (cost != null) {
                  sessionCost += cost;
                }
                sessionTokens += input + output + cache;
                sessionInput += input;
                sessionOutput += output;
                sessionCache += cache;
                sessionCacheWrite += cacheWrite;

                if (msg.role === 'user') {
                  sessionCalls++;
                }

                // Track by date
                if (ts) {
                  const date = new Date(ts).toISOString().split('T')[0];
                  if (!byDate.has(date)) {
                    byDate.set(date, { cost: 0, tokens: 0 });
                  }
                  const d = byDate.get(date);
                  if (cost != null) d.cost += cost;
                  d.tokens += input + output + cache;
                }

                // Track by model
                if (sessionModel) {
                  if (!byModel.has(sessionModel)) {
                    byModel.set(sessionModel, { cost: 0, tokens: 0, pricingAvailable: Boolean(pricingTable[normalizeModelName(sessionModel)]) });
                  }
                  const m = byModel.get(sessionModel);
                  if (cost != null) m.cost += cost;
                  m.tokens += input + output + cache;
                }
              }
            } catch {
              // Skip malformed lines
            }
          }
        } catch {
          // Skip broken files
        }

        // Aggregate totals
        const cleanSessionModel = normalizeModelName(sessionModel || 'unknown');
        const sessionPricingAvailable = Boolean(pricingTable[cleanSessionModel]);
        if (sessionPricingAvailable) {
          totalCost += sessionCost;
        }
        totalTokens += sessionTokens;
        inputTokens += sessionInput;
        outputTokens += sessionOutput;
        cacheReadTokens += sessionCache;
        cacheWriteTokens += sessionCacheWrite;
        apiCalls += sessionCalls;
        totalSessions++;
        totalMessages += sessionMessages;
        const source = isHeartbeatSession ? 'Cron' : 'Telegram';
        if (!bySource.has(source)) {
          bySource.set(source, { cost: 0, tokens: 0, sessions: 0 });
        }
        const sourceData = bySource.get(source);
        if (sessionPricingAvailable) sourceData.cost += sessionCost;
        sourceData.tokens += sessionTokens;
        sourceData.sessions++;

        const flags = [];
        for (const [, count] of toolNames) {
          if (count >= 5) {
            flags.push('LOOP');
            break;
          }
        }
        if (maxMsgInput > 5000 || maxMsgOutput > 5000) flags.push('BLOAT');
        if (sessionInput > 10 * sessionOutput && sessionMessages < 3 && sessionInput > 0) flags.push('ABANDONED');
        const readableTokens = sessionInput + sessionCache;
        if (readableTokens > 0 && sessionCache < 0.2 * readableTokens && sessionMessages >= 2) flags.push('CACHE_MISS');
        if (isHeartbeatSession && sessionOutput === 0 && sessionInput > 0) flags.push('ERROR');

        // Track by agent
        if (!byAgent.has(agentId)) {
          byAgent.set(agentId, { cost: 0, tokens: 0 });
        }
        const a = byAgent.get(agentId);
        if (sessionPricingAvailable) a.cost += sessionCost;
        a.tokens += sessionTokens;

        // Track session for top list
        if (sessionCost > 0 || sessionTokens > 0) {
          sessions.push({
            agentId,
            sessionId,
            cost: sessionPricingAvailable ? sessionCost : null,
            pricingAvailable: sessionPricingAvailable,
            tokens: sessionTokens,
            model: normalizeModelName(sessionModel || 'unknown'),
            source,
            messages: sessionMessages,
            flags,
          });
        }
      }
    } catch {
      // Skip agent if sessions dir unreadable
    }
  }

  // Sort and format results
  const byAgentArray = Array.from(byAgent.entries())
    .map(([agentId, data]) => ({ agentId, ...data }))
    .sort((a, b) => b.cost - a.cost);

  const byDateArray = Array.from(byDate.entries())
    .map(([date, data]) => ({ date, ...data }))
    .sort((a, b) => a.date.localeCompare(b.date));

  const byModelArray = Array.from(byModel.entries())
    .map(([model, data]) => ({ model, ...data }))
    .sort((a, b) => b.tokens - a.tokens);

  const topSessions = sessions
    .sort((a, b) => (b.cost ?? -1) - (a.cost ?? -1))
    .slice(0, 20);

  const topSessionsByTokens = [...sessions]
    .sort((a, b) => (b.tokens ?? 0) - (a.tokens ?? 0))
    .slice(0, 20);

  const topAgentByTokens = byAgentArray.reduce((max, current) => (
    (current.tokens ?? 0) > (max.tokens ?? 0) ? current : max
  ), { agentId: null, tokens: 0 });

  const tokenConcentration = totalTokens > 0
    ? {
      agent: topAgentByTokens.agentId,
      tokens: topAgentByTokens.tokens ?? 0,
      share: (topAgentByTokens.tokens ?? 0) / totalTokens,
      totalTokens,
      suppressed: totalTokens < 50000,
    }
    : {
      agent: null,
      tokens: 0,
      share: 0,
      totalTokens: 0,
      suppressed: true,
    };

  const pricingCoverage = pricedModelsUsed.size === 0
    ? 'none'
    : missingModelsUsed.size > 0
      ? 'partial'
      : 'full';

  return {
    range: rangeStr,
    agentFilter,
    totalCost: Math.round(totalCost * 10000) / 10000,
    totalTokens,
    inputTokens,
    outputTokens,
    cacheReadTokens,
    cacheWriteTokens,
    costComponents: {
      input: Math.round(costInput * 10000) / 10000,
      output: Math.round(costOutput * 10000) / 10000,
      cacheRead: Math.round(costCacheRead * 10000) / 10000,
      cacheWrite: Math.round(costCacheWrite * 10000) / 10000,
    },
    totalSessions,
    totalMessages,
    bySource: Array.from(bySource.entries())
      .map(([source, data]) => ({ source, ...data }))
      .sort((a, b) => b.cost - a.cost),
    apiCalls,
    byAgent: byAgentArray,
    overTime: byDateArray,
    byModel: byModelArray,
    topSessions,
    topSessionsByTokens,
    tokenConcentration,
    pricingCoverage,
  };
}

// ── Token Analytics (granular breakdown by day and agent) ──
function getTokenAnalytics(rangeStr, agentFilter) {
  const AGENTS_DIR = join(homedir(), '.openclaw', 'agents');
  const range = rangeStr === 'all' ? Infinity : parseInt(rangeStr);
  const cutoffDate = rangeStr === 'all' ? 0 : Date.now() - (range * 86400000);

  // Aggregate data structures
  let totalCost = 0;
  let totalTokens = 0;
  let inputTokens = 0;
  let outputTokens = 0;
  let cacheReadTokens = 0;
  let cacheWriteTokens = 0;
  let apiCalls = 0;

  const byAgent = new Map(); // agentId -> {inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens, cost}
  const byDate = new Map(); // date -> {inputTokens, outputTokens, cacheReadTokens, cacheWriteTokens, cost}
  const byModel = new Map(); // model -> {inputTokens, outputTokens, cacheReadTokens, cost}
  const byAgentDate = new Map(); // "agentId:date" -> {inputTokens, outputTokens, cacheReadTokens, cost}

  // Discover all agents
  let agentIds = [];
  try {
    agentIds = readdirSync(AGENTS_DIR, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => d.name);
  } catch {
    // No agents dir
  }

  // Filter agents if needed
  if (agentFilter !== 'all') {
    agentIds = agentIds.filter(id => id === agentFilter);
  }

  // Parse sessions for each agent
  for (const agentId of agentIds) {
    const sessDir = join(AGENTS_DIR, agentId, 'sessions');
    if (!existsSync(sessDir)) continue;

    try {
      const files = readdirSync(sessDir).filter(
        f => f.endsWith('.jsonl') && !f.includes('.deleted.') && !f.includes('.archived.')
      );

      for (const file of files) {
        const sessionPath = join(sessDir, file);
        
        // Check file mtime - skip if too old
        try {
          const stat = statSync(sessionPath);
          if (stat.mtimeMs < cutoffDate) continue;
        } catch {
          continue;
        }

        // Parse session
        let currentModel = null;
        try {
          const content = readFileSync(sessionPath, 'utf8');
          const lines = content.split('\n').filter(l => l.trim());

          for (const line of lines) {
            try {
              const data = JSON.parse(line);

              // Track model changes
              if (data.type === 'model_change' && data.modelId) {
                currentModel = data.modelId;
              }

              // Message cost extraction
              if (data.type === 'message' && data.message) {
                const msg = data.message;
                const usage = msg.usage || {};

                // Check timestamp
                const ts = data.timestamp || msg.timestamp;
                if (ts && ts < cutoffDate) continue;

                // Extract token counts
                const cost = usage.cost?.total || 0;
                const input = usage.input || 0;
                const output = usage.output || 0;
                const cacheRead = usage.cacheRead || 0;
                const cacheWrite = usage.cacheWrite || 0;

                // Aggregate totals
                totalCost += cost;
                totalTokens += input + output + cacheRead;
                inputTokens += input;
                outputTokens += output;
                cacheReadTokens += cacheRead;
                cacheWriteTokens += cacheWrite;

                if (msg.role === 'user') {
                  apiCalls++;
                }

                // Track by date
                if (ts) {
                  const date = new Date(ts).toISOString().split('T')[0];
                  if (!byDate.has(date)) {
                    byDate.set(date, { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0, cost: 0 });
                  }
                  const d = byDate.get(date);
                  d.inputTokens += input;
                  d.outputTokens += output;
                  d.cacheReadTokens += cacheRead;
                  d.cacheWriteTokens += cacheWrite;
                  d.cost += cost;
                }

                // Track by agent
                if (!byAgent.has(agentId)) {
                  byAgent.set(agentId, { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0, cost: 0 });
                }
                const a = byAgent.get(agentId);
                a.inputTokens += input;
                a.outputTokens += output;
                a.cacheReadTokens += cacheRead;
                a.cacheWriteTokens += cacheWrite;
                a.cost += cost;

                // Track by model
                if (currentModel) {
                  const modelKey = currentModel.replace('anthropic/', '').replace('openai/', '');
                  if (!byModel.has(modelKey)) {
                    byModel.set(modelKey, { inputTokens: 0, outputTokens: 0, cacheReadTokens: 0, cost: 0 });
                  }
                  const m = byModel.get(modelKey);
                  m.inputTokens += input;
                  m.outputTokens += output;
                  m.cacheReadTokens += cacheRead;
                  m.cost += cost;
                }

                // Track by agent+date (for multi-agent comparison)
                if (ts) {
                  const date = new Date(ts).toISOString().split('T')[0];
                  const adKey = `${agentId}:${date}`;
                  if (!byAgentDate.has(adKey)) {
                    byAgentDate.set(adKey, { agentId, date, tokens: 0, inputTokens: 0, outputTokens: 0, cost: 0 });
                  }
                  const ad = byAgentDate.get(adKey);
                  ad.tokens += input + output + cacheRead;
                  ad.inputTokens += input;
                  ad.outputTokens += output;
                  ad.cost += cost;
                }
              }
            } catch {
              // Skip malformed lines
            }
          }
        } catch {
          // Skip broken files
        }
      }
    } catch {
      // Skip agent if sessions dir unreadable
    }
  }

  // Sort and format results
  const byAgentArray = Array.from(byAgent.entries())
    .map(([agentId, data]) => ({ agentId, ...data }))
    .sort((a, b) => (b.inputTokens + b.outputTokens + b.cacheReadTokens) - (a.inputTokens + a.outputTokens + a.cacheReadTokens));

  const byDateArray = Array.from(byDate.entries())
    .map(([date, data]) => ({ date, ...data }))
    .sort((a, b) => a.date.localeCompare(b.date));

  const byModelArray = Array.from(byModel.entries())
    .map(([model, data]) => ({ model, ...data }))
    .sort((a, b) => (b.inputTokens + b.outputTokens + b.cacheReadTokens) - (a.inputTokens + a.outputTokens + a.cacheReadTokens));

  // Build per-agent time series (for comparison chart)
  const agentTimeSeries = {};
  for (const [, val] of byAgentDate) {
    if (!agentTimeSeries[val.agentId]) agentTimeSeries[val.agentId] = [];
    agentTimeSeries[val.agentId].push({ date: val.date, tokens: val.tokens, inputTokens: val.inputTokens, outputTokens: val.outputTokens, cost: val.cost });
  }
  for (const id of Object.keys(agentTimeSeries)) {
    agentTimeSeries[id].sort((a, b) => a.date.localeCompare(b.date));
  }

  // Calculate cache efficiency
  const cacheHitRate = inputTokens > 0 ? (cacheReadTokens / (inputTokens + cacheReadTokens) * 100) : 0;
  const avgTokensPerCall = apiCalls > 0 ? Math.round(totalTokens / apiCalls) : 0;

  return {
    range: rangeStr,
    agentFilter,
    totalCost: Math.round(totalCost * 10000) / 10000,
    totalTokens,
    inputTokens,
    outputTokens,
    cacheReadTokens,
    cacheWriteTokens,
    apiCalls,
    cacheHitRate: Math.round(cacheHitRate * 10) / 10,
    avgTokensPerCall,
    byAgent: byAgentArray,
    overTime: byDateArray,
    byModel: byModelArray,
    agentTimeSeries,
  };
}

// ── Session Trace (for waterfall view) ─────────────

function getAllSessions({ limit = 50, offset = 0 } = {}) {
  const AGENTS_DIR = join(homedir(), '.openclaw', 'agents');
  const sessions = [];

  try {
    const agentIds = readdirSync(AGENTS_DIR, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => d.name);

    for (const agentId of agentIds) {
      const sessionsPath = join(AGENTS_DIR, agentId, 'sessions', 'sessions.json');
      if (!existsSync(sessionsPath)) continue;

      try {
        const sessData = JSON.parse(readFileSync(sessionsPath, 'utf8'));
        for (const [key, sess] of Object.entries(sessData)) {
          if (!sess.sessionFile) continue;
          
          const agentInfo = collector.state.get(agentId) || {};
          sessions.push({
            key,
            agentId,
            agentName: agentInfo.name || agentId,
            agentEmoji: agentInfo.emoji || '🤖',
            sessionId: sess.sessionId,
            displayName: sess.displayName || key.split(':').pop() || key,
            updatedAt: sess.updatedAt,
            sessionFile: sess.sessionFile,
          });
        }
      } catch {
        // Skip malformed sessions.json
      }
    }
  } catch {
    // No agents dir
  }

  // Sort by most recent first
  sessions.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
  
  // Apply pagination
  const total = sessions.length;
  const clampedLimit = Math.min(Math.max(1, limit), 200);
  const clampedOffset = Math.max(0, offset);
  const paginated = sessions.slice(clampedOffset, clampedOffset + clampedLimit);
  
  return { sessions: paginated, total, limit: clampedLimit, offset: clampedOffset };
}

function getSessionTrace(sessionKey, { limit = 500 } = {}) {
  const AGENTS_DIR = join(homedir(), '.openclaw', 'agents');
  
  // Find the session file
  let sessionFile = null;
  let agentId = null;

  try {
    const agentIds = readdirSync(AGENTS_DIR, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => d.name);

    for (const aid of agentIds) {
      const sessionsPath = join(AGENTS_DIR, aid, 'sessions', 'sessions.json');
      if (!existsSync(sessionsPath)) continue;

      try {
        const sessData = JSON.parse(readFileSync(sessionsPath, 'utf8'));
        if (sessData[sessionKey]) {
          sessionFile = getSafeSessionFilePath(sessData[sessionKey].sessionFile, aid);
          agentId = aid;
          break;
        }
      } catch {}
    }
  } catch {
    return null;
  }

  if (!sessionFile || !existsSync(sessionFile)) return null;

  // Reject excessively large files (>50MB)
  try {
    const fileStat = statSync(sessionFile);
    if (fileStat.size > 50 * 1024 * 1024) {
      return { sessionKey, agentId, trace: [], truncated: true, totalMessages: 0, error: 'Session file too large (>50MB)', summary: { totalCost: 0, totalTokens: 0, totalInput: 0, totalOutput: 0, totalCacheRead: 0, messageCount: 0, totalDuration: 0, startTime: 0, endTime: 0 } };
    }
  } catch { return null; }

  // Parse the JSONL file
  const trace = [];
  let totalCost = 0;
  let totalTokens = 0;
  let totalInput = 0;
  let totalOutput = 0;
  let totalCacheRead = 0;
  let messageCount = 0;
  let currentModel = 'unknown';

  try {
    const content = readFileSync(sessionFile, 'utf8');
    const lines = content.split('\n').filter(l => l.trim());

    for (const line of lines) {
      try {
        const entry = JSON.parse(line);

        // Track model changes
        if (entry.type === 'model_change' && entry.modelId) {
          currentModel = entry.modelId.replace('anthropic/', '').replace('openai/', '');
        }

        // Extract message data
        if (entry.type === 'message' && entry.message) {
          const msg = entry.message;
          const timestamp = entry.timestamp;
          const role = msg.role;
          const usage = msg.usage || {};
          const stopReason = msg.stopReason || '';

          // Extract content types
          const content = msg.content || [];
          const contentTypes = [];
          const toolCalls = [];
          let hasThinking = false;
          let textContent = '';

          for (const item of content) {
            if (item.type === 'text') {
              textContent += item.text || '';
            } else if (item.type === 'toolCall') {
              toolCalls.push({
                name: item.name,
                arguments: item.arguments,
                id: item.id,
              });
              if (!contentTypes.includes('toolCall')) contentTypes.push('toolCall');
            } else if (item.type === 'thinking') {
              hasThinking = true;
              if (!contentTypes.includes('thinking')) contentTypes.push('thinking');
            }
          }

          if (textContent && !contentTypes.includes('text')) {
            contentTypes.push('text');
          }

          // Calculate cost and tokens
          const inputTokens = usage.input || 0;
          const outputTokens = usage.output || 0;
          const cacheRead = usage.cacheRead || 0;
          const cost = usage.cost?.total || 0;
          const tokens = inputTokens + outputTokens + cacheRead;

          totalCost += cost;
          totalTokens += tokens;
          totalInput += inputTokens;
          totalOutput += outputTokens;
          totalCacheRead += cacheRead;
          messageCount++;

          trace.push({
            timestamp,
            role,
            contentTypes,
            toolCalls: toolCalls.map(t => ({ name: t.name, id: t.id })), // Strip arguments from trace (available on detail click)
            hasThinking,
            textPreview: textContent.substring(0, 200),
            fullText: textContent.substring(0, 10000), // Cap full text to prevent huge payloads
            model: currentModel,
            stopReason,
            usage: {
              input: inputTokens,
              output: outputTokens,
              cacheRead,
              total: tokens,
            },
            cost,
          });
        }
      } catch {
        // Skip malformed lines
      }
    }
  } catch {
    return null;
  }

  // Cap trace size — keep last N messages
  const clampedLimit = Math.min(Math.max(1, limit), 2000);
  const wasTruncated = trace.length > clampedLimit;
  const truncatedTrace = wasTruncated ? trace.slice(-clampedLimit) : trace;

  // Calculate durations (time between messages)
  for (let i = 0; i < truncatedTrace.length - 1; i++) {
    const current = new Date(truncatedTrace[i].timestamp).getTime();
    const next = new Date(truncatedTrace[i + 1].timestamp).getTime();
    truncatedTrace[i].duration = next - current;
  }
  if (truncatedTrace.length > 0) {
    truncatedTrace[truncatedTrace.length - 1].duration = 0; // Last message has no duration
  }

  const startTime = truncatedTrace.length > 0 ? new Date(truncatedTrace[0].timestamp).getTime() : 0;
  const endTime = truncatedTrace.length > 0 ? new Date(truncatedTrace[truncatedTrace.length - 1].timestamp).getTime() : 0;
  const totalDuration = endTime - startTime;

  return {
    sessionKey,
    agentId,
    trace: truncatedTrace,
    truncated: wasTruncated,
    totalMessages: trace.length,
    summary: {
      totalCost,
      totalTokens,
      totalInput,
      totalOutput,
      totalCacheRead,
      messageCount,
      totalDuration,
      startTime,
      endTime,
    },
  };
}

function getSafeSessionFilePath(sessionFile, agentId) {
  if (typeof sessionFile !== 'string' || !sessionFile) return null;
  const sessionsDir = resolve(join(homedir(), '.openclaw', 'agents', agentId, 'sessions'));
  const resolvedFile = resolve(sessionFile);
  const allowedPrefix = `${sessionsDir}${sep}`;

  if (!resolvedFile.startsWith(allowedPrefix)) return null;
  if (!resolvedFile.endsWith('.jsonl')) return null;

  return resolvedFile;
}

// ── Traces (delegation trees) ──────────────────────

function getTraces() {
  const AGENTS_DIR = join(homedir(), '.openclaw', 'agents');
  const traces = [];
  const sessionMap = new Map(); // sessionKey -> session metadata

  try {
    const agentIds = readdirSync(AGENTS_DIR, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => d.name);

    // First pass: collect all sessions
    for (const agentId of agentIds) {
      const sessionsPath = join(AGENTS_DIR, agentId, 'sessions', 'sessions.json');
      if (!existsSync(sessionsPath)) continue;

      try {
        const sessData = JSON.parse(readFileSync(sessionsPath, 'utf8'));
        for (const [key, sess] of Object.entries(sessData)) {
          if (!sess.sessionFile) continue;

          // Extract session stats from JSONL
          let cost = 0;
          let tokens = 0;
          let messageCount = 0;
          let model = null;
          let startTime = null;
          let endTime = null;

          const safeSessionFile = getSafeSessionFilePath(sess.sessionFile, agentId);
          if (safeSessionFile && existsSync(safeSessionFile)) {
            try {
              const content = readFileSync(safeSessionFile, 'utf8');
              const lines = content.split('\n').filter(l => l.trim());

              for (const line of lines) {
                try {
                  const entry = JSON.parse(line);
                  
                  if (entry.type === 'model_change' && entry.modelId) {
                    model = entry.modelId;
                  }

                  if (entry.type === 'message' && entry.message) {
                    const msg = entry.message;
                    const usage = msg.usage || {};
                    cost += usage.cost?.total || 0;
                    tokens += (usage.input || 0) + (usage.output || 0) + (usage.cacheRead || 0);
                    if (msg.role === 'user') messageCount++;

                    const ts = entry.timestamp || msg.timestamp;
                    if (ts) {
                      if (!startTime || ts < startTime) startTime = ts;
                      if (!endTime || ts > endTime) endTime = ts;
                    }
                  }
                } catch {}
              }
            } catch {}
          }

          // Determine if this is a main session or subagent
          const isMain = key.endsWith(':main') || !key.includes(':subagent:');
          const label = sess.displayName || sess.origin?.label || key.split(':').pop() || 'unknown';

          // Extract parent key for subagents
          let parentKey = null;
          if (key.includes(':subagent:')) {
            // Parent is the main session of the same agent
            const parts = key.split(':');
            if (parts.length >= 4) {
              parentKey = `${parts[0]}:${parts[1]}:main`;
            }
          }

          const agentInfo = collector.state.get(agentId) || {};
          sessionMap.set(key, {
            key,
            agentId,
            agentName: agentInfo.name || agentId,
            agentEmoji: agentInfo.emoji || '🤖',
            label,
            model: model ? model.replace('anthropic/', '').replace('openai/', '') : 'unknown',
            cost,
            tokens,
            messageCount,
            startTime,
            endTime,
            updatedAt: sess.updatedAt,
            isMain,
            parentKey,
            children: [],
          });
        }
      } catch {}
    }

    // Second pass: build tree structure
    const rootSessions = [];
    for (const [key, sess] of sessionMap.entries()) {
      if (sess.isMain) {
        rootSessions.push(sess);
      } else if (sess.parentKey) {
        const parent = sessionMap.get(sess.parentKey);
        if (parent) {
          parent.children.push(sess);
        } else {
          // Parent not found, treat as orphan root
          rootSessions.push(sess);
        }
      }
    }

    // Sort roots by most recent first
    rootSessions.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));

    // Calculate summary stats
    let totalSessions = sessionMap.size;
    let totalSubagents = 0;
    let totalCost = 0;
    let maxDepth = 1;

    function calculateDepth(sess, depth = 1) {
      if (depth > maxDepth) maxDepth = depth;
      totalCost += sess.cost || 0;
      if (!sess.isMain) totalSubagents++;
      for (const child of sess.children) {
        calculateDepth(child, depth + 1);
      }
    }

    for (const root of rootSessions) {
      calculateDepth(root);
    }

    return {
      traces: rootSessions,
      summary: {
        totalSessions,
        totalSubagents,
        totalCost: Math.round(totalCost * 10000) / 10000,
        maxDepth,
      },
    };
  } catch (e) {
    console.error('getTraces error:', e);
    return { traces: [], summary: { totalSessions: 0, totalSubagents: 0, totalCost: 0, maxDepth: 0 } };
  }
}

// Cache for session events data
let cachedSessionEvents = null;
let lastSessionEventsComputeTime = 0;
const SESSION_EVENTS_CACHE_TTL = 30000; // 30 seconds for session events
const EVENTS_PER_PAGE = 100;

function getSessionsEvents({ range = '24h', source = 'all', page = 1, limit = EVENTS_PER_PAGE } = {}) {
  const now = Date.now();
  const AGENTS_DIR = join(homedir(), '.openclaw', 'agents');

  // Check cache validity and file mtimes
  if (cachedSessionEvents && (now - lastSessionEventsComputeTime < SESSION_EVENTS_CACHE_TTL)) {
    // For simplicity, we're not doing per-file mtime check for ALL events for now
    // as it can be very expensive for many files. We rely on the TTL.
    // A more robust solution would involve a persistent index of file mtimes.
    // console.log('Serving session events from cache (ignoring file mtimes for full scan).');
  } else {
    // console.log('Recomputing session events.');
    const allEvents = [];
    let agentIds = [];
    try {
      agentIds = readdirSync(AGENTS_DIR, { withFileTypes: true })
        .filter(d => d.isDirectory())
        .map(d => d.name);
    } catch { /* no agents dir */ }

    for (const agentId of agentIds) {
      const sessDir = join(AGENTS_DIR, agentId, 'sessions');
      if (!existsSync(sessDir)) continue;

      try {
        const files = readdirSync(sessDir).filter(
          f => f.endsWith('.jsonl') && !f.includes('.deleted.') && !f.includes('.archived.')
        );

        for (const file of files) {
          const sessionPath = join(sessDir, file);
          let currentModel = 'unknown';

          try {
            const content = readFileSync(sessionPath, 'utf8');
            const lines = content.split('\n').filter(l => l.trim());

            let isHeartbeatSession = false;
            // Determine if it's a heartbeat session by checking the first user message
            for (const line of lines) {
              if (line.includes('\"conversation_label\"') && line.toLowerCase().includes('heartbeat')) {
                isHeartbeatSession = true;
                break;
              }
            }

            for (const line of lines) {
              try {
                const data = JSON.parse(line);

                if (data.type === 'model_change' && data.modelId) {
                  currentModel = data.modelId;
                } else if (data.type === 'custom' && data.customType === 'model-snapshot' && data.data?.modelId) {
                  currentModel = data.data.modelId;
                }

                let eventType = data.type;
                let eventRole = null;
                let eventPreview = null;
                let eventTokens = 0;
                let eventCost = 0;

                if (data.type === 'message' && data.message) {
                  const msg = data.message;
                  eventRole = msg.role;

                  const usage = msg.usage || {};
                  eventTokens = (usage.input || 0) + (usage.output || 0) + (usage.cacheRead || 0);
                  eventCost = usage.cost?.total || 0;

                  let textContent = '';
                  let hasToolCall = false;
                  for (const item of (msg.content || [])) {
                    if (item.type === 'text') {
                      textContent += item.text || '';
                    } else if (item.type === 'toolCall') {
                      hasToolCall = true;
                    }
                  }
                  eventPreview = textContent.substring(0, 100) + (textContent.length > 100 ? '...' : '');
                  if (hasToolCall) eventType = 'tool_call'; // Override type for display

                } else if (data.type === 'session') {
                    eventPreview = `Session started (cwd: ${data.cwd || 'N/A'})`;
                } else if (data.type === 'model_change') {
                    eventPreview = `Model changed to ${data.modelId}`; 
                } else if (data.type === 'thinking_level_change') {
                    eventPreview = `Thinking level changed to ${data.thinkingLevel}`; 
                }

                allEvents.push({
                  timestamp: data.timestamp,
                  sessionId: file.replace('.jsonl', ''),
                  type: isHeartbeatSession && eventType === 'session' ? 'heartbeat' : eventType,
                  model: currentModel.replace('anthropic/', '').replace('openai/', ''),
                  role: eventRole,
                  preview: eventPreview,
                  tokens: eventTokens,
                  cost: eventCost,
                  source: isHeartbeatSession ? 'Heartbeat' : 'Telegram', // Set source based on detection
                });

              } catch (jsonErr) { /* ignore malformed lines */ }
            }
          } catch (readErr) { /* ignore broken files */ }
        }
      } catch (dirErr) { /* ignore inaccessible sessions dir */ }
    }
    cachedSessionEvents = allEvents;
    lastSessionEventsComputeTime = now;
  }

  // Apply filters to cached data
  let filteredEvents = cachedSessionEvents.filter(event => {
    // Time range filter
    const eventTime = new Date(event.timestamp).getTime();
    let cutoffTime = 0;
    if (range === '24h') cutoffTime = now - (24 * 3600 * 1000);
    else if (range === '3d') cutoffTime = now - (3 * 24 * 3600 * 1000);
    else if (range === '7d') cutoffTime = now - (7 * 24 * 3600 * 1000);
    else if (range === '30d') cutoffTime = now - (30 * 24 * 3600 * 1000);

    if (eventTime < cutoffTime) return false;

    // Source filter
    if (source !== 'all' && event.source !== source) return false;

    return true;
  });

  // Sort in reverse-chronological order
  filteredEvents.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  // Apply pagination
  const totalEvents = filteredEvents.length;
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + limit;
  const paginatedEvents = filteredEvents.slice(startIndex, endIndex);
  const hasMore = endIndex < totalEvents;

  return { events: paginatedEvents, total: totalEvents, page, limit, hasMore };
}

// ── HTTP Server ─────────────────────────────────────


function readCortexConfig() {
  if (!existsSync(CORTEX_CONFIG_PATH)) return null;
  return JSON.parse(readFileSync(CORTEX_CONFIG_PATH, 'utf8'));
}

function writeCortexConfig(config) {
  const tmpPath = `${CORTEX_CONFIG_PATH}.tmp`;
  writeFileSync(tmpPath, JSON.stringify(config, null, 2), 'utf8');
  renameSync(tmpPath, CORTEX_CONFIG_PATH);
}

function deepMerge(target, source) {
  const output = target && typeof target === 'object' && !Array.isArray(target) ? { ...target } : {};
  if (!source || typeof source !== 'object' || Array.isArray(source)) return output;
  Object.keys(source).forEach((key) => {
    const value = source[key];
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      output[key] = deepMerge(output[key], value);
    } else {
      output[key] = value;
    }
  });
  return output;
}

function tailJsonLines(filePath, limit = 20) {
  if (!existsSync(filePath)) return { lines: [], total: 0 };
  const raw = readFileSync(filePath, 'utf8');
  if (!raw.trim()) return { lines: [], total: 0 };
  const allLines = raw.split('\n').filter((line) => line.trim());
  const lastLines = allLines.slice(-limit);
  const parsed = [];
  for (const line of lastLines) {
    try {
      parsed.push(JSON.parse(line));
    } catch {
      // Skip malformed line
    }
  }
  return { lines: parsed, total: allLines.length };
}

function getDecisionTimestampMs(decision) {
  const ts = decision?.timestamp || decision?.ts || decision?.createdAt || decision?.time;
  if (typeof ts === 'number') return ts > 1e12 ? ts : ts * 1000;
  if (typeof ts === 'string') {
    const parsed = Date.parse(ts);
    return Number.isNaN(parsed) ? 0 : parsed;
  }
  return 0;
}


function buildCortexUsageFromLogs() {
  const { lines } = tailJsonLines(CORTEX_LOG_PATH, 1000);
  const now = Date.now();
  const hourAgo = now - (60 * 60 * 1000);
  const dayAgo = now - (24 * 60 * 60 * 1000);
  const providers = {};

  for (const decision of lines) {
    const model = String(decision?.modelSelected || decision?.selectedModel || decision?.model || '');
    const provider = String(decision?.provider || model.split('/')[0] || 'unknown').toLowerCase();
    const tsMs = getDecisionTimestampMs(decision);
    if (!providers[provider]) providers[provider] = { rpm: 0, rpd: 0, tpm: 0, lastRequest: null };
    if (tsMs >= hourAgo) providers[provider].rpm += 1;
    if (tsMs >= dayAgo) providers[provider].rpd += 1;
    const tokenGuess = Number(decision?.tokenCount || decision?.tokens || decision?.totalTokens || 0);
    if (Number.isFinite(tokenGuess) && tokenGuess > 0 && tsMs >= hourAgo) providers[provider].tpm += tokenGuess;
    if (tsMs > 0) {
      const iso = new Date(tsMs).toISOString();
      if (!providers[provider].lastRequest || iso > providers[provider].lastRequest) providers[provider].lastRequest = iso;
    }
  }

  const limits = {
    google: { rpmLimit: 15, rpdLimit: 1000 },
    groq: { rpmLimit: 30, rpdLimit: 1000, tpmLimit: 30000 },
    cerebras: { tpmLimit: 1000000 },
    mistral: { tpmLimit: 500000 },
    nvidia: { rpmLimit: 40 }
  };
  Object.entries(limits).forEach(([provider, vals]) => {
    providers[provider] = { ...(providers[provider] || {}), ...vals };
  });

  return {
    providers,
    anthropic: { utilization5h: 0, utilization7d: 0, status: 'normal' },
    openai: { remainingRequests: null, remainingTokens: null, resetRequests: null }
  };
}


function parseIsoOrNull(value) {
  if (!value) return null;
  const ts = Date.parse(value);
  return Number.isNaN(ts) ? null : new Date(ts).toISOString();
}

function getSeverityForUtilization(utilization, mode) {
  const value = Number(utilization);
  if (!Number.isFinite(value) || value < 0) return null;
  if (mode === 'subscription') {
    if (value > 0.9) return 'critical';
    if (value >= 0.6) return 'pressure';
    return 'normal';
  }
  if (value >= 1) return 'blocked';
  if (value >= 0.95) return 'critical';
  if (value >= 0.6) return 'pressure';
  return 'normal';
}

function stripModelProviderPrefix(modelName) {
  if (typeof modelName !== 'string' || !modelName) return 'unknown';
  const parts = modelName.split('/').filter(Boolean);
  return parts.length > 1 ? parts.slice(1).join('/') : parts[0];
}

function buildIntelligenceStrip() {
  const nowIso = new Date().toISOString();

  let sentinelStatus = {
    value: 'unknown',
    alertCount: 0,
    latestFinding: null,
    asOf: null,
    freshnessTier: 'batch',
  };

  try {
    if (existsSync(COST_SENTINEL_STATUS_PATH)) {
      const sentinelPayload = JSON.parse(readFileSync(COST_SENTINEL_STATUS_PATH, 'utf8'));
      if (!sentinelPayload || sentinelPayload.error === 'no_data') {
        sentinelStatus = {
          value: 'unknown',
          alertCount: 0,
          latestFinding: null,
          asOf: null,
          freshnessTier: 'batch',
        };
      } else {
        const checks = Object.values(sentinelPayload.checks && typeof sentinelPayload.checks === 'object' ? sentinelPayload.checks : {});
        const rank = { info: 0, ok: 0, normal: 0, watch: 1, warn: 1, warning: 1, critical: 2 };
        const highest = checks.reduce((best, check) => {
          const severity = String(check?.status || check?.severity || 'ok').toLowerCase();
          const score = rank[severity] ?? 0;
          if (!best || score > best.score) {
            return { score, severity, detail: check?.detail || check?.message || null };
          }
          return best;
        }, null);
        const alertCount = checks.filter((check) => {
          const severity = String(check?.status || check?.severity || 'ok').toLowerCase();
          return severity === 'warn' || severity === 'warning' || severity === 'critical';
        }).length;
        sentinelStatus = {
          value: highest?.severity === 'warning' ? 'warn' : (highest?.severity || 'unknown'),
          alertCount,
          latestFinding: highest?.detail || null,
          asOf: parseIsoOrNull(sentinelPayload.timestamp),
          freshnessTier: 'batch',
        };
      }
    }
  } catch {
    sentinelStatus = {
      value: 'unknown',
      alertCount: 0,
      latestFinding: null,
      asOf: null,
      freshnessTier: 'batch',
    };
  }

  const analytics1d = getAnalytics('1', 'all');
  const analytics7d = getAnalytics('7', 'all');
  const latestOverTime = Array.isArray(analytics1d.overTime) && analytics1d.overTime.length > 0
    ? analytics1d.overTime[analytics1d.overTime.length - 1]
    : null;
  const tokenBurnValue = latestOverTime?.tokens ?? 0;
  const overTime7d = Array.isArray(analytics7d.overTime) ? analytics7d.overTime : [];
  const total7d = overTime7d.reduce((sum, row) => sum + (Number(row?.tokens) || 0), 0);
  const average7d = overTime7d.length > 0 ? (total7d / overTime7d.length) : 0;

  const tokenBurn1h = {
    value: tokenBurnValue,
    delta: average7d > 0 ? tokenBurnValue / average7d : null,
    asOf: nowIso,
    freshnessTier: 'polled',
  };

  const byAgent = Array.isArray(analytics1d.byAgent) ? analytics1d.byAgent : [];
  const topConsumer = byAgent.reduce((best, agent) => (
    (agent?.tokens ?? 0) > (best?.tokens ?? 0) ? agent : best
  ), null);
  const totalTokens = Number(analytics1d.totalTokens) || 0;

  const topConsumer1h = totalTokens > 0 && topConsumer
    ? {
      agent: topConsumer.agentId || null,
      share: (topConsumer.tokens ?? 0) / totalTokens,
      tokens: topConsumer.tokens ?? 0,
      asOf: nowIso,
      freshnessTier: 'polled',
    }
    : {
      agent: null,
      share: 0,
      tokens: 0,
      asOf: nowIso,
      freshnessTier: 'polled',
    };

  const severityRank = { unknown: 0, normal: 1, pressure: 2, critical: 3, blocked: 4 };
  const pressurePools = [];

  try {
    if (existsSync(CORTEX_QUOTA_STATE_PATH)) {
      const quotaState = JSON.parse(readFileSync(CORTEX_QUOTA_STATE_PATH, 'utf8'));
      if (quotaState && typeof quotaState === 'object') {
        const modelUsage = quotaState.modelUsage;
        if (modelUsage && typeof modelUsage === 'object') {
            for (const [modelName, usage] of Object.entries(modelUsage)) {
              if (!usage || typeof usage !== 'object') continue;

              const rpdLimit = Number(usage.rpdLimit);
              if (Number.isFinite(rpdLimit) && rpdLimit > 0) {
                const utilization = (Number(usage.rpd) || 0) / rpdLimit;
                const severity = getSeverityForUtilization(utilization, 'model');
                if (severity) {
                  pressurePools.push({
                    severity,
                    label: `${stripModelProviderPrefix(modelName)} RPD`,
                    utilization,
                    asOf: parseIsoOrNull((quotaState[modelName.split('/')[0]] || {}).updatedAt),
                    freshnessTier: 'realtime',
                  });
                }
              }

              const rpmLimit = Number(usage.rpmLimit);
              if (Number.isFinite(rpmLimit) && rpmLimit > 0) {
                const utilization = (Number(usage.rpm) || 0) / rpmLimit;
                const severity = getSeverityForUtilization(utilization, 'model');
                if (severity) {
                  pressurePools.push({
                    severity,
                    label: `${stripModelProviderPrefix(modelName)} RPM`,
                    utilization,
                    asOf: parseIsoOrNull((quotaState[modelName.split('/')[0]] || {}).updatedAt),
                    freshnessTier: 'realtime',
                  });
                }
              }
            }
          }

        const anthropic = quotaState.anthropic;
        if (anthropic && anthropic.updatedAt) {
          const entries = [
            { label: 'Anthropic 5h', utilization: Number(anthropic.utilization5h) },
            { label: 'Anthropic 7d', utilization: Number(anthropic.utilization7d) },
            { label: 'Anthropic Sonnet 7d', utilization: Number(anthropic.sonnetUtilization) },
          ];
          for (const entry of entries) {
            if (!Number.isFinite(entry.utilization)) continue;
            const severity = getSeverityForUtilization(entry.utilization, 'subscription');
            if (!severity) continue;
            pressurePools.push({
              severity,
              label: entry.label,
              utilization: entry.utilization,
              asOf: parseIsoOrNull(anthropic.updatedAt),
              freshnessTier: 'polled',
            });
          }
        }
      }
    }
  } catch {
    // ignore quota-state parse/read issues; fall back to unknown payload below
  }

  const worstPressure = pressurePools.length > 0
    ? pressurePools.sort((a, b) => {
      const sevDiff = (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0);
      if (sevDiff !== 0) return sevDiff;
      return (b.utilization ?? 0) - (a.utilization ?? 0);
    })[0]
    : {
      severity: 'unknown',
      label: 'No quota data',
      utilization: 0,
      asOf: null,
      freshnessTier: 'realtime',
    };

  return {
    sentinelStatus,
    tokenBurn1h,
    topConsumer1h,
    worstPressure,
  };
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname;

  // ── Security Headers ──
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';");

  // CORS — restrict to same origin (no cross-origin API access)
  const origin = req.headers.origin;
  if (origin) {
    const allowed = `http://127.0.0.1:${PORT}`;
    const allowedLocal = `http://localhost:${PORT}`;
    if (origin === allowed || origin === allowedLocal) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
  }

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ── Login (rate-limited) ──
  if (path === '/api/login' && req.method === 'POST') {
    if (AUTH_DISABLED) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, authDisabled: true }));
      return;
    }

    const clientIp = req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const attempts = loginAttempts.get(clientIp) || [];
    // Prune attempts older than RATE_LIMIT_WINDOW
    const recent = attempts.filter(t => now - t < RATE_LIMIT_WINDOW);
    if (recent.length >= RATE_LIMIT_MAX) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Too many attempts. Try again later.' }));
      return;
    }
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > MAX_BODY_SIZE) { req.destroy(); }
    });
    req.on('end', () => {
      try {
        const { password } = JSON.parse(body);
        const inputHash = createHash('sha256').update(String(password)).digest('hex');
        // Support both legacy plaintext and new hash format
        const storedHash = AUTH.passwordHash || createHash('sha256').update(String(AUTH.password)).digest('hex');
        const inputBuf = Buffer.from(inputHash);
        const storedBuf = Buffer.from(storedHash);
        if (inputBuf.length === storedBuf.length && timingSafeEqual(inputBuf, storedBuf)) {
          loginAttempts.delete(clientIp);
          const token = createSession();
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Set-Cookie': `fmc_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${(AUTH.sessionTtlHours || 24) * 3600}`,
          });
          res.end(JSON.stringify({ ok: true }));
        } else {
          recent.push(now);
          loginAttempts.set(clientIp, recent);
          // Exponential delay: 200ms * 2^(attempts-1), max 5s
          const delay = Math.min(200 * Math.pow(2, recent.length - 1), 5000);
          setTimeout(() => {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: false, error: 'Wrong password' }));
          }, delay);
        }
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'Bad request' }));
      }
    });
    return;
  }

  if (path === '/api/logout' && req.method === 'POST') {
    const token = getSessionToken(req);
    if (token) sessions.delete(token);
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Set-Cookie': 'fmc_session=; Path=/; HttpOnly; Max-Age=0',
    });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // ── Login page ──
  if (path === '/login') {
    if (AUTH_DISABLED) {
      res.writeHead(302, { Location: '/' });
      res.end();
      return;
    }

    // If already logged in, redirect to dashboard
    const token = getSessionToken(req);
    if (token && isValidSession(token)) {
      res.writeHead(302, { Location: '/' });
      res.end();
      return;
    }
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
    });
    res.end(LOGIN_HTML);
    return;
  }

  // ── Auth gate (everything below requires auth) ──
  if (!requireAuth(req, res)) return;

  // ── API Routes ──

  if (path === '/api/health' && req.method === 'GET') {
    try {
      const payload = mergeHealthData();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.error('[API] /api/health error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load health data' }));
    }
    return;
  }

  if (path === '/api/overview/summarizer' && req.method === 'GET') {
    try {
      const statePath = join(process.env.HOME || '/home/openclaw', '.openclaw', 'workspace', 'summarizer-state.json');
      if (!existsSync(statePath)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ available: false, reason: 'Summarizer has not run yet' }));
        return;
      }
      const raw = JSON.parse(readFileSync(statePath, 'utf8'));
      const age = (Date.now() - new Date(raw.generated_at).getTime()) / 1000;
      if (age <= 90) raw.current_freshness = 'fresh';
      else if (age <= 180) raw.current_freshness = 'aging';
      else raw.current_freshness = 'stale';
      raw.age_seconds = Math.round(age);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(raw));
    } catch (e) {
      console.error('[API] /api/overview/summarizer error:', e.message);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ available: false, error: e.message }));
    }
    return;
  }

  if (path === '/api/overview/activity' && req.method === 'GET') {
    const fetchedAt = new Date().toISOString();
    const parsedLimit = Number.parseInt(url.searchParams.get('limit') || '15', 10);
    const limit = Math.max(1, Math.min(50, Number.isFinite(parsedLimit) ? parsedLimit : 15));
    const truncateText = (value, maxLen) => {
      const text = String(value ?? '');
      if (text.length <= maxLen) return text;
      return `${text.slice(0, Math.max(0, maxLen - 1)).trimEnd()}…`;
    };
    const normalizeTimestamp = (value) => {
      const text = String(value ?? '').trim();
      if (!text) return null;
      const replaced = text.includes(' ') ? text.replace(' ', 'T') : text;
      if (/([zZ]|[+-]\d{2}:?\d{2})$/.test(replaced)) return replaced;
      return `${replaced}Z`;
    };
    const fetchLocalJson = (endpointPath, timeoutMs = 500) => new Promise((resolve, reject) => {
      const request = http.get({
        hostname: '127.0.0.1',
        port: 3100,
        path: endpointPath,
        timeout: timeoutMs,
      }, (resp) => {
        if (resp.statusCode && resp.statusCode >= 400) {
          resp.resume();
          reject(new Error(`status ${resp.statusCode}`));
          return;
        }
        let data = '';
        resp.on('data', chunk => { data += chunk; });
        resp.on('end', () => {
          try {
            resolve(JSON.parse(data || '{}'));
          } catch (err) {
            reject(err);
          }
        });
      });
      request.on('timeout', () => request.destroy(new Error('timeout')));
      request.on('error', reject);
    });

    try {
      const taskEvents = (() => {
        const tasksDb = openSqlite('/home/openclaw/clawd-control/tasks.db', { readonly: true, fileMustExist: true });
        try {
          const rows = tasksDb.prepare(`
            SELECT h.id, h.task_id, h.actor, h.action, h.detail, h.created_at, t.title as task_title
            FROM task_history h
            LEFT JOIN tasks t ON t.id = h.task_id
            ORDER BY h.created_at DESC
            LIMIT 20
          `).all();

          return rows.map((row) => {
            const action = String(row.action || 'updated');
            const actionLc = action.toLowerCase();
            let type = 'info';
            if (actionLc === 'created' || actionLc === 'status_change' || actionLc === 'updated') type = 'state_change';
            else if (actionLc.includes('fail')) type = 'failure';

            return {
              timestamp: normalizeTimestamp(row.created_at),
              source: 'tasks',
              type,
              agent: String(row.actor || 'system'),
              title: truncateText(`Task #${row.task_id} ${action}`, 80),
              detail: truncateText(row.detail || row.task_title || '', 100),
              link: '/tasks.html',
            };
          });
        } finally {
          tasksDb.close();
        }
      })();

      const opsEntries = getLog({ limit: 20 }).entries || [];
      const opsEvents = opsEntries.map((entry) => {
        const category = String(entry.category || 'ops');
        const categoryLc = category.toLowerCase();
        const status = String(entry.status || '').toLowerCase();
        const sourceMap = {
          cron: 'cron',
          service: 'gateway',
          session: 'gateway',
          staleness: 'tasks',
          cleanup: 'gateway',
        };
        const link = categoryLc === 'staleness' ? '/tasks.html' : '/ops.html';
        let type = 'info';
        if (status === 'success') type = 'completion';
        else if (status === 'failed') type = 'failure';
        else if (status === 'blocked') type = 'alert';

        return {
          timestamp: normalizeTimestamp(entry.timestamp),
          source: sourceMap[categoryLc] || categoryLc,
          type,
          agent: 'system',
          title: truncateText(`${category}: ${entry.action || ''} ${entry.target || ''}`.trim(), 80),
          detail: truncateText(entry.detail || '', 100),
          link,
        };
      });

      let gatewayEvents = [];
      try {
        const payload = await fetchLocalJson('/api/ops/gateway-events?limit=10', 500);
        const events = Array.isArray(payload?.events) ? payload.events : [];
        gatewayEvents = events.map((event) => ({
          timestamp: normalizeTimestamp(event.timestamp),
          source: 'gateway',
          type: 'info',
          agent: 'system',
          title: truncateText(event.message || '', 80),
          detail: null,
          link: '/ops.html',
        }));
      } catch {
        gatewayEvents = [];
      }

      const events = [...taskEvents, ...opsEvents, ...gatewayEvents]
        .map((event) => ({ ...event, _ts: Date.parse(event.timestamp || '') || 0 }))
        .sort((a, b) => b._ts - a._ts)
        .slice(0, limit)
        .map(({ _ts, ...event }) => event);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        events,
        count: events.length,
        fetched_at: fetchedAt,
      }));
    } catch (e) {
      console.error('[API] /api/overview/activity error:', e.message);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ events: [], count: 0, fetched_at: fetchedAt }));
    }
    return;
  }

  if (path === '/api/overview/actions' && req.method === 'GET') {
    const fetchedAt = new Date().toISOString();
    const truncateText = (value, maxLen) => {
      const text = String(value ?? '');
      if (text.length <= maxLen) return text;
      return `${text.slice(0, Math.max(0, maxLen - 1)).trimEnd()}…`;
    };
    const fetchLocalJson = (endpointPath, timeoutMs = 500) => new Promise((resolve, reject) => {
      const request = http.get({
        hostname: '127.0.0.1',
        port: 3100,
        path: endpointPath,
        timeout: timeoutMs,
      }, (resp) => {
        if (resp.statusCode && resp.statusCode >= 400) {
          resp.resume();
          reject(new Error(`status ${resp.statusCode}`));
          return;
        }
        let data = '';
        resp.on('data', chunk => { data += chunk; });
        resp.on('end', () => {
          try {
            resolve(JSON.parse(data || '{}'));
          } catch (err) {
            reject(err);
          }
        });
      });
      request.on('timeout', () => request.destroy(new Error('timeout')));
      request.on('error', reject);
    });

    try {
      const tasksDb = openSqlite('/home/openclaw/clawd-control/tasks.db', { readonly: true, fileMustExist: true });
      const tasks = (() => {
        try {
          const rows = tasksDb.prepare(`
            SELECT id, title, status, priority, created_by, updated_at
            FROM tasks
            WHERE status IN ('review', 'proposed')
            ORDER BY
              CASE priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,
              updated_at DESC
            LIMIT 20
          `).all();
          return rows.map((row) => ({
            source: 'tasks',
            type: row.status,
            severity: String(row.priority || '').toLowerCase() === 'critical' ? 'red' : 'amber',
            title: truncateText(`Task #${row.id}: ${String(row.title || '')}`, 60),
            detail: truncateText(
              `Priority: ${String(row.priority || 'unknown')}. ${row.status === 'proposed' ? `Proposed by: ${String(row.created_by || 'unknown')}` : 'Awaiting review'}.`,
              100,
            ),
            link: '/tasks.html',
            timestamp: row.updated_at || null,
          }));
        } finally {
          tasksDb.close();
        }
      })();

      const sources = await Promise.race([
        Promise.allSettled([
          fetchLocalJson('/api/security/health', 500),
          fetchLocalJson('/api/watcher/health', 500),
        ]),
        new Promise((resolve) => setTimeout(() => resolve([{ status: 'rejected' }, { status: 'rejected' }]), 2000)),
      ]);

      const securityItems = sources[0]?.status === 'fulfilled'
        ? (Array.isArray(sources[0].value?.checks) ? sources[0].value.checks : [])
          .filter((check) => check?.status === 'red')
          .map((check) => ({
            source: 'security',
            type: 'failure',
            severity: 'red',
            title: truncateText(`Security: ${String(check.name || 'Unnamed check')}`, 60),
            detail: truncateText(String(check.message || check.detail || 'No details'), 100),
            link: '/security.html',
            timestamp: check.checked_at || null,
          }))
        : [];

      const watcherFailed = sources[1]?.status === 'fulfilled'
        ? (Array.isArray(sources[1].value?.results?.system_crons) ? sources[1].value.results.system_crons : [])
          .filter((cron) => cron?.status === 'failed')
        : [];
      const watcherSeverity = watcherFailed.length >= 3 ? 'red' : 'amber';
      const cronItems = watcherFailed.map((cron) => ({
        source: 'crons',
        type: 'failure',
        severity: watcherSeverity,
        title: truncateText(`Cron failed: ${String(cron.id || 'unknown')}`, 60),
        detail: truncateText(String(cron.message || 'No details'), 100),
        link: '/ops.html',
        timestamp: cron.finished_at || cron.last_seen || null,
      }));

      const severityRank = { red: 0, amber: 1 };
      const items = [...tasks, ...securityItems, ...cronItems].sort((a, b) => {
        const sDiff = (severityRank[a.severity] ?? 99) - (severityRank[b.severity] ?? 99);
        if (sDiff !== 0) return sDiff;
        const aTs = Date.parse(a.timestamp || '') || 0;
        const bTs = Date.parse(b.timestamp || '') || 0;
        return bTs - aTs;
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        items,
        count: items.length,
        fetched_at: fetchedAt,
      }));
    } catch (e) {
      console.error('[API] /api/overview/actions error:', e.message);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ items: [], count: 0, fetched_at: fetchedAt }));
    }
    return;
  }

  if (path === '/api/cli-usage' && req.method === 'GET') {
    try {
      const payload = loadCliUsage();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.error('[API] /api/cli-usage error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load CLI usage data' }));
    }
    return;
  }

  if (path === '/api/costs/sentinel' && req.method === 'GET') {
    try {
      if (!existsSync(COST_SENTINEL_STATUS_PATH)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'no_data', message: 'Cost sentinel has not run yet' }));
        return;
      }
      const payload = JSON.parse(readFileSync(COST_SENTINEL_STATUS_PATH, 'utf8'));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.error('[API] /api/costs/sentinel error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'parse_error' }));
    }
    return;
  }

  if (path === '/api/intelligence/strip' && req.method === 'GET') {
    try {
      const payload = buildIntelligenceStrip();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.error('[API] /api/intelligence/strip error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load intelligence strip' }));
    }
    return;
  }


  if (path === '/api/costs/budget' && req.method === 'GET') {
    try {
      if (!existsSync(BUDGET_CONFIG_PATH)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({}));
        return;
      }
      const payload = JSON.parse(readFileSync(BUDGET_CONFIG_PATH, 'utf8'));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.warn('[API] /api/costs/budget warning:', e.message);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({}));
    }
    return;
  }


  // ── Intelligence Config Endpoints ──

  if (path === '/api/config/pricing' && req.method === 'GET') {
    try {
      if (!existsSync(MODEL_PRICING_PATH)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({}));
        return;
      }
      const payload = JSON.parse(readFileSync(MODEL_PRICING_PATH, 'utf8'));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.warn('[API] /api/config/pricing warning:', e.message);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({}));
    }
    return;
  }

  if (path === '/api/config/pricing' && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      try {
        if (!body || typeof body !== 'object' || Array.isArray(body)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'validation_error', message: 'Body must be an object keyed by model name' }));
          return;
        }

        for (const [model, value] of Object.entries(body)) {
          if (!model || typeof model !== 'string') {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'validation_error', message: 'Each model key must be a non-empty string' }));
            return;
          }
          if (!value || typeof value !== 'object' || Array.isArray(value)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'validation_error', message: `Pricing for ${model} must be an object` }));
            return;
          }
          for (const field of ['input', 'output', 'cacheRead', 'cacheWrite']) {
            const num = value[field];
            if (!Number.isFinite(num) || num <= 0) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'validation_error', message: `Pricing field ${field} for ${model} must be a positive finite number` }));
              return;
            }
          }
        }

        writeFileSync(MODEL_PRICING_PATH, JSON.stringify(body, null, 2), 'utf8');
        mergedModelPricing = null;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(body));
      } catch (e) {
        console.error('[API] /api/config/pricing error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'internal_error' }));
      }
    }).catch((e) => {
      if (e.message === 'Payload too large') {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Payload too large' }));
        return;
      }
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
    });
    return;
  }

  if (path === '/api/config/budget' && req.method === 'GET') {
    try {
      if (!existsSync(BUDGET_CONFIG_PATH)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({}));
        return;
      }
      const payload = JSON.parse(readFileSync(BUDGET_CONFIG_PATH, 'utf8'));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.warn('[API] /api/config/budget warning:', e.message);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({}));
    }
    return;
  }

  if (path === '/api/config/budget' && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      try {
        if (!body || typeof body !== 'object' || Array.isArray(body)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'validation_error', message: 'Body must be an object' }));
          return;
        }

        const out = {};
        if (body.daily !== undefined) {
          if (!Number.isFinite(body.daily) || body.daily < 0) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'validation_error', message: 'daily must be a non-negative finite number' }));
            return;
          }
          out.daily = body.daily;
        }
        if (body.weekly !== undefined) {
          if (!Number.isFinite(body.weekly) || body.weekly < 0) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'validation_error', message: 'weekly must be a non-negative finite number' }));
            return;
          }
          out.weekly = body.weekly;
        }

        writeFileSync(BUDGET_CONFIG_PATH, JSON.stringify(out, null, 2), 'utf8');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(out));
      } catch (e) {
        console.error('[API] /api/config/budget error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'internal_error' }));
      }
    }).catch((e) => {
      if (e.message === 'Payload too large') {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Payload too large' }));
        return;
      }
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
    });
    return;
  }

  if (path === '/api/config/sentinel' && req.method === 'GET') {
    try {
      if (!existsSync(SENTINEL_CONFIG_PATH)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({}));
        return;
      }
      const payload = JSON.parse(readFileSync(SENTINEL_CONFIG_PATH, 'utf8'));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.warn('[API] /api/config/sentinel warning:', e.message);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({}));
    }
    return;
  }

  if (path === '/api/config/sentinel' && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      try {
        if (!body || typeof body !== 'object' || Array.isArray(body)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'validation_error', message: 'Body must be an object' }));
          return;
        }

        const defaults = {
          agentConcentrationWarn: 70,
          agentConcentrationCritical: 90,
          dailyBudgetWarn: 1.0,
          dailyBudgetCritical: 2.0,
          sessionVolumeWarn: 30,
          sessionVolumeCritical: 50,
          weeklyTrendMultiplier: 2.0,
          alertCooldownHours: 6,
        };
        const out = { ...defaults };

        const finiteNonNegative = (value) => Number.isFinite(value) && value >= 0;
        const intNonNegative = (value) => Number.isInteger(value) && value >= 0;

        if (body.agentConcentrationWarn !== undefined) {
          const value = body.agentConcentrationWarn;
          if (!finiteNonNegative(value) || value > 100) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'validation_error', message: 'agentConcentrationWarn must be between 0 and 100' }));
            return;
          }
          out.agentConcentrationWarn = value;
        }

        if (body.agentConcentrationCritical !== undefined) {
          const value = body.agentConcentrationCritical;
          if (!finiteNonNegative(value) || value > 100) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'validation_error', message: 'agentConcentrationCritical must be between 0 and 100' }));
            return;
          }
          out.agentConcentrationCritical = value;
        }

        if (body.dailyBudgetWarn !== undefined) {
          const value = body.dailyBudgetWarn;
          if (!finiteNonNegative(value)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'validation_error', message: 'dailyBudgetWarn must be a non-negative finite number' }));
            return;
          }
          out.dailyBudgetWarn = value;
        }

        if (body.dailyBudgetCritical !== undefined) {
          const value = body.dailyBudgetCritical;
          if (!finiteNonNegative(value)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'validation_error', message: 'dailyBudgetCritical must be a non-negative finite number' }));
            return;
          }
          out.dailyBudgetCritical = value;
        }

        if (body.sessionVolumeWarn !== undefined) {
          const value = body.sessionVolumeWarn;
          if (!intNonNegative(value)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'validation_error', message: 'sessionVolumeWarn must be an integer >= 0' }));
            return;
          }
          out.sessionVolumeWarn = value;
        }

        if (body.sessionVolumeCritical !== undefined) {
          const value = body.sessionVolumeCritical;
          if (!intNonNegative(value)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'validation_error', message: 'sessionVolumeCritical must be an integer >= 0' }));
            return;
          }
          out.sessionVolumeCritical = value;
        }

        if (body.weeklyTrendMultiplier !== undefined) {
          const value = body.weeklyTrendMultiplier;
          if (!Number.isFinite(value) || value <= 0) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'validation_error', message: 'weeklyTrendMultiplier must be a finite number greater than 0' }));
            return;
          }
          out.weeklyTrendMultiplier = value;
        }

        if (body.alertCooldownHours !== undefined) {
          const value = body.alertCooldownHours;
          if (!finiteNonNegative(value)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'validation_error', message: 'alertCooldownHours must be a non-negative finite number' }));
            return;
          }
          out.alertCooldownHours = value;
        }

        writeFileSync(SENTINEL_CONFIG_PATH, JSON.stringify(out, null, 2), 'utf8');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(out));
      } catch (e) {
        console.error('[API] /api/config/sentinel error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'internal_error' }));
      }
    }).catch((e) => {
      if (e.message === 'Payload too large') {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Payload too large' }));
        return;
      }
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
    });
    return;
  }

  if (path === '/api/config/rate-limits' && req.method === 'GET') {
    try {
      if (!existsSync(RATE_LIMITS_CONFIG_PATH)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify([]));
        return;
      }
      const payload = JSON.parse(readFileSync(RATE_LIMITS_CONFIG_PATH, 'utf8'));
      if (!Array.isArray(payload)) {
        console.warn('[API] /api/config/rate-limits warning: expected array');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify([]));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.warn('[API] /api/config/rate-limits warning:', e.message);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify([]));
    }
    return;
  }

  if (path === '/api/config/rate-limits' && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      try {
        if (!Array.isArray(body)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'validation_error', message: 'Body must be an array of rate limit entries' }));
          return;
        }

        const out = [];
        for (let i = 0; i < body.length; i++) {
          const entry = body[i];
          if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'validation_error', message: `Entry at index ${i} must be an object` }));
            return;
          }

          const provider = typeof entry.provider === 'string' ? entry.provider.trim() : '';
          const model = typeof entry.model === 'string' ? entry.model.trim() : '';
          const limitType = typeof entry.limitType === 'string' ? entry.limitType.trim() : '';
          const label = typeof entry.label === 'string' ? entry.label.trim() : '';

          if (!provider || !model || !limitType || !label) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'validation_error', message: `Entry at index ${i} requires non-empty provider, model, limitType, and label` }));
            return;
          }

          if (!Number.isFinite(entry.limit) || entry.limit <= 0) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'validation_error', message: `Entry at index ${i} limit must be a positive finite number` }));
            return;
          }

          if (entry.used !== undefined && !Number.isFinite(entry.used)) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'validation_error', message: `Entry at index ${i} used must be a finite number when provided` }));
            return;
          }

          if (entry.source !== undefined && typeof entry.source !== 'string') {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'validation_error', message: `Entry at index ${i} source must be a string when provided` }));
            return;
          }

          const clean = {
            provider,
            model,
            limitType,
            label,
            limit: entry.limit,
          };

          if (entry.used !== undefined) clean.used = entry.used;
          if (entry.source !== undefined) clean.source = entry.source;

          out.push(clean);
        }

        writeFileSync(RATE_LIMITS_CONFIG_PATH, JSON.stringify(out, null, 2), 'utf8');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(out));
      } catch (e) {
        console.error('[API] /api/config/rate-limits error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'internal_error' }));
      }
    }).catch((e) => {
      if (e.message === 'Payload too large') {
        res.writeHead(413, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Payload too large' }));
        return;
      }
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
    });
    return;
  }


  if (path === '/api/cron/health' && req.method === 'GET') {
    try {
      if (!existsSync(CRON_JOBS_PATH)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'unavailable', message: 'Cron jobs file not found' }));
        return;
      }

      const scheduleToHuman = (expr) => {
        const value = String(expr || '').trim();
        if (value === '0 */4 * * *') return 'Every 4 hours';
        if (value === '0 */6 * * *') return 'Every 6 hours';
        if (value === '*/30 * * * *') return 'Every 30 minutes';
        if (value === '0 0 * * *') return 'Daily at midnight';
        return value;
      };

      const payload = JSON.parse(readFileSync(CRON_JOBS_PATH, 'utf8'));
      const jobs = Array.isArray(payload?.jobs) ? payload.jobs : [];
      const health = jobs.map((job) => {
        const state = job?.state && typeof job.state === 'object' ? job.state : {};
        const expr = String(job?.schedule?.expr || '');
        return {
          id: job?.id || '',
          name: job?.name || 'unnamed-job',
          enabled: Boolean(job?.enabled),
          schedule: expr,
          scheduleHuman: scheduleToHuman(expr),
          lastStatus: state?.lastStatus || null,
          consecutiveErrors: Number(state?.consecutiveErrors) || 0,
          lastDurationMs: Number(state?.lastDurationMs) || 0,
          lastRunAtMs: Number(state?.lastRunAtMs) || 0,
          nextRunAtMs: Number(state?.nextRunAtMs) || 0,
          modelOverride: job?.modelOverride || null,
          sessionTarget: job?.sessionTarget || null,
        };
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(health));
    } catch (e) {
      console.error('[API] /api/cron/health error:', e.message);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'unavailable', message: 'Cron jobs file not found' }));
    }
    return;
  }

  if (path === '/api/limits' && req.method === 'GET') {
    try {
      const costsData = computeCostsData();
      const now = new Date();
      const nextMidnight = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 0, 0));
      const limits = [
        {
          provider: 'gemini',
          model: 'gemini-2.5-flash',
          limitType: 'rpd',
          label: 'Requests Per Day',
          used: costsData?.quota?.rpd?.used || 0,
          limit: costsData?.quota?.rpd?.limit || 0,
          resetAt: nextMidnight.toISOString(),
          source: 'verified',
          pollingInterval: 30,
        },
        {
          provider: 'gemini',
          model: 'gemini-2.5-flash',
          limitType: 'rpm',
          label: 'Requests Per Minute',
          used: costsData?.quota?.rpm?.used || 0,
          limit: costsData?.quota?.rpm?.limit || 0,
          resetAt: null,
          source: 'verified',
          pollingInterval: 30,
        },
      ];
      const extraLimitsPath = join(process.env.HOME || '/home/openclaw', '.openclaw', 'workspace', 'rate-limits.json');
      if (existsSync(extraLimitsPath)) {
        const extra = JSON.parse(readFileSync(extraLimitsPath, 'utf8'));
        if (Array.isArray(extra)) limits.push(...extra);
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(limits));
    } catch (e) {
      console.error('[API] /api/limits error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify([]));
    }
    return;
  }

  if (path === '/api/health/check' && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      try {
        const scriptPath = existsSync(SYSTEM_HEALTH_SCRIPT_PATH)
          ? SYSTEM_HEALTH_SCRIPT_PATH
          : LOCAL_HEALTH_SCRIPT_PATH;
        if (!existsSync(scriptPath)) {
          throw new Error('Health check script not found');
        }
        const service = typeof body.service === 'string' ? body.service.trim() : '';
        const args = service ? [service] : [];
        execFileSync(scriptPath, args, { encoding: 'utf8', stdio: 'pipe', timeout: 120000 });
        const payload = mergeHealthData();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(payload));
      } catch (e) {
        console.error('[API] /api/health/check error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Health check failed' }));
      }
    }).catch((e) => {
      const code = e.message === 'Payload too large' ? 413 : 400;
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message === 'Payload too large' ? 'Payload too large' : 'Invalid JSON body' }));
    });
    return;
  }

  if (path.startsWith('/api/health/') && path.endsWith('/key-rotation') && req.method === 'PATCH') {
    const parts = path.split('/').filter(Boolean);
    const serviceId = parts[2];
    if (!serviceId) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid service id' }));
      return;
    }

    readJsonBody(req).then((body) => {
      try {
        const nextLastRotated = body.last_rotated;
        if (nextLastRotated !== null && (typeof nextLastRotated !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(nextLastRotated))) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'last_rotated must be YYYY-MM-DD or null' }));
          return;
        }

        const config = loadApisConfig();
        const service = config.services.find((svc) => svc.id === serviceId);
        if (!service) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Service not found' }));
          return;
        }
        if (!service.api_key) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Service does not have API key tracking' }));
          return;
        }

        service.api_key.last_rotated = nextLastRotated;
        writeFileSync(APIS_CONFIG_PATH, `${JSON.stringify(config, null, 2)}\n`, 'utf8');
        const merged = mergeHealthData();
        const updated = merged.services.find((svc) => svc.id === serviceId);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ service: updated }));
      } catch (e) {
        console.error('[API] /api/health/:id/key-rotation error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Failed to update key rotation' }));
      }
    }).catch((e) => {
      const code = e.message === 'Payload too large' ? 413 : 400;
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message === 'Payload too large' ? 'Payload too large' : 'Invalid JSON body' }));
    });
    return;
  }

  if (path.startsWith('/api/health/') && path.split('/').length === 4 && req.method === 'GET') {
    try {
      const serviceId = path.split('/')[3];
      const payload = mergeHealthData();
      const service = payload.services.find((svc) => svc.id === serviceId);
      if (!service) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Service not found' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        checked_at: payload.checked_at,
        summary: payload.summary,
        service,
      }));
    } catch (e) {
      console.error('[API] /api/health/:id error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load service health' }));
    }
    return;
  }

  if (path === '/api/snapshot') {
    const snapshot = collector.getSnapshot();
    // Enrich with skills count for each agent
    if (snapshot.agents) {
      for (const [id, agent] of Object.entries(snapshot.agents)) {
        agent.skillsCount = getSkillsCount(id);
      }
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(snapshot));
    return;
  }

  if (path === '/api/agents' && req.method === 'GET') {
    try {
      const agents = computeAgentMetrics();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(Object.values(agents)));
    } catch (e) {
      console.error('[API] /api/agents error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  if (path.startsWith('/api/agents/') && path.split('/').length === 4) {
    const id = path.split('/')[3];
    const state = collector.state.get(id);
    if (!state) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'agent not found' }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(state));
    return;
  }

  // ── Tasks ──

  if (path === '/api/ops/services/status' && req.method === 'GET') {
    try {
      const services = OPS_SERVICES.map((name) => {
        const activeRaw = execSync(`systemctl is-active ${name}`, { encoding: 'utf8', timeout: 30000, stdio: ['ignore', 'pipe', 'pipe'] }).trim();
        const showRaw = execSync(`systemctl show ${name} --property=ActiveEnterTimestamp,MainPID,MemoryUsageCurrent`, { encoding: 'utf8', timeout: 30000, stdio: ['ignore', 'pipe', 'pipe'] });
        const parsed = parseSystemctlShow(showRaw);
        return {
          name,
          active: activeRaw === 'active',
          pid: Number.parseInt(parsed.MainPID, 10) || null,
          uptime_since: parsed.ActiveEnterTimestamp || null,
          memory_mb: parseMemoryMb(parsed.MemoryUsageCurrent),
        };
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ services }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to fetch service status' }));
    }
    return;
  }

  if (path.startsWith('/api/ops/services/') && path.endsWith('/restart') && req.method === 'POST') {
    const service = decodeURIComponent(path.split('/')[4] || '');
    if (!OPS_SERVICES.includes(service)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid service name' }));
      return;
    }
    const started = Date.now();
    try {
      execSync(`sudo systemctl restart ${service}`, { timeout: 30000, stdio: ['ignore', 'pipe', 'pipe'] });
      const duration = Date.now() - started;
      logAction({ category: 'service', action: 'restart', target: service, status: 'success', detail: 'Service restarted', duration_ms: duration });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ service, status: 'success', duration_ms: duration, timestamp: new Date().toISOString() }));
    } catch (e) {
      const duration = Date.now() - started;
      logAction({ category: 'service', action: 'restart', target: service, status: 'failed', detail: truncateOutput(e.stderr || e.message), duration_ms: duration });
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to restart service' }));
    }
    return;
  }

  if (path === '/api/ops/sessions/fresh' && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      if (body.confirm !== true) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Confirmation required. Send { confirm: true } to proceed.' }));
        return;
      }
      const started = Date.now();
      try {
        execSync('sudo systemctl restart openclaw', { timeout: 30000, stdio: ['ignore', 'pipe', 'pipe'] });
        const duration = Date.now() - started;
        logAction({ category: 'session', action: 'fresh_session', target: 'openclaw', status: 'success', detail: 'Fresh session triggered', duration_ms: duration });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'success', timestamp: new Date().toISOString() }));
      } catch (e) {
        const duration = Date.now() - started;
        logAction({ category: 'session', action: 'fresh_session', target: 'openclaw', status: 'failed', detail: truncateOutput(e.stderr || e.message), duration_ms: duration });
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Failed to start fresh session' }));
      }
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
    return;
  }

  if (path === '/api/ops/crons' && req.method === 'GET') {
    try {
      const jobs = parseCronEntries();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ jobs }));
    } catch {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to list cron jobs' }));
    }
    return;
  }

  if (path.startsWith('/api/ops/crons/') && path.endsWith('/trigger') && req.method === 'POST') {
    const jobName = decodeURIComponent(path.split('/')[4] || '');
    const jobs = parseCronEntries();
    const job = jobs.find((j) => j.name === jobName);
    if (!job) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid cron job name' }));
      return;
    }

    const commandSpec = CRON_TRIGGER_ALLOWLIST.get(job.command);
    if (!commandSpec) {
      const detail = `Blocked non-allowlisted cron command for ${job.name}: ${job.command}`;
      logAction({ category: 'cron', action: 'trigger', target: job.name, status: 'blocked', detail, duration_ms: 0 });
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Cron job is not triggerable via API' }));
      return;
    }

    const started = Date.now();
    const result = spawnSync(commandSpec.command, commandSpec.args, {
      encoding: 'utf8',
      timeout: 60000,
      shell: false,
    });
    const duration = Date.now() - started;
    const output = truncateOutput((result.stdout || '') + (result.stderr || ''));
    const status = result.status === 0 ? 'success' : 'failed';
    logAction({ category: 'cron', action: 'trigger', target: job.name, status, detail: output, duration_ms: duration });
    res.writeHead(result.status === 0 ? 200 : 500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ name: job.name, exit_code: result.status ?? 1, output, duration_ms: duration }));
    return;
  }

  if (path === '/api/ops/backups' && req.method === 'POST') {
    try {
      const snapshot = createSnapshot();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(snapshot));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path === '/api/ops/backups' && req.method === 'GET') {
    try {
      const snapshots = listSnapshots();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ snapshots }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path.startsWith('/api/ops/backups/') && path.endsWith('/manifest') && req.method === 'GET') {
    const filename = decodeURIComponent(path.split('/')[4] || '');
    try {
      const manifest = getSnapshotManifest(filename);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(manifest));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path.startsWith('/api/ops/backups/') && path.endsWith('/restore') && req.method === 'POST') {
    const filename = decodeURIComponent(path.split('/')[4] || '');
    readJsonBody(req).then((body) => {
      if (body.confirm !== true) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Confirmation required. Send { confirm: true } to proceed.' }));
        return;
      }
      try {
        const result = restoreSnapshot(filename);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
    return;
  }

  if (path.startsWith('/api/ops/backups/') && req.method === 'DELETE') {
    const filename = decodeURIComponent(path.split('/')[4] || '');
    try {
      deleteSnapshot(filename);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ deleted: true, filename }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path === '/api/ops/cleanup' && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      const maxBackups = body.maxBackups ?? 10;
      const maxAgeDays = body.maxAgeDays ?? 30;
      const retainDays = body.retainDays ?? 90;
      try {
        const backupResult = enforceRetention(maxBackups, maxAgeDays);
        const pruned = pruneLog(retainDays);
        logAction({ category: 'cleanup', action: 'retention', target: 'ops', status: 'success', detail: `Deleted ${backupResult.deleted_count} backups; pruned ${pruned} log entries` });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ backups_deleted: backupResult.deleted_count, deleted_files: backupResult.deleted_files, log_entries_pruned: pruned }));
      } catch (e) {
        logAction({ category: 'cleanup', action: 'retention', target: 'ops', status: 'failed', detail: truncateOutput(e.message) });
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
    return;
  }

  if (path === '/api/ops/log' && req.method === 'GET') {
    try {
      const limit = Math.max(1, Math.min(200, Number.parseInt(url.searchParams.get('limit') || '50', 10)));
      const offset = Math.max(0, Number.parseInt(url.searchParams.get('offset') || '0', 10));
      const category = url.searchParams.get('category') || null;
      const { entries, total } = getLog({ limit, offset, category });
      const stats = getLogStats();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ entries, total, stats: { total: stats.total, last_24h: stats.last_24h, last_7d: stats.last_7d, most_recent_timestamp: stats.most_recent_timestamp } }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to fetch operations log' }));
    }
    return;
  }

  if (path === '/api/ops/gateway-events' && req.method === 'GET') {
    try {
      const limitRaw = Number.parseInt(url.searchParams.get('limit') || '50', 10);
      const limit = Math.max(1, Math.min(200, Number.isFinite(limitRaw) ? limitRaw : 50));

      if (!existsSync(API_LIVENESS_LOG_PATH)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ events: [] }));
        return;
      }

      const lines = readFileSync(API_LIVENESS_LOG_PATH, 'utf8')
        .split('\n')
        .map(line => line.trim())
        .filter(Boolean);

      if (lines.length === 0) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ events: [] }));
        return;
      }

      const events = lines
        .slice(-limit)
        .reverse()
        .map((line) => {
          const match = line.match(/^\[([^\]]+)\]\s*(.*)$/);
          if (!match) return null;
          return {
            timestamp: match[1],
            message: match[2] || '',
          };
        })
        .filter(Boolean);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ events }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path === '/api/ops/monitoring-layers' && req.method === 'GET') {
    try {
      const now = Date.now();
      const buildLayer = (name, filePath, staleThresholdSeconds, extra = {}) => {
        if (!existsSync(filePath)) {
          return { name, last_success_at: null, age_seconds: null, status: 'red', source_available: false, ...extra };
        }
        try {
          const payload = JSON.parse(readFileSync(filePath, 'utf8'));
          const lastSuccessAt = payload?.last_finished_at || payload?.last_success_at || null;
          const parsed = parseIsoSafe(lastSuccessAt);
          if (!parsed) {
            return { name, last_success_at: null, age_seconds: null, status: 'red', source_available: false, ...extra };
          }
          const ageSeconds = Math.max(0, Math.floor((now - parsed) / 1000));
          return {
            name,
            last_success_at: lastSuccessAt,
            age_seconds: ageSeconds,
            status: ageSeconds < staleThresholdSeconds ? 'green' : 'amber',
            source_available: true,
            ...extra,
          };
        } catch {
          return { name, last_success_at: null, age_seconds: null, status: 'red', source_available: false, ...extra };
        }
      };

      const pulseRaw = readJsonSafe(OPS_PULSE_STATE_PATH, {});
      const sweepRaw = readJsonSafe(OPS_SWEEP_STATUS_PATH, {});
      const auditRaw = readJsonSafe(OPS_AUDIT_STATUS_PATH, {});
      const pulse = buildLayer('Pulse', OPS_PULSE_STATE_PATH, 10 * 60, {
        consecutive_failures: Number(pulseRaw?.consecutive_failures || 0),
        last_restart_at: pulseRaw?.last_restart_at || null,
      });
      const sweep = buildLayer('Sweep', OPS_SWEEP_STATUS_PATH, 90 * 60, {
        last_check_count: Number(sweepRaw?.results?.length || 0),
      });
      const audit = buildLayer('Audit', OPS_AUDIT_STATUS_PATH, 26 * 60 * 60, {
        last_run_duration_ms: Number(auditRaw?.duration_ms || 0),
      });

      let heartbeatCount = 0;
      try {
        const journalRaw = execSync('journalctl -u openclaw.service --since "60 minutes ago" --no-pager -q', {
          encoding: 'utf8',
          timeout: 30000,
          stdio: ['ignore', 'pipe', 'pipe'],
        });
        heartbeatCount = (journalRaw.match(/heartbeat/gi) || []).length;
      } catch {
        heartbeatCount = 0;
      }
      const heartbeat = {
        name: 'Heartbeat',
        status: heartbeatCount > 0 ? 'green' : 'amber',
        age_seconds: null,
        last_success_at: null,
        gateway_dependent: true,
        heartbeat_count_last_60m: heartbeatCount,
        note: 'Gateway-dependent',
        source_available: true,
      };

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ layers: [pulse, sweep, audit, heartbeat] }));
    } catch (e) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ layers: [] }));
    }
    return;
  }

  if (path === '/api/ops/kill-switches' && req.method === 'GET') {
    const stateRaw = readJsonSafe(OPS_KILL_SWITCHES_PATH, {});
    const stateWithAge = {};
    for (const [name, value] of Object.entries(stateRaw || {})) {
      const item = (value && typeof value === 'object') ? { ...value } : {};
      const age = item.active ? ageSecondsFromIso(item.activated_at) : null;
      stateWithAge[name] = { ...item, age_seconds: age };
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ switches: stateWithAge }));
    return;
  }

  if (path.startsWith('/api/ops/kill-switches/') && path.endsWith('/clear') && req.method === 'POST') {
    const name = decodeURIComponent(path.split('/')[4] || '');
    if (!OPS_KILL_SWITCH_NAMES.has(name)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unknown kill switch name' }));
      return;
    }
    const switches = readJsonSafe(OPS_KILL_SWITCHES_PATH, {});
    const next = { ...(switches && typeof switches === 'object' ? switches : {}) };
    next[name] = { active: false, reason: null, activated_at: null, activated_by: null };
    try {
      writeJsonAtomic(OPS_KILL_SWITCHES_PATH, next);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ switches: next }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to write kill switch state' }));
    }
    return;
  }

  if (path === '/api/ops/recovery-log' && req.method === 'GET') {
    const items = [];
    if (existsSync(OPS_RECOVERY_LOG_PATH)) {
      for (const line of readFileSync(OPS_RECOVERY_LOG_PATH, 'utf8').split('\n').filter(Boolean)) {
        try {
          items.push(JSON.parse(line));
        } catch {
          // ignore malformed lines
        }
      }
    }
    const entries = items
      .sort((a, b) => (parseIsoSafe(b?.timestamp) || 0) - (parseIsoSafe(a?.timestamp) || 0))
      .slice(0, 50);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ entries }));
    return;
  }

  if (path === '/api/ops/doctor' && req.method === 'GET') {
    const statusPayload = readJsonSafe(OPS_DOCTOR_STATUS_PATH, { generated_at: null, exit_code: null, sections: [] });
    const suppressed = readJsonSafe(OPS_DOCTOR_SUPPRESSED_PATH, {});
    const merged = mergeDoctorSuppressions(statusPayload, suppressed);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ...merged, suppressed }));
    return;
  }

  if (path === '/api/ops/doctor/run' && req.method === 'POST') {
    try {
      const payload = runOpenclawDoctor(['timeout', '60', 'openclaw', 'doctor', '--non-interactive'], 65000);
      writeJsonAtomic(OPS_DOCTOR_STATUS_PATH, {
        generated_at: payload.generated_at,
        exit_code: payload.exit_code,
        sections: payload.sections,
      });
      const suppressed = readJsonSafe(OPS_DOCTOR_SUPPRESSED_PATH, {});
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(mergeDoctorSuppressions(payload, suppressed)));
    } catch (e) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ generated_at: new Date().toISOString(), exit_code: 1, sections: [], error: e.message }));
    }
    return;
  }

  if (path === '/api/ops/doctor/suppress' && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      const finding = String(body?.finding || '').trim();
      const reason = String(body?.reason || '').trim();
      if (!finding || !reason) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'finding and reason are required' }));
        return;
      }
      const suppressed = readJsonSafe(OPS_DOCTOR_SUPPRESSED_PATH, {});
      suppressed[finding] = {
        suppressed_at: new Date().toISOString(),
        suppressed_by: 'dashboard',
        reason,
        expires_at: null,
      };
      writeJsonAtomic(OPS_DOCTOR_SUPPRESSED_PATH, suppressed);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ suppressed }));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
    return;
  }

  if (path === '/api/ops/doctor/unsuppress' && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      const finding = String(body?.finding || '').trim();
      if (!finding) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'finding is required' }));
        return;
      }
      const suppressed = readJsonSafe(OPS_DOCTOR_SUPPRESSED_PATH, {});
      delete suppressed[finding];
      writeJsonAtomic(OPS_DOCTOR_SUPPRESSED_PATH, suppressed);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ suppressed }));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
    return;
  }

  if (path === '/api/ops/doctor/prepare-repair' && req.method === 'POST') {
    const payload = runOpenclawDoctor(['timeout', '60', 'openclaw', 'doctor', '--non-interactive'], 65000);
    const token = randomBytes(4).toString('hex');
    doctorRepairTokens.set(token, Date.now() + 5 * 60 * 1000);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      confirmation_token: token,
      confirmation_token_expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      command: 'openclaw doctor --repair',
      sections: payload.sections,
    }));
    return;
  }

  if (path === '/api/ops/doctor/execute-repair' && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      const confirmationToken = String(body?.confirmation_token || '');
      const typedConfirmation = String(body?.typed_confirmation || '');
      const expiresAt = doctorRepairTokens.get(confirmationToken);
      if (!expiresAt || expiresAt < Date.now()) {
        if (confirmationToken) doctorRepairTokens.delete(confirmationToken);
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Confirmation token invalid or expired' }));
        return;
      }
      if (typedConfirmation !== 'REPAIR') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Typed confirmation must be REPAIR' }));
        return;
      }
      doctorRepairTokens.delete(confirmationToken);
      const payload = runOpenclawDoctor(['timeout', '90', 'openclaw', 'doctor', '--repair'], 95000);
      writeJsonAtomic(OPS_DOCTOR_STATUS_PATH, {
        generated_at: payload.generated_at,
        exit_code: payload.exit_code,
        sections: payload.sections,
      });
      const suppressed = readJsonSafe(OPS_DOCTOR_SUPPRESSED_PATH, {});
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(mergeDoctorSuppressions(payload, suppressed)));
    }).catch(() => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid JSON body' }));
    });
    return;
  }

  if (path === '/api/ops/integrity' && req.method === 'GET') {
    const hashes = readJsonSafe(OPS_CRITICAL_HASHES_PATH, { files: {}, generated_at: null });
    const auditStatus = readJsonSafe(OPS_AUDIT_STATUS_PATH, {});
    const driftResult = (Array.isArray(auditStatus?.results) ? auditStatus.results : [])
      .find((item) => item?.check === 'runtime_repo_drift')?.result || {};
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      hashes: {
        files: hashes?.files && typeof hashes.files === 'object' ? hashes.files : {},
        generated_at: hashes?.generated_at || null,
      },
      drift: {
        total_files_checked: Number(driftResult?.total_files_checked || 0),
        files_with_drift: Number(driftResult?.files_with_drift || 0),
        drifted_filenames: Array.isArray(driftResult?.drifted_filenames) ? driftResult.drifted_filenames : [],
      },
    }));
    return;
  }

  if (path === '/api/ops/version-check' && req.method === 'GET') {
    try {
      if (!existsSync(VERSION_CHECK_RESULTS_PATH)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'check_failed', error: 'Version check data unavailable' }));
        return;
      }

      const fileStat = statSync(VERSION_CHECK_RESULTS_PATH);
      const isStale = (Date.now() - fileStat.mtimeMs) > 2 * 60 * 60 * 1000;
      if (isStale) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'check_failed', error: 'Version check data unavailable' }));
        return;
      }

      const payload = JSON.parse(readFileSync(VERSION_CHECK_RESULTS_PATH, 'utf8'));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'check_failed', error: 'Version check data unavailable' }));
    }
    return;
  }

  if (path === '/api/ops/version-check/refresh' && req.method === 'POST') {
    const started = Date.now();
    try {
      execSync(VERSION_CHECK_SCRIPT_PATH, { timeout: 30000, stdio: ['ignore', 'pipe', 'pipe'] });
      const payload = JSON.parse(readFileSync(VERSION_CHECK_RESULTS_PATH, 'utf8'));
      const duration = Date.now() - started;
      logAction({
        category: 'version',
        action: 'refresh',
        target: 'check-openclaw-version.sh',
        status: 'success',
        detail: 'Version check refreshed',
        duration_ms: duration,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      const duration = Date.now() - started;
      logAction({
        category: 'version',
        action: 'refresh',
        target: 'check-openclaw-version.sh',
        status: 'failed',
        detail: truncateOutput(e.stderr || e.message),
        duration_ms: duration,
      });
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to refresh version check' }));
    }
    return;
  }

  function getVerificationEnvelope() {
    if (!existsSync(VERIFY_RESULTS_PATH)) {
      return {
        available: false,
        stale: false,
        age_seconds: null,
        results: null,
      };
    }

    const fileStat = statSync(VERIFY_RESULTS_PATH);
    const ageSeconds = Math.max(0, Math.floor((Date.now() - fileStat.mtimeMs) / 1000));
    const stale = ageSeconds > (24 * 60 * 60);
    const results = JSON.parse(readFileSync(VERIFY_RESULTS_PATH, 'utf8'));
    return {
      available: true,
      stale,
      age_seconds: ageSeconds,
      results,
    };
  }

  if (path === '/api/ops/verification' && req.method === 'GET') {
    try {
      const payload = getVerificationEnvelope();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Failed to read verification results: ${e.message}` }));
    }
    return;
  }

  if (path === '/api/ops/verification/run' && req.method === 'POST') {
    if (verificationRunning) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Verification already in progress' }));
      return;
    }

    verificationRunning = true;
    const started = Date.now();
    const sectionValue = (url.searchParams.get('sections') || '').trim();
    const sections = sectionValue ? sectionValue.split(',').map((section) => section.trim()).filter(Boolean) : [];
    const args = ['--json-only', '--no-color'];
    for (const section of sections) {
      args.push('--section', section);
    }

    try {
      execFileSync(VERIFY_SCRIPT_PATH, args, { timeout: 120000, stdio: ['ignore', 'pipe', 'pipe'] });
      const payload = getVerificationEnvelope();
      const duration = Date.now() - started;
      const summary = payload?.results?.summary || {};
      const detail = `pass=${summary.pass ?? 0}, fail=${summary.fail ?? 0}, warn=${summary.warn ?? 0}, skip=${summary.skip ?? 0}, total=${summary.total ?? 0}`;

      logAction({
        category: 'verification',
        action: 'run',
        target: 'verify-deployment.sh',
        status: 'success',
        detail,
        duration_ms: duration,
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      const duration = Date.now() - started;
      const errorDetail = truncateOutput(e.stderr || e.message);
      logAction({
        category: 'verification',
        action: 'run',
        target: 'verify-deployment.sh',
        status: 'failed',
        detail: errorDetail,
        duration_ms: duration,
      });

      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: `Verification failed: ${errorDetail}` }));
    } finally {
      verificationRunning = false;
    }
    return;
  }

  if (path === '/api/security/health' && req.method === 'GET') {
    try {
      if (!existsSync(SECURITY_HEALTH_RESULTS_PATH)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ overall_status: 'unknown', checks: [], stale: true }));
        return;
      }

      const data = JSON.parse(readFileSync(SECURITY_HEALTH_RESULTS_PATH, 'utf8'));
      const generatedAtRaw = data?.generated_at;
      const generatedAtMs = Date.parse(generatedAtRaw);
      const isStale = !generatedAtRaw || Number.isNaN(generatedAtMs) || (Date.now() - generatedAtMs > 30 * 60 * 1000);

      if (isStale) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ overall_status: 'unknown', checks: [], stale: true }));
        return;
      }

      if (generatedAtRaw !== lastStoredSecurityGeneratedAt && Array.isArray(data.checks)) {
        storeChecks(data.checks);
        lastStoredSecurityGeneratedAt = generatedAtRaw;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ...data, stale: false }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path === '/api/security/history' && req.method === 'GET') {
    try {
      const layer = url.searchParams.get('layer');
      if (!layer) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'layer query parameter is required' }));
        return;
      }
      const limit = Number.parseInt(url.searchParams.get('limit') || '50', 10);
      const rows = getSecurityHistory(layer, limit);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(rows));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path === '/api/security/gateway-trend' && req.method === 'GET') {
    try {
      const rows = getSecurityHistory('gateway-health', 200);
      const trend = rows
        .filter(row => row?.name === 'Gateway-Latency')
        .map(row => {
          let metadata = row?.metadata;
          if (typeof metadata === 'string') {
            try {
              metadata = JSON.parse(metadata);
            } catch {
              return null;
            }
          }
          if (!metadata || typeof metadata !== 'object') return null;

          const rss = Number(metadata.rss_mb);
          const response = Number(metadata.response_ms);
          const time = row?.checked_at;

          if (!time || !Number.isFinite(rss) || !Number.isFinite(response)) return null;
          return {
            time,
            rss_mb: rss,
            response_ms: response,
          };
        })
        .filter(Boolean)
        .sort((a, b) => new Date(a.time).getTime() - new Date(b.time).getTime());

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(trend));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path === '/api/security/transitions' && req.method === 'GET') {
    try {
      const limit = Number.parseInt(url.searchParams.get('limit') || '50', 10);
      const rows = getTransitions(limit);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(rows));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path === '/api/security/decisions' && req.method === 'GET') {
    try {
      const session_id = url.searchParams.get('session_id') || null;
      const task_id = url.searchParams.get('task_id') || null;
      const agent = url.searchParams.get('agent') || null;
      const decision = url.searchParams.get('decision') || null;
      const after = url.searchParams.get('after') || null;
      const before = url.searchParams.get('before') || null;
      const limit = Number.parseInt(url.searchParams.get('limit') || '50', 10);
      const offset = Number.parseInt(url.searchParams.get('offset') || '0', 10);
      const safeLimit = Math.max(1, Math.min(200, Number.isFinite(limit) ? limit : 50));
      const safeOffset = Math.max(0, Number.isFinite(offset) ? offset : 0);
      const { rows, total } = queryDecisions({
        session_id,
        task_id,
        agent,
        decision,
        after,
        before,
        limit: safeLimit,
        offset: safeOffset,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ rows, total, limit: safeLimit, offset: safeOffset }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path === '/api/security/decisions/stats' && req.method === 'GET') {
    try {
      const after = url.searchParams.get('after') || null;
      const before = url.searchParams.get('before') || null;
      const stats = getDecisionStats({ after, before });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(stats));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path === '/api/security/recheck' && req.method === 'POST') {
    exec(SECURITY_CHECK_SCRIPT_PATH, { timeout: 30000 }, (error) => {
      if (error) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: error.message }));
        return;
      }

      try {
        const data = JSON.parse(readFileSync(SECURITY_HEALTH_RESULTS_PATH, 'utf8'));
        if (Array.isArray(data.checks)) {
          storeChecks(data.checks);
          if (data.generated_at) {
            lastStoredSecurityGeneratedAt = data.generated_at;
          }
        }
        logAction({
          category: 'security',
          action: 'security-recheck',
          target: 'security-health',
          status: 'success',
          detail: 'Security recheck triggered from dashboard',
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // POST /api/security/version-check
  // Manual version check: deletes cache and runs the version check portion
  // Returns fresh version check data
  if (path === '/api/security/version-check' && req.method === 'POST') {
    const cacheFile = '/tmp/security-version-cache.json';

    try { unlinkSync(cacheFile); } catch {}

    logAction({
      category: 'security',
      action: 'version_check_manual',
      target: 'openclaw-version',
      status: 'started',
      detail: 'Manual version check triggered from dashboard',
    });

    try {
      execSync(
        'FORCE_VERSION_CHECK=true /usr/local/bin/check-security-health.sh',
        { timeout: 60000, encoding: 'utf8' }
      );

      const data = JSON.parse(readFileSync('/tmp/security-health-results.json', 'utf8'));

      if (Array.isArray(data.checks)) {
        storeChecks(data.checks);
        if (data.generated_at) {
          lastStoredSecurityGeneratedAt = data.generated_at;
        }
      }

      logAction({
        category: 'security',
        action: 'version_check_manual',
        target: 'openclaw-version',
        status: 'success',
        detail: 'Manual version check completed',
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(data));
    } catch (e) {
      logAction({
        category: 'security',
        action: 'version_check_manual',
        target: 'openclaw-version',
        status: 'error',
        detail: `Manual version check failed: ${e.message}`,
      });
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path === '/api/security/update-openclaw' && req.method === 'POST') {
    try {
      logAction({
        category: 'security',
        action: 'update_openclaw_attempted',
        target: 'openclaw-version',
        status: 'success',
        detail: 'Button clicked, not yet implemented',
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        status: 'not_implemented',
        message: 'Automated updates coming soon. Run manually: cp ~/.openclaw/openclaw.json ~/.openclaw/openclaw.json.bak && npm update -g openclaw@latest && openclaw doctor'
      }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path === '/api/security/config-drift/ack' && req.method === 'POST') {
    try {
      if (!existsSync(OPENCLAW_CONFIG_PATH)) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'openclaw.json not found' }));
        return;
      }

      const config = JSON.parse(readFileSync(OPENCLAW_CONFIG_PATH, 'utf8'));
      const flattened = flattenConfigForDrift(config);
      writeFileSync(CONFIG_DRIFT_BASELINE_PATH, `${JSON.stringify(flattened, null, 2)}\n`, 'utf8');

      const timestamp = new Date().toISOString();
      logAction({
        category: 'security',
        action: 'config-drift-ack',
        target: 'config-drift-baseline',
        status: 'success',
        detail: 'Config drift acknowledged by dashboard operator',
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, keyCount: Object.keys(flattened).length, timestamp }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path === '/api/security/soul-hash/ack' && req.method === 'POST') {
    try {
      if (!existsSync(SOUL_MD_PATH)) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'SOUL.md not found' }));
        return;
      }

      const hash = createHash('sha256').update(readFileSync(SOUL_MD_PATH)).digest('hex');
      writeFileSync(SOUL_HASH_PATH, hash, 'utf8');
      const timestamp = new Date().toISOString();

      logAction({
        category: 'security',
        action: 'soul-hash-ack',
        target: 'SOUL.md',
        status: 'success',
        detail: 'SOUL.md hash baseline updated by dashboard operator',
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, hash: hash.slice(0, 12), timestamp }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path === '/api/security/memory-credentials' && req.method === 'GET') {
    try {
      const payload = getMemoryCached('security-memory-credentials', 60000, () => {
        const rows = getCredentialReviewRows();
        return {
          credentials: rows,
          count: rows.length,
          generatedAt: new Date().toISOString(),
        };
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path === '/api/security/memory-credentials/dismiss' && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      try {
        const factId = Number.parseInt(body?.factId, 10);
        const action = String(body?.action || '');
        if (!Number.isInteger(factId) || factId <= 0) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'factId must be a positive integer' }));
          return;
        }
        if (!['delete', 'allowlist'].includes(action)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'action must be delete or allowlist' }));
          return;
        }

        if (action === 'allowlist') {
          const ids = readCredentialAllowlist();
          ids.add(factId);
          writeCredentialAllowlist(ids);
          memoryApiCache.delete('security-memory-credentials');
          logAction({
            category: 'security',
            action: 'memory-credential-allowlist',
            target: 'facts.db',
            status: 'success',
            detail: `Allowlisted credential fact id=${factId}`,
          });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, factId, action }));
          return;
        }

        const db = openFactsDbWrite();
        try {
          const tx = db.transaction((id) => {
            db.prepare('DELETE FROM co_occurrences WHERE fact_a = ? OR fact_b = ?').run(id, id);
            const result = db.prepare('DELETE FROM facts WHERE id = ?').run(id);
            return result.changes;
          });
          const changes = tx(factId);
          if (!changes) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Fact not found' }));
            return;
          }
        } finally {
          db.close();
        }

        memoryApiCache.delete('security-memory-credentials');
        memoryApiCache.delete('stats');

        logAction({
          category: 'security',
          action: 'memory-credential-delete',
          target: 'facts.db',
          status: 'success',
          detail: `Deleted credential fact id=${factId}`,
        });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, factId, action }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    }).catch((e) => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    });
    return;
  }


  if (path === '/api/security/acknowledge' && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      try {
        const layer = body?.layer ? String(body.layer) : '';
        const note = body?.note ? String(body.note) : '';
        if (!layer) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'layer is required' }));
          return;
        }

        if (layer === 'reasoning') {
          const hash = execSync(`sha256sum ${SOUL_MD_PATH} | awk '{print $1}'`, { encoding: 'utf8' }).trim();
          writeFileSync(SOUL_HASH_PATH, hash, 'utf8');
          logAction({
            category: 'security',
            action: 'security-acknowledge',
            target: layer,
            status: 'success',
            detail: `Acknowledged ${layer}: ${note}`,
          });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: true, message: 'SOUL.md baseline updated' }));
          return;
        }

        logAction({
          category: 'security',
          action: 'security-acknowledge',
          target: layer,
          status: 'success',
          detail: `Acknowledged ${layer}: ${note}`,
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, message: `Acknowledged ${layer}` }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    }).catch((e) => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    });
    return;
  }

  if (path === '/api/security/test' && req.method === 'POST') {
    if (existsSync(SECURITY_TEST_LOCK_PATH)) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Test already running' }));
      return;
    }

    const command = (typeof process.getuid === 'function' && process.getuid() === 0)
      ? `su -s /bin/bash openclaw -c '${SECURITY_TEST_SCRIPT_PATH}'`
      : SECURITY_TEST_SCRIPT_PATH;

    exec(command, { timeout: 90000, maxBuffer: 1024 * 1024 * 2 }, (error, stdout, stderr) => {
      if (error) {
        const detail = (stderr || error.message || 'Security test failed').trim();
        logAction({
          category: 'security',
          action: 'security-test',
          target: 'active-probes',
          status: 'error',
          detail,
        });
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: detail }));
        return;
      }

      try {
        const data = JSON.parse(stdout);
        const passed = Number(data?.summary?.passed || 0);
        const failed = Number(data?.summary?.failed || 0);
        const warned = Number(data?.summary?.warned || 0);
        const summary = `${passed} passed, ${failed} failed${warned ? `, ${warned} warned` : ''}`;

        logAction({
          category: 'security',
          action: 'security-test',
          target: 'active-probes',
          status: 'success',
          detail: summary,
        });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
      } catch (e) {
        const detail = `Invalid test output: ${e.message}`;
        logAction({
          category: 'security',
          action: 'security-test',
          target: 'active-probes',
          status: 'error',
          detail,
        });
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: detail }));
      }
    });
    return;
  }

  if (path === '/api/security/test-results' && req.method === 'GET') {
    try {
      if (!existsSync(SECURITY_TEST_RESULTS_PATH)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ never_run: true }));
        return;
      }

      const data = JSON.parse(readFileSync(SECURITY_TEST_RESULTS_PATH, 'utf8'));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(data));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path === '/api/security/liveness' && req.method === 'GET') {
    try {
      if (!existsSync(API_LIVENESS_PATH)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ never_run: true }));
        return;
      }

      const data = JSON.parse(readFileSync(API_LIVENESS_PATH, 'utf8'));
      if (!data.checked_at && data.timestamp) data.checked_at = data.timestamp;
      const checkedAtMs = Date.parse(data?.checked_at);
      const stale = !data?.checked_at || Number.isNaN(checkedAtMs) || (Date.now() - checkedAtMs > 10 * 60 * 1000);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ...data, stale }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  // ── WATCHER API ─────────────────────────────────────────────
  if (path === '/api/watcher/health' && req.method === 'GET') {
    try {
      if (!existsSync(WATCHER_STATUS_PATH)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ available: false, stale: false, age_seconds: null, results: null }));
        return;
      }

      const raw = readFileSync(WATCHER_STATUS_PATH, 'utf8');
      const results = JSON.parse(raw);
      const stat = statSync(WATCHER_STATUS_PATH);
      const ageSeconds = Math.max(0, Math.floor((Date.now() - stat.mtimeMs) / 1000));
      const stale = ageSeconds > 15 * 60;

      try {
        if (results?.system_crons) {
          for (const cron of results.system_crons) {
            recordRun({
              job_id: cron.id,
              job_type: 'system',
              status: cron.status,
              started_at: cron.started_at || null,
              finished_at: cron.finished_at || null,
              duration_ms: cron.duration_ms ?? null,
              exit_code: cron.exit_code ?? null,
              heartbeat_version: cron.heartbeat_version || null,
              message: cron.message || null,
            });
          }
        }
        if (results?.gateway_crons) {
          for (const cron of results.gateway_crons) {
            recordRun({
              job_id: cron.id,
              job_type: 'gateway',
              status: cron.status,
              started_at: null,
              finished_at: null,
              duration_ms: cron.last_duration_ms ?? null,
              exit_code: null,
              heartbeat_version: null,
              message: cron.last_error || null,
            });
          }
        }

        const now = Date.now();
        if ((now - lastWatcherPruneAt) > 24 * 60 * 60 * 1000) {
          pruneOldRuns(7);
          lastWatcherPruneAt = now;
        }
      } catch (dbError) {
        console.error('[WATCHER] history ingestion failed:', dbError.message);
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        available: true,
        stale,
        age_seconds: ageSeconds,
        results,
      }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  const watcherHistoryMatch = path.match(/^\/api\/watcher\/history\/([^/]+)$/);
  if (watcherHistoryMatch && req.method === 'GET') {
    try {
      const jobId = decodeURIComponent(watcherHistoryMatch[1]);
      const limit = Math.max(1, Math.min(100, Number.parseInt(url.searchParams.get('limit'), 10) || 20));
      const runs = getWatcherHistory(jobId, limit);
      const stats = getJobStats(jobId);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ job_id: jobId, runs, stats }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  const watcherTrendsMatch = path.match(/^\/api\/watcher\/trends\/([^/]+)$/);
  if (watcherTrendsMatch && req.method === 'GET') {
    try {
      const jobId = decodeURIComponent(watcherTrendsMatch[1]);
      const hours = Math.max(1, Math.min(720, Number.parseInt(url.searchParams.get('hours'), 10) || 168));
      const dataPoints = getWatcherTrends(jobId, hours);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ job_id: jobId, hours, data_points: dataPoints }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path === '/api/watcher/config' && req.method === 'GET') {
    try {
      if (!existsSync(WATCHER_CONFIG_PATH)) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'WATCHER config not found' }));
        return;
      }
      const config = JSON.parse(readFileSync(WATCHER_CONFIG_PATH, 'utf8'));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(config));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  const watcherActionMatch = path.match(/^\/api\/watcher\/gateway\/([0-9a-f-]{36})\/(run|enable|disable)$/i);
  if (watcherActionMatch && req.method === 'POST') {
    const [, jobId, action] = watcherActionMatch;
    const isValidId = /^[0-9a-f-]{36}$/i.test(jobId);
    if (!isValidId) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid gateway job id' }));
      return;
    }

    const timeoutSeconds = action === 'run' ? 120 : 60;
    const actionVerb = action === 'run' ? 'run --force' : action;
    const command = `sudo -u openclaw timeout ${timeoutSeconds} /usr/bin/openclaw cron ${actionVerb} ${jobId} 2>&1`;
    const started = Date.now();

    exec(command, { timeout: timeoutSeconds * 1000, maxBuffer: 1024 * 1024 }, (error, stdout = '', stderr = '') => {
      const duration = Date.now() - started;
      const output = truncateOutput((stdout || stderr || error?.message || '').trim());
      const success = !error;

      logAction({
        category: 'watcher',
        action: `watcher-gateway-${action}`,
        target: jobId,
        status: success ? 'success' : 'failed',
        detail: output || `${action} ${success ? 'completed' : 'failed'}`,
        duration_ms: duration,
      });

      res.writeHead(success ? 200 : 500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success, output, duration_ms: duration }));
    });
    return;
  }

  if (path.startsWith('/api/watcher/gateway/') && req.method === 'POST') {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Invalid gateway job id or action' }));
    return;
  }


  if (path === '/api/goals' && req.method === 'GET') {
    try {
      getDb();
      const status = url.searchParams.get('status') || undefined;
      const goals = getAllGoals(status);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ goals }));
    } catch (e) {
      console.error('[API] /api/goals error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  if (path === '/api/goals' && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      const title = typeof body.title === 'string' ? body.title.trim() : '';
      if (!title || title.length > 200) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'title is required and must be <= 200 chars' }));
        return;
      }
      if (typeof body.description === 'string' && body.description.length > 2000) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'description must be <= 2000 chars' }));
        return;
      }
      try {
        const goal = createGoal(body);
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ goal }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message || 'Invalid goal payload' }));
      }
    }).catch((e) => {
      const code = e.message === 'Payload too large' ? 413 : 400;
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message === 'Payload too large' ? 'Payload too large' : 'Invalid JSON body' }));
    });
    return;
  }

  if (path.match(/^\/api\/goals\/\d+\/composition-status$/) && req.method === 'GET') {
    const goalId = Number(path.split('/')[3]);
    const result = getGoalCompositionStatus(goalId);
    if (!result) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Goal not found' }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
    return;
  }

  if (path.startsWith('/api/goals/') && path.endsWith('/tasks') && req.method === 'GET') {
    const segments = path.split('/');
    const goalId = Number.parseInt(segments[3], 10);
    if (!Number.isInteger(goalId) || goalId <= 0) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid goal id' }));
      return;
    }
    try {
      const goal = getGoalById(goalId);
      if (!goal) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Goal not found' }));
        return;
      }
      const tasks = getGoalTasks(goalId);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ tasks }));
    } catch (e) {
      console.error('[API] /api/goals/:id/tasks error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  if (path.startsWith('/api/goals/') && path.endsWith('/needs-tasks') && req.method === 'GET') {
    const segments = path.split('/');
    const goalId = Number.parseInt(segments[3], 10);
    if (!Number.isInteger(goalId) || goalId <= 0) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid goal id' }));
      return;
    }
    try {
      const goal = getGoalById(goalId);
      if (!goal) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Goal not found' }));
        return;
      }
      const advisory = goalNeedsTasks(goalId);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(advisory));
    } catch (e) {
      console.error('[API] /api/goals/:id/needs-tasks error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  if (path.startsWith('/api/goals/') && path.split('/').length === 4) {
    const goalId = Number.parseInt(path.split('/')[3], 10);
    if (!Number.isInteger(goalId) || goalId <= 0) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid goal id' }));
      return;
    }

    if (req.method === 'GET') {
      try {
        const goal = getGoalById(goalId);
        if (!goal) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Goal not found' }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ goal }));
      } catch (e) {
        console.error('[API] /api/goals/:id error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
      }
      return;
    }

    if (req.method === 'PATCH') {
      readJsonBody(req).then((body) => {
        const allowedFields = new Set(['title', 'description', 'status', 'assigned_agents', 'tasks_per_period', 'period', 'max_open_tasks']);
        const requestedKeys = Object.keys(body);
        const hasInvalidField = requestedKeys.some((key) => !allowedFields.has(key));
        if (hasInvalidField) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid fields in PATCH body' }));
          return;
        }
        if (typeof body.title === 'string' && body.title.trim().length > 200) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'title must be <= 200 chars' }));
          return;
        }
        if (typeof body.description === 'string' && body.description.length > 2000) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'description must be <= 2000 chars' }));
          return;
        }

        const goal = updateGoal(goalId, body);
        if (!goal) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Goal not found' }));
          return;
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ goal }));
      }).catch((e) => {
        const code = e.message === 'Payload too large' ? 413 : 400;
        res.writeHead(code, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message === 'Payload too large' ? 'Payload too large' : 'Invalid JSON body' }));
      });
      return;
    }

    if (req.method === 'DELETE') {
      try {
        const goal = archiveGoal(goalId);
        if (!goal) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Goal not found' }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ goal }));
      } catch (e) {
        console.error('[API] /api/goals/:id delete error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
      }
      return;
    }
  }


  if (path === '/api/workflows' && req.method === 'GET') {
    try {
      const templates = getAllTemplates();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ templates }));
    } catch (e) {
      console.error('[API] /api/workflows error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  if (path === '/api/workflows' && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      try {
        const template = createTemplate(body || {});
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ template }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message || 'Invalid template payload' }));
      }
    }).catch((e) => {
      const code = e.message === 'Payload too large' ? 413 : 400;
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message === 'Payload too large' ? 'Payload too large' : 'Invalid JSON body' }));
    });
    return;
  }

  if (path.match(/^\/api\/workflows\/[^/]+\/instantiate$/) && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      const templateId = decodeURIComponent(path.split('/')[3] || '');
      try {
        const result = instantiatePipeline({ template_id: templateId, ...(body || {}) });
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (e) {
        const code = e.message === 'Template not found' ? 404 : 400;
        res.writeHead(code, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    }).catch((e) => {
      const code = e.message === 'Payload too large' ? 413 : 400;
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message === 'Payload too large' ? 'Payload too large' : 'Invalid JSON body' }));
    });
    return;
  }

  if (path.startsWith('/api/workflows/') && path.split('/').length === 4) {
    const templateId = decodeURIComponent(path.split('/')[3] || '');

    if (req.method === 'GET') {
      const template = getTemplateById(templateId);
      if (!template) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Template not found' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ template }));
      return;
    }

    if (req.method === 'PUT') {
      readJsonBody(req).then((body) => {
        try {
          const template = updateTemplate(templateId, body || {});
          if (!template) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Template not found' }));
            return;
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ template }));
        } catch (e) {
          const code = e.message.includes('active pipeline instances') ? 409 : 400;
          res.writeHead(code, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
      }).catch((e) => {
        const code = e.message === 'Payload too large' ? 413 : 400;
        res.writeHead(code, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message === 'Payload too large' ? 'Payload too large' : 'Invalid JSON body' }));
      });
      return;
    }

    if (req.method === 'DELETE') {
      try {
        const result = deleteTemplate(templateId);
        if (!result.deleted) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Template not found' }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (e) {
        const code = e.message.includes('pipeline instances') ? 409 : 400;
        res.writeHead(code, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
      return;
    }
  }

  if (path === '/api/pipelines' && req.method === 'GET') {
    try {
      const status = url.searchParams.get('status') || undefined;
      const template_id = url.searchParams.get('template_id') || undefined;
      const limit = url.searchParams.get('limit') || undefined;
      const offset = url.searchParams.get('offset') || undefined;
      const pipelines = listPipelineInstances({ status, template_id, limit, offset });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ pipelines }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message || 'Invalid query params' }));
    }
    return;
  }

  if (path.startsWith('/api/pipelines/') && path.split('/').length === 5 && req.method === 'PATCH') {
    const parts = path.split('/');
    const pipelineId = decodeURIComponent(parts[3] || '');
    const action = parts[4] || '';
    const actionMap = {
      pause: { status: 'paused' },
      resume: { status: 'active' },
      'disable-auto': { auto_advance_enabled: 0 },
      'enable-auto': { auto_advance_enabled: 1 },
    };
    if (!actionMap[action]) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Route not found' }));
      return;
    }
    try {
      const pipeline = updatePipelineInstance(pipelineId, actionMap[action]);
      if (!pipeline) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Pipeline instance not found' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ pipeline }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  if (path.startsWith('/api/pipelines/') && path.endsWith('/state') && path.split('/').length === 5 && req.method === 'GET') {
    const pipelineId = decodeURIComponent(path.split('/')[3] || '');
    const pipeline = getPipelineInstance(pipelineId);
    if (!pipeline) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Pipeline instance not found' }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      current_step: pipeline.current_step,
      version: pipeline.version,
      status: pipeline.status,
      auto_advance_enabled: pipeline.auto_advance_enabled,
    }));
    return;
  }

  if (path.startsWith('/api/pipelines/') && path.split('/').length === 4) {
    const pipelineId = decodeURIComponent(path.split('/')[3] || '');
    if (req.method === 'GET') {
      const pipeline = getPipelineInstance(pipelineId);
      if (!pipeline) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Pipeline instance not found' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ pipeline }));
      return;
    }

    if (req.method === 'PATCH') {
      readJsonBody(req).then((body) => {
        try {
          const pipeline = updatePipelineInstance(pipelineId, body || {});
          if (!pipeline) {
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Pipeline instance not found' }));
            return;
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ pipeline }));
        } catch (e) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: e.message }));
        }
      }).catch((e) => {
        const code = e.message === 'Payload too large' ? 413 : 400;
        res.writeHead(code, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message === 'Payload too large' ? 'Payload too large' : 'Invalid JSON body' }));
      });
      return;
    }
  }

  if (path === '/api/kill-switches' && req.method === 'GET') {
    try {
      let killSwitches;
      try {
        killSwitches = JSON.parse(readFileSync(KILL_SWITCHES_PATH, 'utf8'));
      } catch {
        killSwitches = getKillSwitches();
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(killSwitches));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message || 'Failed to read kill switches' }));
    }
    return;
  }

  if (path === '/api/kill-switches/pipeline-auto-advance' && req.method === 'PUT') {
    readJsonBody(req).then((body) => {
      const active = body?.active === true;
      const reason = body?.reason == null ? null : String(body.reason);
      const activatedBy = body?.activated_by == null ? null : String(body.activated_by);
      const currentSwitches = getKillSwitches();
      const next = {
        ...currentSwitches,
        pipeline_auto_advance: {
          active,
          reason,
          activated_at: active ? new Date().toISOString() : null,
          activated_by: active ? (activatedBy || 'unknown') : null,
        },
      };
      try {
        writeKillSwitches(next);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(next));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message || 'Failed to write kill switch file' }));
      }
    }).catch((e) => {
      const code = e.message === 'Payload too large' ? 413 : 400;
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message === 'Payload too large' ? 'Payload too large' : 'Invalid JSON body' }));
    });
    return;
  }

  if (path === '/api/task-sessions' && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      try {
        const taskSession = createTaskSession(body || {});
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ task_session: taskSession }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    }).catch((e) => {
      const code = e.message === 'Payload too large' ? 413 : 400;
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message === 'Payload too large' ? 'Payload too large' : 'Invalid JSON body' }));
    });
    return;
  }

  if (path === '/api/task-sessions' && req.method === 'GET') {
    const taskId = url.searchParams.get('task_id') || '';
    if (!taskId.trim()) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'task_id query parameter required' }));
      return;
    }
    try {
      const sessions = getTaskSessions(taskId);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ sessions }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }


  if (path === '/api/tasks' && req.method === 'GET') {
    try {
      getDb();
      const status = url.searchParams.get('status') || undefined;
      const priority = url.searchParams.get('priority') || undefined;
      const assigned_agent = url.searchParams.get('assigned_agent') || undefined;
      const tasks = getAllTasks({ status, priority, assigned_agent });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ tasks }));
    } catch (e) {
      console.error('[API] /api/tasks error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  if (path === '/api/tasks/transitions' && req.method === 'GET') {
    try {
      const db = getDb();
      const transitions = db.prepare(`
        SELECT action, COUNT(*) as count
        FROM task_history
        GROUP BY action
        ORDER BY count DESC
        LIMIT 10
      `).all();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ transitions }));
    } catch (e) {
      console.error('[API] /api/tasks/transitions error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  if (path.match(/^\/api\/tasks\/\d+\/artifacts$/) && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      const taskId = Number(path.split('/')[3]);
      const task = getTaskById(taskId);
      if (!task) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Task not found' }));
        return;
      }
      if (!body.artifact_type || !body.content || !body.transition || !body.created_by) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Missing required fields: artifact_type, content, transition, created_by' }));
        return;
      }
      const validTransitions = ['in_progress->review', 'review->done'];
      if (!validTransitions.includes(body.transition)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid transition. Must be: in_progress->review or review->done' }));
        return;
      }
      try {
        const artifact = createArtifact({
          task_id: taskId,
          artifact_type: body.artifact_type,
          content: typeof body.content === 'string' ? body.content : JSON.stringify(body.content),
          created_by: body.created_by,
          transition: body.transition,
        });
        addAuditEntry({
          task_id: taskId,
          action: 'artifact_submitted',
          actor: body.created_by,
          details: { artifact_type: body.artifact_type, artifact_id: artifact.id, transition: body.transition },
        });
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ artifact }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    }).catch((e) => {
      const code = e.message === 'Payload too large' ? 413 : 400;
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    });
    return;
  }

  if (path.match(/^\/api\/tasks\/\d+\/artifacts$/) && req.method === 'GET') {
    const taskId = Number(path.split('/')[3]);
    const task = getTaskById(taskId);
    if (!task) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Task not found' }));
      return;
    }
    const transition = url.searchParams.get('transition') || null;
    const artifacts = getArtifacts(taskId, transition);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ artifacts }));
    return;
  }

  if (path.match(/^\/api\/tasks\/\d+\/claim$/) && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      const taskId = Number(path.split('/')[3]);
      if (!body.agent_id) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'agent_id required' }));
        return;
      }
      const timeout = Number(body.timeout_hours) || 4;
      const result = claimTask(taskId, body.agent_id, timeout);
      if (!result.ok) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
      }
      addAuditEntry({
        task_id: taskId,
        action: 'claimed',
        actor: body.agent_id,
        details: { expires_at: result.expires_at },
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    }).catch((e) => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    });
    return;
  }

  if (path.match(/^\/api\/tasks\/\d+\/claim$/) && req.method === 'PUT') {
    readJsonBody(req).then((body) => {
      const taskId = Number(path.split('/')[3]);
      if (!body.agent_id) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'agent_id required' }));
        return;
      }
      const timeout = Number(body.timeout_hours) || 4;
      const result = refreshClaim(taskId, body.agent_id, timeout);
      if (!result.ok) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    }).catch((e) => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    });
    return;
  }

  if (path.match(/^\/api\/tasks\/\d+\/claim$/) && req.method === 'DELETE') {
    readJsonBody(req).then((body) => {
      const taskId = Number(path.split('/')[3]);
      if (!body.agent_id) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'agent_id required' }));
        return;
      }
      const result = releaseClaim(taskId, body.agent_id);
      if (!result.ok) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
      }
      addAuditEntry({
        task_id: taskId,
        action: 'claim_released',
        actor: body.agent_id,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    }).catch((e) => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    });
    return;
  }

  if (path.match(/^\/api\/tasks\/\d+\/handoffs$/) && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      const taskId = Number(path.split('/')[3]);
      const task = getTaskById(taskId);
      if (!task) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Task not found' }));
        return;
      }
      try {
        const handoff = createHandoff({ task_id: taskId, ...body });
        addAuditEntry({
          task_id: taskId,
          action: 'handoff_created',
          actor: body.from_agent || 'unknown',
          details: { handoff_id: handoff.id, to_agent: body.to_agent, checkpoint_id: body.checkpoint_id || null },
        });
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ handoff }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    }).catch((e) => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    });
    return;
  }

  if (path.match(/^\/api\/tasks\/\d+\/handoffs$/) && req.method === 'GET') {
    const taskId = Number(path.split('/')[3]);
    const task = getTaskById(taskId);
    if (!task) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Task not found' }));
      return;
    }
    const handoffs = getHandoffs(taskId);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ handoffs }));
    return;
  }

  if (path.match(/^\/api\/handoffs\/\d+$/) && req.method === 'PATCH') {
    readJsonBody(req).then((body) => {
      const handoffId = Number(path.split('/')[3]);
      if (!body.status) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'status required (accepted, rejected, superseded)' }));
        return;
      }
      try {
        const handoff = resolveHandoff(handoffId, body.status);
        if (!handoff) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Handoff not found' }));
          return;
        }
        addAuditEntry({
          task_id: handoff.task_id,
          action: 'handoff_resolved',
          actor: body.actor || 'unknown',
          details: { handoff_id: handoff.id, status: body.status },
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ handoff }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    }).catch((e) => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    });
    return;
  }

  if (path.match(/^\/api\/tasks\/\d+\/checkpoints$/) && req.method === 'GET') {
    const taskId = Number(path.split('/')[3]);
    const task = getTaskById(taskId);
    if (!task) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Task not found' }));
      return;
    }
    const checkpoints = getCheckpoints(taskId);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ checkpoints }));
    return;
  }

  if (path.match(/^\/api\/tasks\/\d+\/intent$/) && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      const taskId = Number(path.split('/')[3]);
      try {
        const result = updateIntent(taskId, body);
        addAuditEntry({
          task_id: taskId,
          action: 'intent_updated',
          actor: body.changed_by,
          details: { version: result.version, change_reason: body.change_reason },
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (e) {
        const code = e.message === 'Task not found' ? 404 : 400;
        res.writeHead(code, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    }).catch((e) => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    });
    return;
  }

  if (path.match(/^\/api\/tasks\/\d+\/intent-history$/) && req.method === 'GET') {
    const taskId = Number(path.split('/')[3]);
    const task = getTaskById(taskId);
    if (!task) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Task not found' }));
      return;
    }
    const history = getIntentHistory(taskId);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ intent_history: history }));
    return;
  }

  if (path.match(/^\/api\/tasks\/\d+\/audit$/) && req.method === 'GET') {
    const taskId = Number(path.split('/')[3]);
    const task = getTaskById(taskId);
    if (!task) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Task not found' }));
      return;
    }
    const trail = getAuditTrail(taskId);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ audit: trail }));
    return;
  }

  if (path === '/api/task-types' && req.method === 'GET') {
    const configs = getTaskTypeConfigs();
    if (!configs) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ types: {} }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(configs));
    return;
  }

  if (path.match(/^\/api\/tasks\/\d+\/artifact-gate$/) && req.method === 'GET') {
    const taskId = Number(path.split('/')[3]);
    const task = getTaskById(taskId);
    if (!task) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Task not found' }));
      return;
    }
    const transition = url.searchParams.get('transition');
    if (!transition) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'transition query parameter required' }));
      return;
    }
    const gate = checkArtifactGate(taskId, transition, task.task_type);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      task_id: taskId, task_type: task.task_type, transition, ...gate,
    }));
    return;
  }

  if (path === '/api/tasks/next' && req.method === 'GET') {
    try {
      getDb();
      const agent = url.searchParams.get('agent') || null;
      const task = getNextTask(agent);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ task: task || null }));
    } catch (e) {
      console.error('[API] /api/tasks/next error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  if (path === '/api/tasks/stats' && req.method === 'GET') {
    try {
      getDb();
      const stats = getTaskStats();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(stats));
    } catch (e) {
      console.error('[API] /api/tasks/stats error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  if (path === '/api/tasks/scratch-summary' && req.method === 'GET') {
    try {
      getDb();
      const agent = url.searchParams.get('agent') || null;
      const summary = getCurrentTaskSummary(agent);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ summary }));
    } catch (e) {
      console.error('[API] /api/tasks/scratch-summary error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  if (path === '/api/tasks' && req.method === 'POST') {
    readJsonBody(req).then((body) => {
      const title = typeof body.title === 'string' ? body.title.trim() : '';
      if (!title || title.length > 100) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'title is required and must be <= 100 chars' }));
        return;
      }

      try {
        const task = createTask(body);
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ task }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message || 'Invalid task payload' }));
      }
    }).catch((e) => {
      const code = e.message === 'Payload too large' ? 413 : 400;
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message === 'Payload too large' ? 'Payload too large' : 'Invalid JSON body' }));
    });
    return;
  }

  if (path.startsWith('/api/tasks/') && path.endsWith('/dispatch') && req.method === 'POST') {
    const segments = path.split('/');
    const taskId = Number.parseInt(segments[3], 10);
    if (!Number.isInteger(taskId) || taskId <= 0) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid task id' }));
      return;
    }

    try {
      const task = getTaskById(taskId);
      if (!task) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Task not found' }));
        return;
      }

      if (task.status !== 'backlog') {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Only backlog tasks can be dispatched' }));
        return;
      }

      const inProgressTasks = getAllTasks({ status: 'in_progress' })
        .slice()
        .sort((a, b) => Date.parse(a.updated_at) - Date.parse(b.updated_at) || a.id - b.id);
      const queuedBehindTask = inProgressTasks[0] || null;
      const hasRunningTask = Boolean(queuedBehindTask);

      updateTask(taskId, { status: 'in_progress' });
      addHistory(taskId, 'system', 'dispatch', 'Task dispatched');

      const response = {
        dispatched: true,
        triggered: !hasRunningTask,
        task_id: taskId,
      };
      if (hasRunningTask) {
        response.queued_behind = queuedBehindTask.id;
      }

      if (!hasRunningTask) {
        try {
          const child = spawn('openclaw', ['cron', 'run', 'e6981a1c-70cf-48d0-8b51-a5855aeaa972'], {
            detached: true,
            stdio: 'ignore',
            
          });
              child.unref();
        } catch (e) {
          response.trigger_error = true;
          response.error = truncateOutput((e.stderr || '') || (e.stdout || '') || e.message || 'Cron trigger failed');
        }
      }

      logAction({
        category: 'task',
        action: 'dispatch',
        target: task.title,
        status: response.trigger_error ? 'failed' : 'success',
        detail: JSON.stringify(response),
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(response));
    } catch (e) {
      console.error('[API] /api/tasks/:id/dispatch error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  if (path.startsWith('/api/tasks/') && path.endsWith('/failures') && req.method === 'GET') {
    const segments = path.split('/');
    const taskId = Number.parseInt(segments[3], 10);
    if (!Number.isInteger(taskId) || taskId <= 0) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid task id' }));
      return;
    }

    try {
      const failures = getTaskFailures(taskId);
      if (!failures) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Task not found' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(failures));
    } catch (e) {
      console.error('[API] /api/tasks/:id/failures error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  if (path.startsWith('/api/tasks/') && path.endsWith('/fail') && req.method === 'POST') {
    const segments = path.split('/');
    const taskId = Number.parseInt(segments[3], 10);
    if (!Number.isInteger(taskId) || taskId <= 0) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid task id' }));
      return;
    }

    readJsonBody(req).then((body) => {
      const reason = typeof body.reason === 'string' ? body.reason.trim() : '';
      if (!reason) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'reason is required' }));
        return;
      }

      const result = recordFailure(taskId, reason);
      if (!result) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Task not found' }));
        return;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    }).catch((e) => {
      const code = e.message === 'Payload too large' ? 413 : 400;
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message === 'Payload too large' ? 'Payload too large' : 'Invalid JSON body' }));
    });
    return;
  }

  if (path.startsWith('/api/tasks/') && path.endsWith('/reset-retries') && req.method === 'PATCH') {
    const segments = path.split('/');
    const taskId = Number.parseInt(segments[3], 10);
    if (!Number.isInteger(taskId) || taskId <= 0) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid task id' }));
      return;
    }

    try {
      const task = resetTaskRetries(taskId);
      if (!task) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Task not found' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ task }));
    } catch (e) {
      console.error('[API] /api/tasks/:id/reset-retries error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  if (path.startsWith('/api/tasks/') && path.endsWith('/history')) {
    const segments = path.split('/');
    const taskId = Number.parseInt(segments[3], 10);
    if (!Number.isInteger(taskId) || taskId <= 0) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid task id' }));
      return;
    }

    if (req.method === 'GET') {
      try {
        const history = getHistory(taskId);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ history }));
      } catch (e) {
        console.error('[API] /api/tasks/:id/history error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
      }
      return;
    }

    if (req.method === 'POST') {
      readJsonBody(req).then((body) => {
        const actor = typeof body.actor === 'string' && body.actor.trim() ? body.actor.trim() : null;
        const action = typeof body.action === 'string' && body.action.trim() ? body.action.trim() : null;
        if (!actor || !action) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'actor and action are required' }));
          return;
        }
        const task = getTaskById(taskId);
        if (!task) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Task not found' }));
          return;
        }
        const entry = addHistory(taskId, actor, action, body.detail ?? '');
        res.writeHead(201, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ entry }));
      }).catch((e) => {
        const code = e.message === 'Payload too large' ? 413 : 400;
        res.writeHead(code, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message === 'Payload too large' ? 'Payload too large' : 'Invalid JSON body' }));
      });
      return;
    }
  }


  if (path === '/api/tasks/overdue' && req.method === 'GET') {
    try {
      const overdue = getOverdueTasks();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ tasks: overdue }));
    } catch (e) {
      console.error('[API] /api/tasks/overdue error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  if (path === '/api/tasks/stale' && req.method === 'GET') {
    try {
      getDb();
      const softRaw = Number.parseInt(url.searchParams.get('soft_threshold') || '48', 10);
      const hardRaw = Number.parseInt(url.searchParams.get('hard_threshold') || '120', 10);
      const softThreshold = Number.isFinite(softRaw) && softRaw >= 1 ? softRaw : 48;
      const hardThreshold = Number.isFinite(hardRaw) && hardRaw >= 1 ? hardRaw : 120;
      const startedAt = Date.now();
      const result = getStaleTasks(softThreshold, hardThreshold);
      const duration = Date.now() - startedAt;
      logAction({
        category: 'staleness',
        action: 'query',
        target: 'tasks',
        status: 'success',
        detail: `Returned ${result.counts.total} stale tasks (soft=${result.counts.soft}, hard=${result.counts.hard}) thresholds=${softThreshold}/${hardThreshold}`,
        duration_ms: duration,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (e) {
      logAction({
        category: 'staleness',
        action: 'query',
        target: 'tasks',
        status: 'failed',
        detail: truncateOutput(e.message),
      });
      console.error('[API] /api/tasks/stale error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  if (path.startsWith('/api/tasks/') && path.split('/').length === 4) {
    const taskId = Number.parseInt(path.split('/')[3], 10);
    if (!Number.isInteger(taskId) || taskId <= 0) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid task id' }));
      return;
    }

    if (req.method === 'GET') {
      try {
        const task = getTaskById(taskId);
        if (!task) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Task not found' }));
          return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ task }));
      } catch (e) {
        console.error('[API] /api/tasks/:id error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
      }
      return;
    }

    if (req.method === 'PATCH') {
      readJsonBody(req).then((body) => {
        const current = getTaskById(taskId);
        if (!current) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Task not found' }));
          return;
        }

        const allowedFields = new Set([
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
          'source',
          'goal_id',
          'due_at',
          'delivery_channel',
          'execution_mode',
          'requested_via',
          'accepted_at',
          'user_notified_at',
          'task_type',
          'original_intent',
          'active_intent',
          'active_intent_version',
          'acceptance_criteria',
          'scoped_contribution',
          'non_goals',
          'claimed_by',
          'claimed_at',
          'claim_expires_at',
          'parent_checkpoint_id',
          'parent_intent_version',
          'stale_dependency',
        ]);
        const requestedKeys = Object.keys(body);
        const hasInvalidField = requestedKeys.some((key) => !allowedFields.has(key));
        if (hasInvalidField) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid fields in PATCH body' }));
          return;
        }
        if (typeof body.title === 'string' && body.title.trim().length > 100) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'title must be <= 100 chars' }));
          return;
        }
        if (typeof body.description === 'string' && body.description.length > 2000) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'description must be <= 2000 chars' }));
          return;
        }
        if (body.handoff_payload != null && String(body.handoff_payload).length > 2000) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'handoff_payload must be <= 2000 chars' }));
          return;
        }

        // Trivial guardrail
        if (body.task_type === 'trivial' && current.task_type !== 'trivial') {
          const conn = getDb();
          const hasChildren = conn.prepare("SELECT COUNT(*) as count FROM tasks WHERE depends_on LIKE '%' || ? || '%'").get(String(taskId));
          const dependencyIds = parseDependsOnIds(current.depends_on);
          if ((hasChildren?.count || 0) > 0 || dependencyIds.length > 0 || current.goal_id) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              error: 'trivial_guardrail',
              message: 'Tasks with children or goal linkage cannot be marked trivial',
            }));
            return;
          }
        }

        const source = typeof body.source === 'string' && body.source.trim() ? body.source.trim() : 'human';
        const targetStatus = typeof body.status === 'string' ? body.status : current.status;
        const targetDepends = Object.hasOwn(body, 'depends_on') ? body.depends_on : current.depends_on;
        const depIds = parseDependsOnIds(targetDepends);
        if (depIds.includes(taskId)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Task cannot depend on itself' }));
          return;
        }

        if (targetStatus === 'in_progress') {
          const allTasks = getAllTasks();
          const statusById = new Map(allTasks.map((task) => [task.id, task.status]));
          const blockedBy = depIds.filter((id) => {
            const depStatus = statusById.get(id);
            return depStatus !== 'done' && depStatus !== 'archive';
          });
          if (blockedBy.length) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Task is blocked by dependencies', blocked_by: blockedBy }));
            return;
          }
        }

        // Claim enforcement for backlog -> in_progress
        if (current.status === 'backlog' && targetStatus === 'in_progress') {
          const claimed = current.claimed_by;
          const claimExpires = current.claim_expires_at ? new Date(current.claim_expires_at).getTime() : 0;
          if (!claimed || claimExpires <= Date.now()) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              error: 'claim_required',
              message: 'Task must be claimed before moving to in_progress. POST /api/tasks/:id/claim first.',
            }));
            return;
          }
        }

        if (Object.hasOwn(body, 'status') && targetStatus !== current.status) {
          const validation = validateTransition(current.status, targetStatus, source);
          if (!validation.valid) {
            const validList = validation.validTransitions.join(', ');
            const message = `Cannot move from ${current.status} to ${targetStatus}. Valid next states: ${validList || 'none'}.`;
            addHistory(taskId, 'system', 'transition_rejected', `${current.status} -> ${targetStatus} (source: ${source})`);
            res.writeHead(409, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
              error: 'invalid_transition',
              current_status: current.status,
              requested_status: targetStatus,
              message,
              valid_transitions: validation.validTransitions,
            }));
            return;
          }
        }

        // Artifact gate enforcement (Phase 2)
        if (Object.hasOwn(body, 'status') && targetStatus !== current.status) {
          let gateTransition = null;
          if (current.status === 'in_progress' && targetStatus === 'review') {
            gateTransition = 'in_progress->review';
          } else if (current.status === 'review' && targetStatus === 'done') {
            gateTransition = 'review->done';
          }
          if (gateTransition) {
            const gate = checkArtifactGate(taskId, gateTransition, current.task_type);
            if (!gate.passed) {
              addAuditEntry({
                task_id: taskId,
                action: 'gate_rejected',
                from_status: current.status,
                to_status: targetStatus,
                actor: source || 'unknown',
                details: { transition: gateTransition, missing: gate.missing, required: gate.required },
              });
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({
                error: 'artifact_gate_failed',
                message: `Missing required artifacts for ${gateTransition}`,
                task_type: current.task_type,
                transition: gateTransition,
                missing_artifacts: gate.missing,
                required_artifacts: gate.required,
                submitted_artifacts: gate.submitted,
              }));
              return;
            }
          }
        }

        const updateBody = { ...body };
        delete updateBody.source;
        if (Object.hasOwn(updateBody, 'status') && targetStatus !== current.status) {
          updateBody.transitioned_by = source;
        }

        const task = updateTask(taskId, updateBody);

        if (current.status !== targetStatus) {
          addHistory(taskId, 'system', 'status_changed', `${current.status} -> ${targetStatus}`);
          addAuditEntry({
            task_id: taskId,
            action: 'status_changed',
            from_status: current.status,
            to_status: targetStatus,
            actor: source || 'unknown',
            details: { transitioned_by: source },
          });
        }

        // Checkpoint creation for gated transitions
        if (current.status !== targetStatus) {
          let gateTransition = null;
          if (current.status === 'in_progress' && targetStatus === 'review') {
            gateTransition = 'in_progress->review';
          } else if (current.status === 'review' && targetStatus === 'done') {
            gateTransition = 'review->done';
          }
          if (gateTransition) {
            const artifacts = getArtifacts(taskId, gateTransition);
            if (artifacts.length > 0) {
              const checkpoint = createCheckpoint({
                task_id: taskId,
                transition: gateTransition,
                artifact_ids: artifacts.map((a) => a.id),
                created_by: source || 'unknown',
              });
              addAuditEntry({
                task_id: taskId,
                action: 'checkpoint_created',
                from_status: current.status,
                to_status: targetStatus,
                actor: source || 'unknown',
                checkpoint_id: checkpoint.id,
                details: { artifact_count: artifacts.length },
              });
            }
          }
        }

        // Rollback handling: supersede checkpoints and flag stale dependencies
        if (current.status === 'review' && targetStatus === 'in_progress') {
          const checkpoints = getCheckpoints(taskId);
          const activeReviewCheckpoint = checkpoints.find((c) => c.status === 'active' && c.transition === 'in_progress->review');
          if (activeReviewCheckpoint) {
            supersedeCheckpoint(activeReviewCheckpoint.id, null);
            const flagged = flagStaleDependencies(taskId);
            if (flagged.length > 0) {
              addAuditEntry({
                task_id: taskId,
                action: 'stale_dependencies_flagged',
                from_status: current.status,
                to_status: targetStatus,
                actor: source || 'unknown',
                details: { flagged_task_ids: flagged, superseded_checkpoint: activeReviewCheckpoint.id },
              });
            }
          }
        }

        // Auto-advance pipeline (Stage 4A)
        if (current.status !== targetStatus && targetStatus === 'done' && task.group_id) {
          try {
            const advanceResult = tryAutoAdvance(taskId, targetStatus);
            if (advanceResult.advanced) {
              task.__auto_advance = advanceResult;
            }
          } catch (advanceError) {
            // Auto-advance failure must never block the status transition response
            console.error('[auto-advance] error:', advanceError.message);
          }
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ task }));
      }).catch((e) => {
        const code = e.message === 'Payload too large' ? 413 : 400;
        res.writeHead(code, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message === 'Payload too large' ? 'Payload too large' : 'Invalid JSON body' }));
      });
      return;
    }
  }

  // ── Create Agent ──
  if (path === '/api/create-agent' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > MAX_BODY_SIZE) { req.destroy(); return; } });
    req.on('end', async () => {
      try {
        const data = JSON.parse(body);
        const result = await createAgent(data);
        res.writeHead(result.ok ? 200 : 400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        // Reload collector config if agent was created
        if (result.ok) {
          setTimeout(() => { try { collector.loadConfig(); } catch {} }, 2000);
        }
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        console.error('[API] /api/create-agent error:', e.message);
        res.end(JSON.stringify({ ok: false, error: 'Agent creation failed', steps: ['❌ Internal error'] }));
      }
    });
    return;
  }

  // ── Security Audit ──
  if (path === '/api/security-audit' && req.method === 'GET') {
    try {
      const result = runSecurityAudit();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      console.error('[API] /api/security-audit error:', e.message);
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  // ── Crons ──
  if (path === '/api/crons' && req.method === 'GET') {
    try {
      const clawdbotBin = join(process.execPath, '..', 'clawdbot');
      const output = execFileSync(clawdbotBin, ['cron', 'list', '--json'], { encoding: 'utf8', stdio: 'pipe', timeout: 10000 });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(output);
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      console.error('[API] /api/crons error:', e.message);
      res.end(JSON.stringify({ error: 'Failed to list cron jobs' }));
    }
    return;
  }

  // ── Analytics ──
  if (path === '/api/analytics' && req.method === 'GET') {
    try {
      const range = url.searchParams.get('range') || '7';
      const agentFilter = url.searchParams.get('agent') || 'all';
      const result = getCachedOrCompute(`analytics:${range}:${agentFilter}`, () => getAnalytics(range, agentFilter));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      console.error('[API] error:', e.message); res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  // ── Token Analytics (granular breakdown) ──
  if (path === '/api/tokens' && req.method === 'GET') {
    try {
      const range = url.searchParams.get('range') || '7';
      const agentFilter = url.searchParams.get('agent') || 'all';
      const result = getCachedOrCompute(`tokens:${range}:${agentFilter}`, () => getTokenAnalytics(range, agentFilter));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      console.error('[API] error:', e.message); res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  // ── Costs Analytics ──
  if (path === '/api/costs/quota' && req.method === 'GET') {
    try {
      const costsData = computeCostsData();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(costsData.quota));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      console.error('[API] /api/costs/quota error:', e.message);
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  // ── Session Trace (Waterfall Data) ──
  if (path.startsWith('/api/session/') && path.endsWith('/trace') && req.method === 'GET') {
    try {
      const sessionKey = decodeURIComponent(path.split('/')[3]);
      const traceLimit = parseInt(url.searchParams.get('limit') || '500');
      const result = getSessionTrace(sessionKey, { limit: traceLimit });
      if (!result) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Session not found' }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      console.error('[API] error:', e.message); res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  // ── Traces (parent→child delegation trees) ──
  if (path === '/api/traces' && req.method === 'GET') {
    try {
      const result = getTraces();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      console.error('[API] error:', e.message); res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }


  // ── Chat Messages ──
  if (path === '/api/chat/messages' && req.method === 'GET') {
    try {
      const limit = Number.parseInt(url.searchParams.get('limit') || '100', 10);
      const after = url.searchParams.get('after');
      const result = getChatMessages({
        limit: Number.isFinite(limit) ? limit : 100,
        after: after || null,
      });
      result.agentStreaming = chatGatewayClient.isAgentStreaming();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      console.error('[API] /api/chat/messages error:', e.message);
      res.end(JSON.stringify({ error: 'Failed to load chat messages' }));
    }
    return;
  }

  // ── Chat Latest Message ──
  if (path === '/api/chat/latest' && req.method === 'GET') {
    try {
      const result = getLatestMessage();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      console.error('[API] /api/chat/latest error:', e.message);
      res.end(JSON.stringify({ error: 'Failed to load latest chat message' }));
    }
    return;
  }

  // ── Chat Send ──
  if (path === '/api/chat/send' && req.method === 'POST') {
    req.on('error', () => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Invalid request body' }));
    });

    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > MAX_BODY_SIZE) {
        req.destroy();
      }
    });

    req.on('end', async () => {
      try {
        const parsed = body ? JSON.parse(body) : {};
        const message = typeof parsed.message === 'string' ? parsed.message.trim() : '';
        if (!message) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Message is required' }));
          return;
        }

        await chatGatewayClient.sendMessage(message);
        console.log('✅ Chat message sent via gateway:', message.substring(0, 50));

        // Fire-and-forget: relay user message to Telegram so both sides stay in sync
        const TELEGRAM_RELAY = '/home/openclaw/.openclaw/workspace/send-to-telegram.sh';
        const safeMsg = message.replace(/'/g, "'\\''"); // escape single quotes for shell
        exec(`bash ${TELEGRAM_RELAY} '📱 ${safeMsg}'`, (err) => {
          if (err) console.error('⚠️ Telegram relay failed:', err.message);
          else console.log('✅ User message relayed to Telegram');
        });

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        console.error('❌ Chat send failed:', e.message);
        const status = e.message === 'Gateway not connected' ? 503 : 500;
        res.writeHead(status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: e.message || 'Failed to send message' }));
      }
    });
    return;
  }

  // ── List Sessions ──
  if (path === '/api/sessions' && req.method === 'GET') {
    try {
      const limit = parseInt(url.searchParams.get('limit') || '50');
      const offset = parseInt(url.searchParams.get('offset') || '0');
      const result = getAllSessions({ limit, offset });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      console.error('[API] error:', e.message); res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  // ── Session Events (paginated and filtered) ──
  if (path === '/api/sessions/events' && req.method === 'GET') {
    try {
      const range = url.searchParams.get('range') || '24h';
      const source = url.searchParams.get('source') || 'all';
      const page = parseInt(url.searchParams.get('page') || '1');
      const limit = parseInt(url.searchParams.get('limit') || String(EVENTS_PER_PAGE));

      const result = getSessionsEvents({ range, source, page, limit });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      console.error('[API] /api/sessions/events error:', e.message);
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }


  // ── Agent Detail ──
  if (path.startsWith('/api/agents/') && path.endsWith('/detail') && req.method === 'GET') {
    const agentId = path.split('/')[3];
    const result = getAgentDetail(agentId);
    if (!result) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Agent not found' }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
    return;
  }

  // ── Agent Detail page ──
  if (path.startsWith('/agent/')) {
    const fullPath = join(DIR, 'agent-detail.html');
    if (existsSync(fullPath)) {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
      });
      res.end(readFileSync(fullPath));
    } else {
      res.writeHead(404); res.end('Not found');
    }
    return;
  }


  if (path === '/cortex') {
    const fullPath = join(DIR, 'cortex.html');
    if (existsSync(fullPath)) {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
      });
      res.end(readFileSync(fullPath));
    } else {
      res.writeHead(404); res.end('Not found');
    }
    return;
  }

  if (path === '/memory') {
    const fullPath = join(DIR, 'memory.html');
    if (existsSync(fullPath)) {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
      });
      res.end(readFileSync(fullPath));
    } else {
      res.writeHead(404); res.end('Not found');
    }
    return;
  }

  // ── Agent Actions (stop/start/reset) ──
  if (path.startsWith('/api/agents/') && path.endsWith('/action') && req.method === 'POST') {
    const agentId = path.split('/')[3];
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > MAX_BODY_SIZE) { req.destroy(); return; } });
    req.on('end', async () => {
      try {
        const { action } = JSON.parse(body);
        const result = await handleAgentAction(agentId, action);
        res.writeHead(result.ok ? 200 : 400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        console.error('[API] agent action error:', e.message);
        res.end(JSON.stringify({ ok: false, error: 'Action failed' }));
      }
    });
    return;
  }


  if (path === '/api/cortex/status' && req.method === 'GET') {
    try {
      let quotaState = null;
      try {
        const qPath = join(OPENCLAW_DIR, 'workspace/cortex/quota-state.json');
        if (existsSync(qPath)) quotaState = JSON.parse(readFileSync(qPath, 'utf8'));
      } catch { /* ignore */ }
      const config = readCortexConfig();
      if (!config) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'cortex not configured', status: 404 }));
        return;
      }
      const payload = {
        version: config.version,
        ladder: Array.isArray(config.ladder) ? config.ladder : [],
        agentPins: config.agentPins && typeof config.agentPins === 'object' ? config.agentPins : {},
        scoring: { weights: config?.scoring?.weights && typeof config.scoring.weights === 'object' ? config.scoring.weights : {} },
        schedule: config.schedule && typeof config.schedule === 'object' ? config.schedule : {},
        quotaThresholds: config.quotaThresholds && typeof config.quotaThresholds === 'object' ? config.quotaThresholds : {},
        alerts: config.alerts && typeof config.alerts === 'object' ? config.alerts : {},
      };
      if (quotaState) payload.providerQuota = quotaState;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.error('[API] /api/cortex/status error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load cortex status' }));
    }
    return;
  }


  if (path === '/api/cortex/sentinel' && req.method === 'GET') {
    try {
      if (!existsSync(CORTEX_SENTINEL_STATUS_PATH)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          available: false,
          stale: false,
          age_seconds: null,
          status: null,
        }));
        return;
      }

      const fileStats = statSync(CORTEX_SENTINEL_STATUS_PATH);
      const ageSeconds = Math.max(0, Math.floor((Date.now() - fileStats.mtimeMs) / 1000));
      const stale = ageSeconds > (25 * 60 * 60);

      let sentinelPayload;
      try {
        sentinelPayload = JSON.parse(readFileSync(CORTEX_SENTINEL_STATUS_PATH, 'utf8'));
      } catch {
        sentinelPayload = null;
      }

      if (!sentinelPayload || typeof sentinelPayload !== 'object') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          available: false,
          stale,
          age_seconds: ageSeconds,
          status: null,
        }));
        return;
      }

      const checksObject = sentinelPayload.checks && typeof sentinelPayload.checks === 'object' ? sentinelPayload.checks : {};
      const checks = Object.values(checksObject);
      const rank = { info: 0, ok: 0, normal: 0, watch: 1, warn: 1, warning: 1, critical: 2 };
      const highest = checks.reduce((best, check) => {
        const severity = String(check?.status || check?.severity || sentinelPayload?.overall || 'unknown').toLowerCase();
        const score = rank[severity] ?? 0;
        if (!best || score > best.score) {
          return { score, severity };
        }
        return best;
      }, null);
      const alertCount = checks.filter((check) => {
        const severity = String(check?.status || check?.severity || 'ok').toLowerCase();
        return severity === 'warn' || severity === 'warning' || severity === 'critical';
      }).length;

      const overallRaw = String(sentinelPayload.overall || highest?.severity || 'unknown').toLowerCase();
      const overall = overallRaw === 'warning' ? 'warn' : overallRaw;

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        available: true,
        stale,
        age_seconds: ageSeconds,
        status: {
          value: overall || 'unknown',
          alertCount,
          checks: checksObject,
          asOf: parseIsoOrNull(sentinelPayload.timestamp),
        },
      }));
    } catch (e) {
      console.error('[API] /api/cortex/sentinel error:', e.message);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        available: false,
        stale: false,
        age_seconds: null,
        status: null,
      }));
    }
    return;
  }

  if (path === '/api/cortex/bypass-check' && req.method === 'GET') {
    try {
      const requestedWindow = Number(url.searchParams.get('window'));
      const windowMinutes = Math.min(120, Math.max(5, Number.isFinite(requestedWindow) ? requestedWindow : 30));
      const cutoff = new Date(Date.now() - windowMinutes * 60000).toISOString();
      const agentsDir = join(process.env.HOME || '/home/openclaw', '.openclaw', 'agents');

      let newestActiveSession = null;
      let newestActiveMtime = 0;
      let newestArchivedSession = null;
      let newestArchivedMtime = 0;

      if (existsSync(agentsDir)) {
        const agents = readdirSync(agentsDir, { withFileTypes: true }).filter((entry) => entry.isDirectory());
        for (const agent of agents) {
          const sessionsDir = join(agentsDir, agent.name, 'sessions');
          if (!existsSync(sessionsDir)) continue;

          const entries = readdirSync(sessionsDir, { withFileTypes: true });
          for (const entry of entries) {
            if (!entry.isDirectory() || entry.name === 'archive') continue;
            const jsonlPath = join(sessionsDir, entry.name, 'session.jsonl');
            if (!existsSync(jsonlPath)) continue;
            const stats = statSync(jsonlPath);
            if (stats.mtimeMs > newestActiveMtime) {
              newestActiveMtime = stats.mtimeMs;
              newestActiveSession = jsonlPath;
            }
          }

          const archiveDir = join(sessionsDir, 'archive');
          if (!existsSync(archiveDir)) continue;
          const archivedFiles = readdirSync(archiveDir, { withFileTypes: true }).filter((entry) => entry.isFile() && entry.name.endsWith('.jsonl'));
          for (const archived of archivedFiles) {
            const jsonlPath = join(archiveDir, archived.name);
            const stats = statSync(jsonlPath);
            if (stats.mtimeMs > newestArchivedMtime) {
              newestArchivedMtime = stats.mtimeMs;
              newestArchivedSession = jsonlPath;
            }
          }
        }
      }

      const sessionFile = newestActiveSession || newestArchivedSession;
      if (!sessionFile) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ bypasses: [], telemetry_healthy: false, reason: 'No session files found' }));
        return;
      }

      const lines = readFileSync(sessionFile, 'utf8').split('\n').filter(Boolean).slice(-500);
      const sessionTurns = [];
      for (const line of lines) {
        try {
          const entry = JSON.parse(line);
          if (!entry?.provider || !entry?.timestamp) continue;
          const turnMs = new Date(entry.timestamp).getTime();
          if (!Number.isFinite(turnMs)) continue;
          const turnIso = new Date(turnMs).toISOString();
          if (turnIso < cutoff) continue;
          sessionTurns.push({
            provider: String(entry.provider),
            modelId: entry.modelId ? String(entry.modelId) : 'unknown',
            timestamp: turnIso,
            id: entry.id ? String(entry.id) : null,
          });
        } catch {
          // ignore malformed lines
        }
      }

      let outcomeRows = [];
      if (existsSync(OUTCOME_DB_PATH)) {
        const db = openSqlite(OUTCOME_DB_PATH, { readonly: true });
        try {
          outcomeRows = db.prepare(
            'SELECT id, timestamp, chosen_provider, chosen_model FROM outcome_records WHERE timestamp >= ? ORDER BY timestamp ASC'
          ).all(cutoff);
        } finally {
          db.close();
        }
      }

      const outcomeTimestamps = outcomeRows
        .map((row) => new Date(row.timestamp).getTime())
        .filter((value) => Number.isFinite(value));
      const unmatchedTurns = sessionTurns.filter((turn) => {
        const turnMs = new Date(turn.timestamp).getTime();
        if (!Number.isFinite(turnMs)) return false;
        return !outcomeTimestamps.some((outcomeMs) => Math.abs(outcomeMs - turnMs) <= 10000);
      });

      const unmatchedByClass = {};
      for (const turn of unmatchedTurns) {
        const workloadClass = `${turn.provider}/${turn.modelId || 'unknown'}`;
        if (!unmatchedByClass[workloadClass]) {
          unmatchedByClass[workloadClass] = {
            workloadClass,
            provider: turn.provider,
            model: turn.modelId || 'unknown',
            count: 0,
            first_seen: turn.timestamp,
            last_seen: turn.timestamp,
          };
        }
        unmatchedByClass[workloadClass].count += 1;
        if (turn.timestamp < unmatchedByClass[workloadClass].first_seen) unmatchedByClass[workloadClass].first_seen = turn.timestamp;
        if (turn.timestamp > unmatchedByClass[workloadClass].last_seen) unmatchedByClass[workloadClass].last_seen = turn.timestamp;
      }

      const telemetryHealthy = outcomeRows.length > 0;
      const bypasses = telemetryHealthy
        ? Object.values(unmatchedByClass).map((row) => ({
            tier: row.count >= 5 ? 'confirmed' : 'suspected',
            workloadClass: row.workloadClass,
            provider: row.provider,
            model: row.model,
            count: row.count,
            window_minutes: windowMinutes,
            first_seen: row.first_seen,
            last_seen: row.last_seen,
          }))
        : [];

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        bypasses,
        telemetry_healthy: telemetryHealthy,
        session_file: sessionFile.replace(process.env.HOME || '/home/openclaw', '~'),
        session_turns_in_window: sessionTurns.length,
        outcome_records_in_window: outcomeRows.length,
        unmatched_count: unmatchedTurns.length,
        window_minutes: windowMinutes,
      }));
    } catch (e) {
      console.error('[API] /api/cortex/bypass-check error:', e.message);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ bypasses: [], telemetry_healthy: false, reason: e.message }));
    }
    return;
  }

  if (path === '/api/cortex/decisions' && req.method === 'GET') {
    try {
      const requestedLimit = parseInt(url.searchParams.get('limit') || '20', 10);
      const limit = Math.max(1, Math.min(Number.isFinite(requestedLimit) ? requestedLimit : 20, 200));
      const { lines, total } = tailJsonLines(CORTEX_LOG_PATH, limit * 3);
      const decisions = lines.filter(l => !l.event && (l.modelSelected || l.selectedModel || l.model));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ decisions: decisions.slice(-limit).reverse(), total }));
    } catch (e) {
      console.error('[API] /api/cortex/decisions error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load cortex decisions' }));
    }
    return;
  }

  if (path === '/api/cortex/outcomes' && req.method === 'GET') {
    try {
      const requestedLimit = parseInt(url.searchParams.get('limit') || '20', 10);
      const limit = Math.max(1, Math.min(Number.isFinite(requestedLimit) ? requestedLimit : 20, 200));
      if (!existsSync(OUTCOME_DB_PATH)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ outcomes: [] }));
        return;
      }
      const db = openSqlite(OUTCOME_DB_PATH, { readonly: true });
      try {
        const rows = db.prepare('SELECT * FROM outcome_records ORDER BY timestamp DESC LIMIT ?').all(limit);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ outcomes: rows }));
      } finally {
        db.close();
      }
    } catch (e) {
      console.error('[API] /api/cortex/outcomes error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load cortex outcomes' }));
    }
    return;
  }

  if (path === '/api/cortex/outcomes/stats' && req.method === 'GET') {
    try {
      const requestedPeriod = String(url.searchParams.get('period') || '24h');
      const periodHours = ({ '24h': 24, '7d': 168, '30d': 720 })[requestedPeriod] || 24;
      const period = ({ 24: '24h', 168: '7d', 720: '30d' })[periodHours] || '24h';
      if (!existsSync(OUTCOME_DB_PATH)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          period,
          summary: { total_decisions: 0, avg_reward: null, correction_rate: null, escalation_rate: null },
          byModel: [],
          byWorkType: [],
        }));
        return;
      }

      const sinceIso = new Date(Date.now() - (periodHours * 60 * 60 * 1000)).toISOString();
      const db = openSqlite(OUTCOME_DB_PATH, { readonly: true });
      try {
        const summary = db.prepare(`
          SELECT
            COUNT(*) as total_decisions,
            AVG(reward_score) as avg_reward,
            AVG(CASE WHEN followup_correction = 1 THEN 1.0 ELSE 0.0 END) as correction_rate,
            AVG(CASE WHEN escalated = 1 THEN 1.0 ELSE 0.0 END) as escalation_rate
          FROM outcome_records WHERE timestamp >= ?
        `).get(sinceIso);

        const byModel = db.prepare(`
          SELECT chosen_model, COUNT(*) as decision_count, AVG(reward_score) as avg_reward,
            AVG(CASE WHEN followup_correction = 1 THEN 1.0 ELSE 0.0 END) as correction_rate,
            AVG(CASE WHEN escalated = 1 THEN 1.0 ELSE 0.0 END) as escalation_rate
          FROM outcome_records WHERE timestamp >= ? GROUP BY chosen_model ORDER BY decision_count DESC
        `).all(sinceIso);

        const byWorkType = db.prepare(`
          SELECT json_extract(policy_input, '$.workType') as work_type, COUNT(*) as decision_count, AVG(reward_score) as avg_reward,
            AVG(CASE WHEN followup_correction = 1 THEN 1.0 ELSE 0.0 END) as correction_rate,
            AVG(CASE WHEN escalated = 1 THEN 1.0 ELSE 0.0 END) as escalation_rate
          FROM outcome_records WHERE timestamp >= ? GROUP BY json_extract(policy_input, '$.workType') ORDER BY decision_count DESC
        `).all(sinceIso);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ period, summary: summary || { total_decisions: 0 }, byModel, byWorkType }));
      } finally {
        db.close();
      }
    } catch (e) {
      console.error('[API] /api/cortex/outcomes/stats error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load cortex outcome stats' }));
    }
    return;
  }

  if (path === '/api/cortex/workload-tokens' && req.method === 'GET') {
    try {
      const period = url.searchParams.get('period') || '24h';
      const periodMap = { '24h': 1, '3d': 3, '7d': 7 };
      const days = periodMap[period] || 1;
      const cutoff = new Date(Date.now() - days * 86400000).toISOString();

      if (!existsSync(OUTCOME_DB_PATH)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ workloads: [], period, has_token_data: false, total_turns: 0, total_tokens: 0 }));
        return;
      }

      const db = openSqlite(OUTCOME_DB_PATH, { readonly: true });
      let rows;
      try {
        rows = db.prepare(
          'SELECT timestamp, chosen_provider, chosen_model, chosen_cost_tier, tokens_in, tokens_out, estimated_cost_usd, policy_input FROM outcome_records WHERE timestamp >= ? ORDER BY timestamp ASC'
        ).all(cutoff);
      } finally {
        db.close();
      }

      const openclawConfig = readOpenClawConfig();
      const heartbeatModel = openclawConfig?.agents?.defaults?.heartbeat?.model || '';
      const heartbeatDisabled = openclawConfig?.agents?.defaults?.heartbeat?.every === '0m';

      const classified = rows.map((row) => {
        let workloadClass = 'primary';
        if (heartbeatModel && String(row.chosen_model || '').includes(heartbeatModel)) {
          workloadClass = 'heartbeat';
        }
        if (row.policy_input) {
          try {
            const policy = JSON.parse(row.policy_input);
            const workType = String(policy.workType || '').toLowerCase();
            if (workType === 'heartbeat' || workType === 'health_check') workloadClass = 'heartbeat';
            else if (workType === 'compaction' || workType === 'compact') workloadClass = 'compaction';
            else if (workType === 'cron' || workType === 'scheduled') workloadClass = 'cron';
          } catch {
            // ignore parse errors
          }
        }

        const tokensIn = Number(row.tokens_in) || 0;
        const tokensOut = Number(row.tokens_out) || 0;
        const totalTokens = tokensIn + tokensOut;
        const cost = Number(row.estimated_cost_usd) || 0;

        return {
          workloadClass,
          provider: row.chosen_provider,
          model: row.chosen_model,
          costTier: row.chosen_cost_tier || 'free',
          tokens: totalTokens,
          tokensIn,
          tokensOut,
          cost,
          timestamp: row.timestamp,
        };
      });

      const validClasses = ['primary', 'heartbeat', 'compaction', 'cron', 'unknown'];
      const agg = {};
      for (const cls of validClasses) {
        agg[cls] = { workloadClass: cls, turns: 0, tokens: 0, tokensIn: 0, tokensOut: 0, cost: 0, providers: {} };
      }

      let hasTokenData = false;
      for (const item of classified) {
        const bucket = agg[item.workloadClass] || agg.unknown;
        bucket.turns += 1;
        bucket.tokens += item.tokens;
        bucket.tokensIn += item.tokensIn;
        bucket.tokensOut += item.tokensOut;
        bucket.cost += item.cost;
        if (item.tokens > 0) hasTokenData = true;
        const providerKey = item.provider || 'unknown';
        if (!bucket.providers[providerKey]) bucket.providers[providerKey] = { turns: 0, tokens: 0 };
        bucket.providers[providerKey].turns += 1;
        bucket.providers[providerKey].tokens += item.tokens;
      }

      const totalTurns = classified.length;
      const totalTokens = classified.reduce((sum, item) => sum + item.tokens, 0);
      const workloads = validClasses
        .map((cls) => ({
          ...agg[cls],
          pctTurns: totalTurns > 0 ? agg[cls].turns / totalTurns : 0,
          pctTokens: totalTokens > 0 ? agg[cls].tokens / totalTokens : 0,
          confidence: cls === 'heartbeat' || cls === 'primary' ? 'reliable' : 'estimated',
        }))
        .filter((row) => row.turns > 0);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        workloads,
        period,
        has_token_data: hasTokenData,
        total_turns: totalTurns,
        total_tokens: totalTokens,
        heartbeat_model: heartbeatModel || null,
        heartbeat_disabled: heartbeatDisabled,
      }));
    } catch (e) {
      console.error('[API] /api/cortex/workload-tokens error:', e.message);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ workloads: [], period: '24h', has_token_data: false, total_turns: 0, total_tokens: 0 }));
    }
    return;
  }


  if (path === '/api/cortex/usage' && req.method === 'GET') {
    try {
      const payload = buildCortexUsageFromLogs();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.error('[API] /api/cortex/usage error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load cortex usage' }));
    }
    return;
  }

  if (path === '/api/cortex/health' && req.method === 'GET') {
    try {
      const { lines: decisions } = tailJsonLines(CORTEX_LOG_PATH, 50);
      const config = readCortexConfig() || {};
      const providers = {};
      for (const decision of decisions) {
        const selectedModel = String(decision?.modelSelected || decision?.selectedModel || decision?.model || '');
        const provider = String(decision?.provider || selectedModel.split('/')[0] || 'unknown');
        if (!providers[provider]) {
          providers[provider] = { requests: 0, lastUsed: null, skips: 0 };
        }
        providers[provider].requests += 1;
        const tsMs = getDecisionTimestampMs(decision);
        if (tsMs > 0) {
          const iso = new Date(tsMs).toISOString();
          if (!providers[provider].lastUsed || iso > providers[provider].lastUsed) {
            providers[provider].lastUsed = iso;
          }
        }
        const skipped = Array.isArray(decision?.modelsSkipped) ? decision.modelsSkipped.length : 0;
        providers[provider].skips += skipped;
      }

      const ladder = Array.isArray(config?.ladder) ? config.ladder : [];
      const activeModels = ladder.filter((m) => m?.enabled !== false).map((m) => m.model).filter(Boolean);
      const disabledModels = ladder.filter((m) => m?.enabled === false).map((m) => m.model).filter(Boolean);
      const schedulePolicy = config?.schedule?.policy || config?.schedule?.mode || null;

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ providers, schedulePolicy, activeModels, disabledModels }));
    } catch (e) {
      console.error('[API] /api/cortex/health error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load cortex health' }));
    }
    return;
  }


  if (path === '/api/workload-routing' && req.method === 'GET') {
    try {
      const config = readOpenClawConfig();
      if (!config) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'openclaw.json not found' }));
        return;
      }
      const defaults = config.agents?.defaults || {};
      const cortexConfig = readCortexConfig();
      const ladder = Array.isArray(cortexConfig?.ladder) ? cortexConfig.ladder : [];
      const catalog = ladder
        .filter((entry) => entry && typeof entry === 'object')
        .map((entry) => ({
          model: entry.model,
          provider: entry.model?.split('/')[0] || 'unknown',
          enabled: entry.enabled !== false,
          tier: entry.tier || entry.costTier || null,
        }));

      const result = {
        primary: {
          model: defaults.model?.primary || null,
          source: 'agents.defaults.model.primary',
          status: defaults.model?.primary ? 'pinned' : 'none',
        },
        fallbacks: {
          models: Array.isArray(defaults.model?.fallbacks) ? defaults.model.fallbacks : [],
          source: 'agents.defaults.model.fallbacks',
        },
        heartbeat: {
          model: defaults.heartbeat?.model || '',
          every: defaults.heartbeat?.every || '0m',
          activeHours: defaults.heartbeat?.activeHours || null,
          status: defaults.heartbeat?.every === '0m'
            ? 'disabled'
            : defaults.heartbeat?.model
              ? 'pinned'
              : 'routed',
        },
        compaction: {
          model: config.agents?.defaults?.compaction?.model || null,
          mode: defaults.compaction?.mode || config.compaction?.mode || null,
          status: 'unavailable',
        },
        cron: {
          model: null,
          status: 'inherits_primary',
        },
        catalog,
      };

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    } catch (e) {
      console.error('[API] /api/workload-routing error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  if (path === '/api/workload-routing' && req.method === 'PUT') {
    readJsonBody(req).then((body) => {
      try {
        const config = readOpenClawConfig();
        if (!config) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'openclaw.json not found' }));
          return;
        }

        if (!config.agents) config.agents = {};
        if (!config.agents.defaults) config.agents.defaults = {};
        if (!config.agents.defaults.model) config.agents.defaults.model = {};
        if (!config.agents.defaults.heartbeat) config.agents.defaults.heartbeat = {};

        let changed = false;

        if (Object.hasOwn(body, 'primary') && typeof body.primary === 'string') {
          if (!body.primary) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Primary model cannot be empty' }));
            return;
          }
          config.agents.defaults.model.primary = body.primary;
          changed = true;
        }

        if (Object.hasOwn(body, 'fallbacks') && Array.isArray(body.fallbacks)) {
          config.agents.defaults.model.fallbacks = body.fallbacks;
          changed = true;
        }

        if (Object.hasOwn(body, 'heartbeat_model') && typeof body.heartbeat_model === 'string') {
          config.agents.defaults.heartbeat.model = body.heartbeat_model;
          changed = true;
        }

        if (Object.hasOwn(body, 'heartbeat_every') && typeof body.heartbeat_every === 'string') {
          config.agents.defaults.heartbeat.every = body.heartbeat_every;
          changed = true;
        }

        if (!changed) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'No valid fields to update' }));
          return;
        }

        writeOpenClawConfig(config);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, message: 'Config saved. Restart gateway to apply.' }));
      } catch (e) {
        console.error('[API] PUT /api/workload-routing error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Failed to write config' }));
      }
    }).catch((e) => {
      const code = e.message === 'Payload too large' ? 413 : 400;
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    });
    return;
  }

  if (path === '/api/cortex/config' && req.method === 'PUT') {
    readJsonBody(req).then((body) => {
      try {
        const current = readCortexConfig();
        if (!current) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'cortex not configured' }));
          return;
        }
        const allowed = ['ladder', 'agentPins', 'scoring', 'quotaThresholds', 'schedule', 'alerts'];
        const patch = {};
        for (const key of allowed) {
          if (Object.prototype.hasOwnProperty.call(body || {}, key)) patch[key] = body[key];
        }
        const updated = deepMerge(current, patch);
        writeCortexConfig(updated);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, version: updated.version }));
      } catch (e) {
        console.error('[API] /api/cortex/config error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Failed to update cortex config' }));
      }
    }).catch((e) => {
      const code = e.message === 'Payload too large' ? 413 : 400;
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message === 'Payload too large' ? 'Payload too large' : 'Invalid JSON body' }));
    });
    return;
  }

  if (path.startsWith('/api/cortex/ladder/') && path.endsWith('/toggle') && req.method === 'PUT') {
    try {
      const prefix = '/api/cortex/ladder/';
      const modelSegment = path.slice(prefix.length, path.length - '/toggle'.length).replace(/^\/+|\/+$/g, '');
      const model = decodeURIComponent(modelSegment);
      if (!model) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid model id' }));
        return;
      }
      const current = readCortexConfig();
      if (!current) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'cortex not configured' }));
        return;
      }
      const ladder = Array.isArray(current.ladder) ? current.ladder : [];
      const idx = ladder.findIndex((entry) => String(entry?.model || '') === model);
      if (idx === -1) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Model not found in ladder' }));
        return;
      }
      ladder[idx] = { ...ladder[idx], enabled: ladder[idx].enabled === false ? true : false };
      current.ladder = ladder;
      writeCortexConfig(current);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, model, enabled: Boolean(ladder[idx].enabled) }));
    } catch (e) {
      console.error('[API] /api/cortex/ladder/:model/toggle error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to toggle model' }));
    }
    return;
  }

  if (path === '/api/cortex/pins' && req.method === 'PUT') {
    readJsonBody(req).then((body) => {
      try {
        const agentId = typeof body?.agentId === 'string' ? body.agentId.trim() : '';
        const model = body?.model === null ? null : (typeof body?.model === 'string' ? body.model.trim() : undefined);
        if (!agentId || model === undefined) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'agentId and model are required' }));
          return;
        }

        const current = readCortexConfig();
        if (!current) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'cortex not configured' }));
          return;
        }

        const pins = current.agentPins && typeof current.agentPins === 'object' ? { ...current.agentPins } : {};
        if (model === null || model === '') {
          delete pins[agentId];
        } else {
          pins[agentId] = model;
        }
        current.agentPins = pins;
        writeCortexConfig(current);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, agentPins: pins }));
      } catch (e) {
        console.error('[API] /api/cortex/pins error:', e.message);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Failed to update cortex pins' }));
      }
    }).catch((e) => {
      const code = e.message === 'Payload too large' ? 413 : 400;
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message === 'Payload too large' ? 'Payload too large' : 'Invalid JSON body' }));
    });
    return;
  }



  if (path === '/api/proxy/stats' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    const credentials = getProxyCredentials();
    if (!credentials.available) {
      res.end(JSON.stringify({ available: false, reason: credentials.reason }));
      return;
    }

    try {
      const { payload, stale } = await getProxyCached(proxyApiCache.stats, PROXY_STATS_CACHE_MS, async () => {
        const raw = await fetchProxyApi('/api/stats', credentials);
        return {
          available: true,
          stale: false,
          raw,
          computed: computeProxyStats(raw),
        };
      });
      res.end(JSON.stringify({ ...payload, stale }));
    } catch (error) {
      console.error('[API] /api/proxy/stats error:', error.message);
      res.end(JSON.stringify({ available: false, error: error.message }));
    }
    return;
  }

  if (path === '/api/proxy/history' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    const credentials = getProxyCredentials();
    if (!credentials.available) {
      res.end(JSON.stringify({ available: false, reason: credentials.reason }));
      return;
    }

    const days = Math.max(1, Math.min(90, parseInt(url.searchParams.get('days') || '30', 10) || 30));
    const cacheKey = `days:${days}`;
    const now = new Date();
    const from = new Date(now.getTime() - (days * 86400000));

    if (!proxyApiCache.history.has(cacheKey)) {
      proxyApiCache.history.set(cacheKey, { timestamp: 0, data: null });
    }

    try {
      const { payload, stale } = await getProxyCached(proxyApiCache.history.get(cacheKey), PROXY_HISTORY_CACHE_MS, async () => {
        const raw = await fetchProxyApi('/api/stats_with_history', credentials, {
          group_type: 'day',
          from: from.toISOString(),
          to: now.toISOString(),
        });
        return { available: true, stale: false, raw, days };
      });
      res.end(JSON.stringify({ ...payload, stale }));
    } catch (error) {
      console.error('[API] /api/proxy/history error:', error.message);
      res.end(JSON.stringify({ available: false, error: error.message }));
    }
    return;
  }

  if (path === '/api/proxy/errors' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    const credentials = getProxyCredentials();
    if (!credentials.available) {
      res.end(JSON.stringify({ available: false, reason: credentials.reason }));
      return;
    }

    const days = Math.max(1, Math.min(90, parseInt(url.searchParams.get('days') || '7', 10) || 7));
    const cacheKey = `days:${days}`;
    const now = new Date();
    const from = new Date(now.getTime() - (days * 86400000));

    if (!proxyApiCache.errors.has(cacheKey)) {
      proxyApiCache.errors.set(cacheKey, { timestamp: 0, data: null });
    }

    try {
      const { payload, stale } = await getProxyCached(proxyApiCache.errors.get(cacheKey), PROXY_ERRORS_CACHE_MS, async () => {
        const raw = await fetchProxyApi('/api/errors_stats_with_parameters', credentials, {
          groupby: 'datetime,host',
          datetime_interval: 'day',
          from: from.toISOString(),
          to: now.toISOString(),
          limit: 100,
          offset: 0,
        });
        return { available: true, stale: false, raw, days };
      });
      res.end(JSON.stringify({ ...payload, stale }));
    } catch (error) {
      console.error('[API] /api/proxy/errors error:', error.message);
      res.end(JSON.stringify({ available: false, error: error.message }));
    }
    return;
  }

  if (path === '/api/proxy/sentinel' && req.method === 'GET') {
    try {
      const sentinelPath = join(process.env.HOME || '/home/openclaw', '.openclaw', 'workspace', 'proxy-sentinel-status.json');
      if (!existsSync(sentinelPath)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ available: false }));
        return;
      }
      const raw = JSON.parse(readFileSync(sentinelPath, 'utf8'));
      const age = Math.floor((Date.now() - new Date(raw.timestamp).getTime()) / 1000);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ available: true, stale: age > 3900, age_seconds: age, data: raw }));
    } catch (e) {
      console.error('[API] /api/proxy/sentinel error:', e.message);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ available: false, error: e.message }));
    }
    return;
  }

  if (path === '/api/proxy/top-hosts' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    const days = Math.max(1, Math.min(7, parseInt(url.searchParams.get('days') || '7', 10) || 7));
    const cacheKey = `days:${days}`;

    if (!proxyApiCache.topHosts.has(cacheKey)) {
      proxyApiCache.topHosts.set(cacheKey, { timestamp: 0, data: null });
    }

    try {
      const { payload, stale } = await getProxyCached(proxyApiCache.topHosts.get(cacheKey), PROXY_TOP_HOSTS_CACHE_MS, async () => {
        return await computeTopProxyHosts(days);
      });
      res.end(JSON.stringify({ ...payload, stale }));
    } catch (error) {
      console.error('[API] /api/proxy/top-hosts error:', error.message);
      res.end(JSON.stringify({ available: false, error: error.message }));
    }
    return;
  }

  if (path === '/api/memory/health' && req.method === 'GET') {
    try {
      const payload = getMemoryCached('health', 60000, () => {
        const checks = [];
        const now = Date.now();
        const todayIso = new Date().toISOString().slice(0, 10);
        const todayStart = Date.parse(`${todayIso}T00:00:00Z`);

        let dbAccessible = false;
        try {
          const db = openFactsDb();
          db.prepare('SELECT 1 LIMIT 1').get();
          db.close();
          dbAccessible = true;
        } catch {
          dbAccessible = false;
        }

        const cfg = readOpenClawConfig();
        const memorySearchEnabled = Boolean(getByPath(cfg, ['agents', 'defaults', 'memorySearch', 'enabled']));

        const gatewayLogPath = `/tmp/openclaw/openclaw-${todayIso}.log`;
        const graphMemoryPluginSeen = safeReadLines(gatewayLogPath, 5000).some((line) => line.toLowerCase().includes('graph-memory'));

        const recallRowsToday = readJsonlWindow(MEMORY_TELEMETRY_PATH, todayStart, 6000);
        const captureRowsToday = readJsonlWindow(MEMORY_CAPTURE_TELEMETRY_PATH, todayStart, 6000);

        const ingestAgeHours = (() => {
          const ms = getLastLogTimestampMs(safeReadLines(MEMORY_INGEST_LOG_PATH, 5000));
          return ms ? ((now - ms) / 3600000) : null;
        })();

        const pruneAgeHours = (() => {
          const ms = getLastLogTimestampMs(safeReadLines(MEMORY_PRUNE_LOG_PATH, 5000));
          return ms ? ((now - ms) / 3600000) : null;
        })();

        const drift = getCaptureDriftDetails();

        checks.push({ key: 'factsDbAccessible', label: 'facts.db accessible', status: dbAccessible ? 'green' : 'red' });
        checks.push({ key: 'graphMemoryPluginLoaded', label: 'graph-memory plugin loaded', status: graphMemoryPluginSeen ? 'green' : 'red' });
        checks.push({ key: 'memorySearchEnabled', label: 'memorySearch enabled', status: memorySearchEnabled ? 'green' : 'red' });
        checks.push({ key: 'recallHookActive', label: 'Recall hook active', status: recallRowsToday.length > 0 ? 'green' : 'red', entriesToday: recallRowsToday.length });
        checks.push({ key: 'captureHookActive', label: 'Capture hook active', status: captureRowsToday.length > 0 ? 'green' : 'red', entriesToday: captureRowsToday.length });
        checks.push({ key: 'nightlyIngest', label: 'Nightly ingest', status: statusLevel(ingestAgeHours !== null && ingestAgeHours < 26, ingestAgeHours !== null && ingestAgeHours <= 48), ageHours: ingestAgeHours });
        checks.push({ key: 'hourlyPrune', label: 'Hourly prune', status: statusLevel(pruneAgeHours !== null && pruneAgeHours < 2, pruneAgeHours !== null && pruneAgeHours <= 4), ageHours: pruneAgeHours });
        checks.push({ key: 'runtimeDrift', label: 'Runtime drift', status: drift.drifted ? 'red' : 'green', message: drift.drifted ? 'Runtime differs from repo' : 'Runtime matches repo' });

        return {
          checks,
          memoryToolsDisabled: !memorySearchEnabled,
          runtimeDriftDetected: drift.drifted,
          generatedAt: new Date().toISOString(),
        };
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.error('[API] /api/memory/health error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load memory health' }));
    }
    return;
  }

  if (path === '/api/memory/stats' && req.method === 'GET') {
    try {
      const payload = getMemoryCached('stats', 60000, () => {
        const todayIso = new Date().toISOString().slice(0, 10);
        const db = openFactsDb();
        const totalFacts = queryCountSafe(db, 'SELECT COUNT(*) AS count FROM facts LIMIT 1');
        const relations = queryCountSafe(db, 'SELECT COUNT(*) AS count FROM relations LIMIT 1');
        const aliasCount = queryCountSafe(db, 'SELECT COUNT(*) AS count FROM aliases LIMIT 1');
        const coOccurrenceCount = queryCountSafe(db, 'SELECT COUNT(*) AS count FROM co_occurrences LIMIT 1');
        const decayRows = db.prepare('SELECT decay_class, COUNT(*) AS count FROM facts GROUP BY decay_class LIMIT 10').all();
        const todayCaptures = queryCountSafe(db, "SELECT COUNT(*) AS count FROM facts WHERE source = 'auto-capture:session' AND created_at >= ? LIMIT 1", [`${todayIso}T00:00:00`]);
        const sourceDistribution = db.prepare('SELECT source, COUNT(*) AS count FROM facts GROUP BY source ORDER BY count DESC LIMIT 20').all();
        const structuredCount = queryCountSafe(db, "SELECT COUNT(*) AS count FROM facts WHERE COALESCE(key, '') != 'note' LIMIT 1");
        const topEntities = db.prepare("SELECT entity, COUNT(*) AS count FROM facts WHERE COALESCE(entity, '') != '' GROUP BY entity ORDER BY count DESC LIMIT 5").all();
        db.close();
        return {
          totalFacts,
          relations,
          todayCaptures,
          aliasCount,
          coOccurrenceCount,
          structuredRatio: totalFacts > 0 ? (structuredCount / totalFacts) * 100 : 0,
          sourceDistribution: sourceDistribution.map((row) => ({ source: row.source || 'unknown', count: Number(row.count || 0) })),
          topEntities: topEntities.map((row) => ({ entity: row.entity, count: Number(row.count || 0) })),
          decay: decayRows.map((row) => ({ decayClass: row.decay_class || 'unknown', count: Number(row.count || 0) })),
          generatedAt: new Date().toISOString(),
        };
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.error('[API] /api/memory/stats error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load memory stats' }));
    }
    return;
  }

  if (path === '/api/memory/facts' && req.method === 'GET') {
    try {
      const requestedLimit = parseInt(url.searchParams.get('limit') || '50', 10);
      const requestedOffset = parseInt(url.searchParams.get('offset') || '0', 10);
      const limit = Math.max(1, Math.min(100, Number.isFinite(requestedLimit) ? requestedLimit : 50));
      const offset = Math.max(0, Number.isFinite(requestedOffset) ? requestedOffset : 0);
      const decay = String(url.searchParams.get('decay') || 'all').toLowerCase();
      const period = String(url.searchParams.get('period') || 'all').toLowerCase();
      const cacheKey = `facts:${limit}:${offset}:${decay}:${period}`;

      const payload = getMemoryCached(cacheKey, 30000, () => {
        const conditions = [];
        const params = [];
        if (['permanent', 'stable', 'active', 'session'].includes(decay)) {
          conditions.push('decay_class = ?');
          params.push(decay);
        }
        if (period === 'today') {
          conditions.push('created_at >= ?');
          params.push(`${new Date().toISOString().slice(0, 10)}T00:00:00`);
        }
        const whereSql = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

        const db = openFactsDb();
        const total = Number(db.prepare(`SELECT COUNT(*) AS count FROM facts ${whereSql} LIMIT 1`).get(...params)?.count || 0);
        const rows = db
          .prepare(`SELECT id, entity, key, value, category, source, decay_class, confidence, activation, expires_at, created_at FROM facts ${whereSql} ORDER BY datetime(created_at) DESC LIMIT ? OFFSET ?`)
          .all(...params, limit, offset);
        db.close();

        return {
          limit,
          offset,
          total,
          items: rows,
        };
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.error('[API] /api/memory/facts error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load memory facts' }));
    }
    return;
  }

  if (path.startsWith('/api/memory/fact/') && req.method === 'GET') {
    try {
      const id = parseInt(path.split('/').pop() || '', 10);
      if (!Number.isFinite(id) || id <= 0) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid fact id' }));
        return;
      }

      const db = openFactsDb();
      const fact = db.prepare('SELECT * FROM facts WHERE id = ? LIMIT 1').get(id);
      db.close();
      if (!fact) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Fact not found' }));
        return;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(fact));
    } catch (e) {
      console.error('[API] /api/memory/fact/:id error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load memory fact' }));
    }
    return;
  }

  if (path === '/api/memory/telemetry' && req.method === 'GET') {
    try {
      const payload = getMemoryCached('telemetry', 120000, () => {
        const cutoff = Date.now() - (24 * 3600000);
        const recallRows = readJsonlWindow(MEMORY_TELEMETRY_PATH, cutoff, 8000);
        const captureRows = readJsonlWindow(MEMORY_CAPTURE_TELEMETRY_PATH, cutoff, 8000);

        const recalls = recallRows.length;
        const recallHits = recallRows.filter((row) => Number(row.result_count || row.results || 0) > 0).length;
        const avgFactsPerRecall = recallRows.reduce((acc, row) => acc + Number(row.result_count || row.results || 0), 0) / Math.max(1, recalls);
        const avgLatencyMs = recallRows.reduce((acc, row) => acc + Number(row.latency || row.latency_ms || 0), 0) / Math.max(1, recalls);
        const cacheHits = recallRows.filter((row) => {
          const hit = row.cache_hit;
          if (typeof hit === 'boolean') return hit;
          return String(row.cache || '').toLowerCase() === 'hit';
        }).length;
        const timeoutCount = recallRows.filter((row) => String(row.error || '').toLowerCase().includes('timeout')).length;
        const zeroResultCount = recallRows.filter((row) => Number(row.result_count || row.results || 0) === 0).length;

        const filteredBreakdown = { lengthBounds: 0, xmlHtml: 0, emojiDensity: 0, heavyMarkdown: 0, sensitivePattern: 0, userMessageFilter: 0, duplicate: 0 };
        let skippedTurns = 0;
        let captureTurns = 0;
        let eligibleSentences = 0;
        let capturedFacts = 0;
        let structuredCaptures = 0;
        let noteOnlyCaptures = 0;
        for (const row of captureRows) {
          captureTurns += 1;
          if (row.skippedTurn) skippedTurns += 1;
          eligibleSentences += Number(row.eligible || 0);
          capturedFacts += Number(row.captured || 0);
          structuredCaptures += Number(row.structured || 0);
          noteOnlyCaptures += Number(row.noteOnly || 0);
          const fb = row.filtered || {};
          for (const key of Object.keys(filteredBreakdown)) {
            filteredBreakdown[key] += Number(fb[key] || 0);
          }
        }

        return {
          available: recalls > 0 || captureTurns > 0,
          windowHours: 24,
          recall: {
            available: recalls > 0,
            recalls,
            recallHitRate: (recallHits / Math.max(1, recalls)) * 100,
            avgFactsPerRecall,
            avgLatencyMs,
            cacheHitRate: (cacheHits / Math.max(1, recalls)) * 100,
            timeoutCount,
            zeroResultCount,
          },
          capture: {
            available: captureTurns > 0,
            captureTurns,
            skippedTurns,
            eligibleSentences,
            filteredBreakdown,
            capturedFacts,
            structuredCaptures,
            noteOnlyCaptures,
          },
        };
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.error('[API] /api/memory/telemetry error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load memory telemetry' }));
    }
    return;
  }

  if (path === '/api/memory/ingest-coverage' && req.method === 'GET') {
    try {
      const payload = getMemoryCached('ingest-coverage', 300000, () => {
        const lines = safeReadLines(MEMORY_INGEST_LOG_PATH, 5000);
        if (!lines.length) {
          return {
            available: false,
            lastRunTimestamp: null,
            sourceDate: null,
            linesScanned: null,
            candidatesExtracted: null,
            factsInserted: null,
            duplicatesSkipped: null,
            lastStatus: { state: 'error', message: 'No ingest log data' },
          };
        }
        const joined = lines.join('\n');
        const m = (re) => {
          const match = joined.match(re);
          return match ? match[1] : null;
        };
        const tsMatch = joined.match(/(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z)?)/g);
        const lastRunTimestamp = tsMatch?.length ? tsMatch[tsMatch.length - 1].replace(' ', 'T') : null;
        const lastErrorLine = [...lines].reverse().find((line) => /error|failed|exception/i.test(line));
        const sourceDate = m(/(?:source\s*(?:date|file)|processing\s+file|Scanning\s+)[^\d]*(\d{4}-\d{2}-\d{2})/i);
        const linesScanned = parseNumberOrNull(m(/(?:lines\s*scanned|scanned\s*lines|total\s*lines|files_scanned)[=:\s]*(\d+)/i));
        const candidatesExtracted = parseNumberOrNull(m(/(?:candidates\s*extracted|candidate\s*lines|eligible\s*lines|candidates)[=:\s]*(\d+)/i));
        const factsInserted = parseNumberOrNull(m(/(?:facts\s*inserted|inserted\s*facts|new\s*facts|new_facts_stored)[=:\s]*(\d+)/i));
        const duplicatesSkipped = parseNumberOrNull(m(/(?:duplicates\s*skipped|skipped\s*duplicates|duplicates_skipped)[=:\s]*(\d+)/i));
        const hasSuccess = /success|completed|SUMMARY/i.test(lastErrorLine || '') ? false : /success|completed|SUMMARY/i.test(joined);
        return {
          available: true,
          lastRunTimestamp,
          sourceDate,
          linesScanned,
          candidatesExtracted,
          factsInserted,
          duplicatesSkipped,
          lastStatus: lastErrorLine ? { state: 'error', message: lastErrorLine } : { state: hasSuccess ? 'success' : 'error', message: hasSuccess ? 'Completed' : 'Unknown status' },
        };
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.error('[API] /api/memory/ingest-coverage error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load ingest coverage' }));
    }
    return;
  }

  if (path === '/api/memory/drift' && req.method === 'GET') {
    try {
      const payload = getMemoryCached('memory-drift', 60000, () => {
        const drift = getCaptureDriftDetails();
        const pair = drift.filePairs[0] || {};
        return {
          drifted: drift.drifted,
          repoSize: pair.repoSize ?? null,
          runtimeSize: pair.runtimeSize ?? null,
          repoModified: pair.repoModified ?? null,
          runtimeModified: pair.runtimeModified ?? null,
          filePairs: drift.filePairs,
        };
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.error('[API] /api/memory/drift error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load memory drift' }));
    }
    return;
  }

  if (path === '/api/memory/daily-files' && req.method === 'GET') {
    try {
      const payload = getMemoryCached('daily-files', 300000, () => {
        const today = new Date();
        const expected = [];
        for (let i = 0; i < 14; i++) {
          const d = new Date(today.getTime() - (i * 86400000));
          expected.push(d.toISOString().slice(0, 10));
        }
        const files = [];
        const availableSet = new Set();
        if (existsSync(MEMORY_FILES_DIR_PATH)) {
          const names = readdirSync(MEMORY_FILES_DIR_PATH).filter((name) => /^\d{4}-\d{2}-\d{2}\.md$/.test(name));
          for (const day of expected) {
            const fileName = `${day}.md`;
            if (!names.includes(fileName)) continue;
            const fullPath = join(MEMORY_FILES_DIR_PATH, fileName);
            const content = readFileSync(fullPath, 'utf8');
            const words = content.trim() ? content.trim().split(/\s+/).length : 0;
            const size = statSync(fullPath).size;
            files.push({ date: day, fileName, sizeBytes: size, estimatedWords: words });
            availableSet.add(day);
          }
        }
        const missingDays = expected.filter((day) => !availableSet.has(day));
        return {
          windowDays: 14,
          files,
          missingDays,
        };
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.error('[API] /api/memory/daily-files error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load memory daily files' }));
    }
    return;
  }

  if (path === '/api/memory/tools-status' && req.method === 'GET') {
    try {
      const payload = getMemoryCached('tools-status', 60000, () => {
        const cfg = readOpenClawConfig();
        return {
          memorySearchEnabled: Boolean(getByPath(cfg, ['agents', 'defaults', 'memorySearch', 'enabled'])),
          graphMemoryPluginEnabled: Boolean(getByPath(cfg, ['plugins', 'entries', 'graph-memory', 'enabled'])),
        };
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    } catch (e) {
      console.error('[API] /api/memory/tools-status error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load memory tools status' }));
    }
    return;
  }

  if (path === '/api/logs' && req.method === 'GET') {
    try {
      const requestedLimit = parseInt(url.searchParams.get('limit') || '50', 10);
      const requestedOffset = parseInt(url.searchParams.get('offset') || '0', 10);
      const limit = Math.max(1, Math.min(200, Number.isFinite(requestedLimit) ? requestedLimit : 50));
      const offset = Math.max(0, Number.isFinite(requestedOffset) ? requestedOffset : 0);

      const { rows, total } = queryLogs({
        source: url.searchParams.get('source') || null,
        agent: url.searchParams.get('agent') || null,
        severity: url.searchParams.get('severity') || null,
        after: url.searchParams.get('after') || null,
        before: url.searchParams.get('before') || null,
        task_id: url.searchParams.get('task_id') || null,
        session_id: url.searchParams.get('session_id') || null,
        limit,
        offset,
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ rows, total, limit, offset }));
    } catch (e) {
      console.error('[API] /api/logs error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load logs' }));
    }
    return;
  }

  if (path === '/api/logs/health' && req.method === 'GET') {
    try {
      const sources = getIngestHealth();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        sources,
        last_cycle: lastLogsIngestionCycle,
        retention_days: 30,
      }));
    } catch (e) {
      console.error('[API] /api/logs/health error:', e.message);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Failed to load logs health' }));
    }
    return;
  }

  if (path === '/api/host') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(collector.hostMetrics));
    return;
  }

  // ── SSE Stream ──

  if (path === '/api/stream') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    });
    res.write(`data: ${JSON.stringify({ type: 'snapshot', data: collector.getSnapshot() })}\n\n`);
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
    return;
  }

  // ── Static Files ──

  let filePath = path === '/' ? '/dashboard.html' : path;
  const fullPath = join(DIR, filePath);

  if (!fullPath.startsWith(DIR) || !existsSync(fullPath)) {
    res.writeHead(404);
    res.end('Not found');
    return;
  }

  try {
    const data = readFileSync(fullPath);
    const ext = extname(fullPath);
    const contentType = MIME[ext] || 'application/octet-stream';

    // Smart caching: cache JS/CSS assets, force revalidation for HTML
    const isAsset = ['.js', '.mjs', '.css', '.png', '.svg', '.ico'].includes(ext);
    const isHtml = ext === '.html';
    const cacheControl = isAsset
      ? 'public, max-age=3600'
      : (isHtml ? 'no-cache, no-store, must-revalidate' : 'no-cache');

    // Gzip text responses > 1KB
    const isText = ['.html', '.js', '.mjs', '.css', '.json', '.svg'].includes(ext);
    const acceptGzip = (req.headers['accept-encoding'] || '').includes('gzip');
    if (isText && acceptGzip && data.length > 1024) {
      const compressed = gzipSync(data);
      res.writeHead(200, {
        'Content-Type': contentType,
        'Content-Encoding': 'gzip',
        'Cache-Control': cacheControl,
        'Vary': 'Accept-Encoding',
      });
      res.end(compressed);
    } else {
      res.writeHead(200, {
        'Content-Type': contentType,
        'Cache-Control': cacheControl,
      });
      res.end(data);
    }
  } catch {
    res.writeHead(500);
    res.end('Error');
  }
});

// ── Login Page HTML ──
const LOGIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login — Clawd Control</title>
<style>
  :root { --bg: #0f1117; --card: #1a1d27; --border: #2a2d3a; --text: #e4e4e7; --muted: #71717a; --accent: #c9a44a; --accent-hover: #d4af5a; --red: #ef4444; --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
  .login-box { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 40px; width: 100%; max-width: 360px; text-align: center; }
  .login-box h1 { font-size: 2rem; margin-bottom: 8px; }
  .login-box .sub { color: var(--muted); font-size: 0.85rem; margin-bottom: 32px; letter-spacing: 0.02em; }
  .login-box input {
    width: 100%; padding: 12px 16px; background: var(--bg); border: 1px solid var(--border);
    border-radius: 8px; color: var(--text); font-size: 0.95rem; font-family: var(--font);
    outline: none; margin-bottom: 16px; text-align: center; letter-spacing: 1px;
  }
  .login-box input:focus { border-color: var(--accent); }
  .login-box button {
    width: 100%; padding: 12px; background: var(--accent); color: #0f1117; border: none;
    border-radius: 8px; font-size: 0.95rem; font-weight: 600; cursor: pointer; font-family: var(--font);
  }
  .login-box button:hover { background: var(--accent-hover); }
  .login-box button:disabled { opacity: 0.4; }
  .error { color: var(--red); font-size: 0.82rem; margin-bottom: 12px; min-height: 18px; }
</style>
</head>
<body>
<div class="login-box">
  <h1><i data-lucide="castle" style="width:2rem;height:2rem;display:inline-block;vertical-align:middle"></i></h1>
  <p class="sub">Clawd Control</p>
  <form onsubmit="login(event)">
    <input type="password" id="pw" placeholder="Password" autofocus autocomplete="current-password">
    <div class="error" id="err"></div>
    <button type="submit" id="btn">Enter</button>
  </form>
</div>
<script>
async function login(e) {
  e.preventDefault();
  const pw = document.getElementById('pw').value;
  const btn = document.getElementById('btn');
  const err = document.getElementById('err');
  btn.disabled = true; err.textContent = '';
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pw }),
    });
    const data = await res.json();
    if (data.ok) {
      window.location.href = '/';
    } else {
      err.textContent = data.error || 'Wrong password';
      btn.disabled = false;
    }
  } catch (e) {
    err.textContent = 'Connection error';
    btn.disabled = false;
  }
}
</script>
<script src="/lucide.min.js"></script>
<script>lucide.createIcons();</script>
</body>
</html>`;

const BIND = process.argv.find((_, i, a) => a[i - 1] === '--bind') || '127.0.0.1';

async function runUnifiedLogsIngestion() {
  try {
    lastLogsIngestionCycle = await runIngestionCycle();
  } catch (e) {
    console.error('[logs] ingestion cycle failed:', e.message);
  }
}

function runUnifiedLogsPrune() {
  try {
    const deleted = pruneOldLogs(30);
    console.log(`[logs] prune deleted ${deleted} rows`);
  } catch (e) {
    console.error('[logs] prune failed:', e.message);
  }
}

setTimeout(() => {
  runUnifiedLogsIngestion();
  setInterval(() => {
    runUnifiedLogsIngestion();
  }, 60_000);
}, 5_000);

runUnifiedLogsPrune();
setInterval(() => {
  runUnifiedLogsPrune();
}, 24 * 60 * 60 * 1000);

server.listen(PORT, BIND, () => {
  console.log(`🏰 Clawd Control v2.0`);
  console.log(`   http://${BIND}:${PORT}`);
  console.log(`   Agents: ${collector.agents.size}`);
  console.log(`   🔐 Auth: ${AUTH_DISABLED ? 'disabled (AUTH_DISABLED=true)' : 'enabled (password in auth.json)'}`);
  console.log(`   🔒 Bound to ${BIND} (home network only)`);
});
