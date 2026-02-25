#!/usr/bin/env node
/**
 * Clawd Control — Server
 * 
 * HTTP server with REST API + SSE for live dashboard updates.
 * Aggregates data from AgentCollector.
 */

import http from 'http';
const { createServer } = http;
import { readFileSync, existsSync, writeFileSync, copyFileSync, readdirSync, statSync } from 'fs';
import { join, extname, resolve, sep } from 'path';
import { gzipSync } from 'zlib';
import { execFileSync } from 'child_process';
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
} from './tasks-db.mjs';

import { createHash, randomBytes, timingSafeEqual } from 'crypto';

const PORT = parseInt(process.argv.find((_, i, a) => a[i - 1] === '--port') || '3100');
const DIR = new URL('.', import.meta.url).pathname;
const AUTH_DISABLED = String(process.env.AUTH_DISABLED || '').toLowerCase() === 'true';

// ── Security constants ──
const MAX_BODY_SIZE = 1024 * 1024; // 1MB max POST body
const RATE_LIMIT_WINDOW = 60000;   // 1 minute window
const RATE_LIMIT_MAX = 5;          // 5 attempts per window
const loginAttempts = new Map();   // ip → [timestamps]

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

  // Allow login page and login API without auth
  if (url.pathname === '/login' || url.pathname === '/api/login') return true;

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
  const range = rangeStr === 'all' ? Infinity : parseInt(rangeStr);
  const cutoffDate = rangeStr === 'all' ? 0 : Date.now() - (range * 86400000);

  // Aggregate data structures
  let totalCost = 0;
  let totalTokens = 0;
  let inputTokens = 0;
  let outputTokens = 0;
  let cacheReadTokens = 0;
  let apiCalls = 0;

  const byAgent = new Map(); // agentId -> {cost, tokens}
  const byDate = new Map(); // date -> {cost, tokens}
  const byModel = new Map(); // model -> {cost, tokens}
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
        let sessionCalls = 0;
        let sessionModel = null;

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

              // Message cost extraction
              if (data.type === 'message' && data.message) {
                const msg = data.message;
                const usage = msg.usage || {};

                // Check timestamp
                const ts = data.timestamp || msg.timestamp;
                if (ts && ts < cutoffDate) continue;

                // Track costs
                const cost = usage.cost?.total || 0;
                const input = usage.input || 0;
                const output = usage.output || 0;
                const cache = usage.cacheRead || 0;

                sessionCost += cost;
                sessionTokens += input + output + cache;
                sessionInput += input;
                sessionOutput += output;
                sessionCache += cache;

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
                  d.cost += cost;
                  d.tokens += input + output + cache;
                }

                // Track by model
                if (sessionModel) {
                  if (!byModel.has(sessionModel)) {
                    byModel.set(sessionModel, { cost: 0, tokens: 0 });
                  }
                  const m = byModel.get(sessionModel);
                  m.cost += cost;
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
        totalCost += sessionCost;
        totalTokens += sessionTokens;
        inputTokens += sessionInput;
        outputTokens += sessionOutput;
        cacheReadTokens += sessionCache;
        apiCalls += sessionCalls;

        // Track by agent
        if (!byAgent.has(agentId)) {
          byAgent.set(agentId, { cost: 0, tokens: 0 });
        }
        const a = byAgent.get(agentId);
        a.cost += sessionCost;
        a.tokens += sessionTokens;

        // Track session for top list
        if (sessionCost > 0 || sessionTokens > 0) {
          sessions.push({
            agentId,
            sessionId,
            cost: sessionCost,
            tokens: sessionTokens,
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
    .sort((a, b) => b.cost - a.cost)
    .slice(0, 20);

  return {
    range: rangeStr,
    agentFilter,
    totalCost: Math.round(totalCost * 10000) / 10000,
    totalTokens,
    inputTokens,
    outputTokens,
    cacheReadTokens,
    apiCalls,
    byAgent: byAgentArray,
    overTime: byDateArray,
    byModel: byModelArray,
    topSessions,
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
                    byAgentDate.set(adKey, { agentId, date, tokens: 0, cost: 0 });
                  }
                  const ad = byAgentDate.get(adKey);
                  ad.tokens += input + output + cacheRead;
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
    agentTimeSeries[val.agentId].push({ date: val.date, tokens: val.tokens, cost: val.cost });
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

const server = createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname;

  // ── Security Headers ──
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';");

  // CORS — restrict to same origin (no cross-origin API access)
  const origin = req.headers.origin;
  if (origin) {
    const allowed = `http://127.0.0.1:${PORT}`;
    const allowedLocal = `http://localhost:${PORT}`;
    if (origin === allowed || origin === allowedLocal) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
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

      if (body.source === 'agent' && body.status === 'proposed') {
        const todayCst = toCstDate(new Date().toISOString());
        const proposalCount = getProposalCount(todayCst);
        if (proposalCount >= 3) {
          res.writeHead(429, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Proposal limit reached (3/day)' }));
          return;
        }
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

        const targetStatus = typeof body.status === 'string' ? body.status : current.status;
        const targetPriority = typeof body.priority === 'string' ? body.priority : current.priority;
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

        let task = updateTask(taskId, body);

        if (current.status !== targetStatus) {
          addHistory(taskId, 'system', 'status_changed', `${current.status} -> ${targetStatus}`);
        }

        if (current.status !== 'review' && targetStatus === 'review' && (targetPriority === 'low' || targetPriority === 'medium')) {
          addHistory(taskId, 'system', 'review_entered', 'Task moved to review');
          task = updateTask(taskId, { status: 'done' });
          addHistory(taskId, 'system', 'auto_approved', `Auto-approved (${targetPriority} priority): review -> done`);
          addHistory(taskId, 'system', 'status_changed', 'review -> done');
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
  if (path === '/api/costs/daily' && req.method === 'GET') {
    try {
      const costsData = computeCostsData();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(costsData.daily));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      console.error('[API] /api/costs/daily error:', e.message);
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

  if (path === '/api/costs/sessions' && req.method === 'GET') {
    try {
      const costsData = computeCostsData();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(costsData.sessions));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      console.error('[API] /api/costs/sessions error:', e.message);
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    return;
  }

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

server.listen(PORT, BIND, () => {
  console.log(`🏰 Clawd Control v2.0`);
  console.log(`   http://${BIND}:${PORT}`);
  console.log(`   Agents: ${collector.agents.size}`);
  console.log(`   🔐 Auth: ${AUTH_DISABLED ? 'disabled (AUTH_DISABLED=true)' : 'enabled (password in auth.json)'}`);
  console.log(`   🔒 Bound to ${BIND} (home network only)`);
});
