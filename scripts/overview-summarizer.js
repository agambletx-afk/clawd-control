#!/usr/bin/env node

import http from 'http';
import fs from 'fs';
import { execSync } from 'child_process';
import { join } from 'path';

const HOST = '127.0.0.1';
const API_PORT = 3100;
const GATEWAY_PORT = 18789;
const REQUEST_TIMEOUT_MS = 500;
const TOTAL_TIMEOUT_MS = 5000;
const LOCK_PATH = '/tmp/overview-summarizer.lock';
const STATE_PATH = '/home/openclaw/.openclaw/workspace/summarizer-state.json';
const COST_PATH = '/home/openclaw/.openclaw/workspace/cortex/quota-state.json';

function mapHealthStatus(value, greenWords, amberWords, redWords) {
  const normalized = String(value || '').trim().toLowerCase();
  if (greenWords.includes(normalized)) return 'green';
  if (amberWords.includes(normalized)) return 'amber';
  if (redWords.includes(normalized)) return 'red';
  return 'amber';
}

function domainRecord(health, attention, detail, observedAt, sourceAgeSeconds, sourceError) {
  return {
    health,
    attention,
    detail,
    observed_at: observedAt,
    source_age_seconds: sourceAgeSeconds,
    source_error: sourceError,
  };
}

function readJsonFileSafe(path) {
  try {
    const content = fs.readFileSync(path, 'utf8');
    return { ok: true, data: JSON.parse(content) };
  } catch (error) {
    return { ok: false, error };
  }
}

function getTokensToday(costRaw) {
  if (!costRaw || typeof costRaw !== 'object') return 0;
  const candidates = [
    costRaw.totalTokens,
    costRaw.total_tokens,
    costRaw.tokensToday,
    costRaw.tokens_today,
    costRaw.todayTokens,
    costRaw.usage?.totalTokens,
    costRaw.usage?.total_tokens,
  ];
  for (const candidate of candidates) {
    const parsed = Number(candidate);
    if (Number.isFinite(parsed) && parsed >= 0) return Math.round(parsed);
  }
  return 0;
}

function fetchJson(path, port, timeoutMs, controllers) {
  return new Promise((resolve, reject) => {
    const controller = new AbortController();
    controllers.push(controller);
    const startedAt = Date.now();

    const req = http.request(
      {
        host: HOST,
        port,
        path,
        method: 'GET',
        signal: controller.signal,
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const durationMs = Date.now() - startedAt;
          const body = Buffer.concat(chunks).toString('utf8');
          resolve({
            ok: res.statusCode >= 200 && res.statusCode < 300,
            statusCode: res.statusCode,
            durationMs,
            body,
          });
        });
      }
    );

    const timer = setTimeout(() => {
      controller.abort();
    }, timeoutMs);

    req.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });

    req.on('close', () => {
      clearTimeout(timer);
    });

    req.end();
  });
}

async function main() {
  const runStartedAt = Date.now();
  const startedIso = new Date(runStartedAt).toISOString();

  try {
    execSync(`flock -n ${LOCK_PATH} -c true`, { stdio: 'ignore' });
  } catch (_error) {
    console.error('skipped (locked)');
    process.exit(0);
  }

  const controllers = [];
  const totalTimeout = setTimeout(() => {
    for (const controller of controllers) {
      try {
        controller.abort();
      } catch (_err) {
        // no-op
      }
    }
  }, TOTAL_TIMEOUT_MS);

  const requestJobs = {
    gateway: fetchJson('/', GATEWAY_PORT, REQUEST_TIMEOUT_MS, controllers),
    cortex: fetchJson('/api/cortex/status', API_PORT, REQUEST_TIMEOUT_MS, controllers),
    watcher: fetchJson('/api/watcher/health', API_PORT, REQUEST_TIMEOUT_MS, controllers),
    memory: fetchJson('/api/memory/health', API_PORT, REQUEST_TIMEOUT_MS, controllers),
    security: fetchJson('/api/security/health', API_PORT, REQUEST_TIMEOUT_MS, controllers),
    tasks: fetchJson('/api/tasks/stats', API_PORT, REQUEST_TIMEOUT_MS, controllers),
  };

  const costRead = readJsonFileSafe(COST_PATH);

  const requestNames = Object.keys(requestJobs);
  const settledEntries = await Promise.allSettled(requestNames.map((name) => requestJobs[name]));

  clearTimeout(totalTimeout);

  const observedAt = new Date().toISOString();
  const results = {};
  let failedSources = 0;

  settledEntries.forEach((entry, index) => {
    const name = requestNames[index];
    if (entry.status === 'fulfilled') {
      results[name] = { ok: true, ...entry.value };
      if (!entry.value.ok) failedSources += 1;
    } else {
      results[name] = { ok: false, error: entry.reason };
      failedSources += 1;
    }
  });

  const parseJson = (name) => {
    const payload = results[name];
    if (!payload || !payload.ok) {
      return { ok: false, error: payload?.error || new Error(`${name} unavailable`) };
    }
    try {
      return { ok: true, data: JSON.parse(payload.body) };
    } catch (error) {
      return { ok: false, error };
    }
  };

  const gatewayRes = results.gateway;
  let gatewayHealth = 'red';
  let gatewayDetail = 'Unreachable';
  let gatewayError = null;
  if (gatewayRes?.ok && gatewayRes.statusCode >= 200 && gatewayRes.statusCode < 300) {
    gatewayHealth = 'green';
    gatewayDetail = 'Responding';
  } else if (gatewayRes?.ok) {
    gatewayHealth = 'red';
    gatewayDetail = `HTTP ${gatewayRes.statusCode}`;
    gatewayError = `Unexpected status ${gatewayRes.statusCode}`;
  } else {
    gatewayError = gatewayRes?.error ? String(gatewayRes.error.message || gatewayRes.error) : 'Request failed';
  }

  const cortexJson = parseJson('cortex');
  let cortexHealth = 'red';
  let cortexDetail = 'CORTEX unavailable';
  let cortexError = null;
  if (cortexJson.ok) {
    const ladder = Array.isArray(cortexJson.data?.ladder) ? cortexJson.data.ladder : [];
    const enabledCount = ladder.filter((model) => model?.enabled !== false).length;
    if (enabledCount > 0) {
      cortexHealth = 'green';
      cortexDetail = `${enabledCount} models enabled`;
    } else {
      cortexHealth = 'red';
      cortexDetail = 'No models enabled';
    }
  } else {
    cortexError = String(cortexJson.error?.message || cortexJson.error || 'Request failed');
  }

  const watcherJson = parseJson('watcher');
  let sessionsHealth = 'red';
  let sessionsDetail = 'Watchdog unavailable';
  let sessionsError = null;
  let cronsHealth = 'red';
  let cronsAttention = null;
  let cronsDetail = 'Cron watcher unavailable';
  let cronsError = null;

  if (watcherJson.ok) {
    const stale = Boolean(watcherJson.data?.stale);
    const overallStatus = watcherJson.data?.results?.overall_status;
    sessionsHealth = mapHealthStatus(
      overallStatus,
      ['healthy', 'ok', 'green'],
      ['warning', 'warn', 'stale', 'yellow', 'degraded'],
      ['critical', 'error', 'failed', 'red']
    );
    if (stale && sessionsHealth !== 'red') sessionsHealth = 'amber';
    sessionsDetail = `Watchdog ${String(overallStatus || 'unknown')}`;

    const crons = Array.isArray(watcherJson.data?.results?.system_crons)
      ? watcherJson.data.results.system_crons
      : [];
    const failedCount = crons.filter((cron) => ['failed', 'critical'].includes(String(cron?.status || '').toLowerCase())).length;
    const healthyCount = crons.filter((cron) => ['ok', 'healthy'].includes(String(cron?.status || '').toLowerCase())).length;

    if (crons.length > 0 && healthyCount === crons.length) {
      cronsHealth = 'green';
      cronsDetail = 'All crons on time';
    } else if (failedCount > 0) {
      cronsHealth = 'red';
      cronsDetail = `${failedCount} cron failures`;
    } else {
      cronsHealth = 'amber';
      cronsDetail = 'Cron warnings present';
    }

    if (failedCount >= 3) cronsAttention = 'red';
    else if (failedCount >= 1) cronsAttention = 'amber';
  } else {
    const watcherErr = String(watcherJson.error?.message || watcherJson.error || 'Request failed');
    sessionsError = watcherErr;
    cronsError = watcherErr;
  }

  const memoryJson = parseJson('memory');
  let memoryHealth = 'red';
  let memoryDetail = 'Memory health unavailable';
  let memoryError = null;
  if (memoryJson.ok) {
    const checks = Array.isArray(memoryJson.data?.checks) ? memoryJson.data.checks : [];
    const statuses = checks.map((check) => String(check?.status || '').toLowerCase());
    if (checks.length > 0 && statuses.every((status) => status === 'green')) {
      memoryHealth = 'green';
      memoryDetail = 'All checks passing';
    } else if (statuses.some((status) => status === 'red')) {
      memoryHealth = 'red';
      memoryDetail = 'Critical memory check failed';
    } else {
      memoryHealth = 'amber';
      memoryDetail = checks.length ? 'Memory warnings present' : 'No memory checks reported';
    }
  } else {
    memoryError = String(memoryJson.error?.message || memoryJson.error || 'Request failed');
  }

  const securityJson = parseJson('security');
  let securityHealth = 'red';
  let securityDetail = 'Security health unavailable';
  let securityError = null;
  let securityOverallStatus = 'red';
  let securityCriticalFailures = 0;
  let securityTotalChecks = 0;
  if (securityJson.ok) {
    securityOverallStatus = String(securityJson.data?.overall_status || 'unknown').toLowerCase();
    securityHealth = mapHealthStatus(
      securityOverallStatus,
      ['green', 'secure', 'ok'],
      ['yellow', 'warning', 'degraded'],
      ['red', 'critical', 'failed']
    );
    if (Boolean(securityJson.data?.stale) && securityHealth !== 'red') securityHealth = 'amber';
    securityDetail = `Security ${securityOverallStatus}`;
    const checks = Array.isArray(securityJson.data?.checks) ? securityJson.data.checks : [];
    securityTotalChecks = checks.length;
    securityCriticalFailures = checks.filter((check) => {
      const status = String(check?.status || '').toLowerCase();
      const severity = String(check?.severity || '').toLowerCase();
      return status === 'red' && severity === 'critical';
    }).length;
  } else {
    securityError = String(securityJson.error?.message || securityJson.error || 'Request failed');
  }

  const tasksJson = parseJson('tasks');
  let tasksHealth = 'red';
  let tasksAttention = null;
  let tasksDetail = 'Tasks API unavailable';
  let tasksError = null;
  let tasksByStatus = {};
  if (tasksJson.ok && tasksJson.data && typeof tasksJson.data === 'object' && tasksJson.data.by_status && typeof tasksJson.data.by_status === 'object') {
    tasksHealth = 'green';
    tasksDetail = 'API responding';
    tasksByStatus = tasksJson.data.by_status;
    const inProgress = Number(tasksByStatus.in_progress || 0);
    if (Number.isFinite(inProgress) && inProgress > 0) tasksAttention = 'amber';
  } else {
    tasksError = tasksJson.ok ? 'Missing by_status in response' : String(tasksJson.error?.message || tasksJson.error || 'Request failed');
  }

  let costHealth = 'red';
  let costDetail = 'Quota state unavailable';
  let costError = null;
  let costAgeSeconds = 0;
  let costTokensToday = 0;

  if (costRead.ok) {
    try {
      const st = fs.statSync(COST_PATH);
      costAgeSeconds = Math.max(0, Math.round((Date.now() - st.mtimeMs) / 1000));
      costTokensToday = getTokensToday(costRead.data);
      if (costAgeSeconds < 3600) {
        costHealth = 'green';
        costDetail = 'Quota state fresh';
      } else {
        costHealth = 'amber';
        costDetail = 'Quota state stale';
      }
    } catch (error) {
      costError = String(error.message || error);
    }
  } else {
    costError = String(costRead.error?.message || costRead.error || 'Unable to read quota state');
  }

  if (!costRead.ok) failedSources += 1;

  const domains = {
    gateway: domainRecord(gatewayHealth, null, gatewayDetail, observedAt, 0, gatewayError),
    cortex: domainRecord(cortexHealth, null, cortexDetail, observedAt, 0, cortexError),
    sessions: domainRecord(sessionsHealth, null, sessionsDetail, observedAt, 0, sessionsError),
    memory: domainRecord(memoryHealth, null, memoryDetail, observedAt, 0, memoryError),
    security: domainRecord(securityHealth, null, securityDetail, observedAt, 0, securityError),
    crons: domainRecord(cronsHealth, cronsAttention, cronsDetail, observedAt, 0, cronsError),
    tasks: domainRecord(tasksHealth, tasksAttention, tasksDetail, observedAt, 0, tasksError),
    cost: domainRecord(costHealth, null, costDetail, observedAt, costAgeSeconds, costError),
  };

  const runEndedAt = Date.now();
  const state = {
    schema_version: 1,
    generated_at: new Date(runEndedAt).toISOString(),
    last_run_status: failedSources === 0 ? 'success' : 'partial',
    current_freshness: 'fresh',
    run_duration_ms: runEndedAt - runStartedAt,
    consecutive_skips: 0,
    heartbeat: {
      last_started: startedIso,
      last_completed: new Date(runEndedAt).toISOString(),
    },
    domains,
    stat_cards: {
      gateway: {
        status: gatewayHealth === 'green' ? 'connected' : gatewayHealth === 'amber' ? 'degraded' : 'down',
        uptime_seconds: null,
      },
      cost: {
        tokens_today: costTokensToday,
        delta_pct: null,
      },
      tasks: {
        review: Number(tasksByStatus.review || 0),
        in_progress: Number(tasksByStatus.in_progress || 0),
        proposed: Number(tasksByStatus.proposed || 0),
        blocked: Number(tasksByStatus.blocked || 0),
      },
      security: {
        overall_status: securityHealth,
        critical_failures: securityCriticalFailures,
        total_checks: securityTotalChecks,
      },
    },
  };

  const outputDir = join('/home/openclaw', '.openclaw', 'workspace');
  fs.mkdirSync(outputDir, { recursive: true });

  try {
    const tmpPath = `${STATE_PATH}.tmp`;
    fs.writeFileSync(tmpPath, `${JSON.stringify(state, null, 2)}\n`, 'utf8');
    const fd = fs.openSync(tmpPath, 'r');
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fs.renameSync(tmpPath, STATE_PATH);
    process.exit(0);
  } catch (error) {
    console.error('[overview-summarizer] write failed:', error.message);
    process.exit(1);
  }
}

main();
