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

  const previousState = readJsonFileSafe(STATE_PATH);
  const previousOperationsCards = previousState.ok && previousState.data && typeof previousState.data === 'object'
    ? previousState.data.operations_cards
    : null;

  const operationsCardsGeneratedAt = new Date().toISOString();

  let servicesCard = {
    status: 'red',
    up: 0,
    total: 0,
    down_names: [],
    generated_at: operationsCardsGeneratedAt,
    source_last_success_at: null,
    source_error: null,
  };

  try {
    const servicesRes = await fetchJson('/api/ops/services/status', API_PORT, REQUEST_TIMEOUT_MS, controllers);
    if (!servicesRes.ok) throw new Error(`Unexpected status ${servicesRes.statusCode}`);
    const parsed = JSON.parse(servicesRes.body);
    const services = Array.isArray(parsed)
      ? parsed
      : Array.isArray(parsed?.services)
        ? parsed.services
        : [];
    const total = services.length;
    const isUp = (service) => {
      if (service?.active === true) return true;
      const s = String(service?.status || '').toLowerCase();
      return ['running', 'healthy', 'up', 'ok'].includes(s);
    };
    const up = services.filter(isUp).length;
    const downNames = services
      .filter((service) => !isUp(service))
      .map((service) => String(service?.name || service?.service || 'unknown'))
      .filter(Boolean);

    let status = 'red';
    if (total > 0 && up === total) status = 'green';
    else if (up > total / 2) status = 'amber';

    servicesCard = {
      status,
      up,
      total,
      down_names: downNames,
      generated_at: operationsCardsGeneratedAt,
      source_last_success_at: operationsCardsGeneratedAt,
      source_error: null,
    };
  } catch (error) {
    const previousServices = previousOperationsCards && typeof previousOperationsCards === 'object' ? previousOperationsCards.services : null;
    servicesCard = {
      status: 'red',
      up: Number(previousServices?.up || 0),
      total: Number(previousServices?.total || 0),
      down_names: Array.isArray(previousServices?.down_names) ? previousServices.down_names : [],
      generated_at: operationsCardsGeneratedAt,
      source_last_success_at: previousServices?.source_last_success_at || null,
      source_error: String(error.message || error || 'Request failed'),
    };
  }

  let jobsCard = {
    status: 'red',
    scheduler_health: {
      fired: 0,
      total: 0,
      missed: 0,
    },
    attention: {
      failing_count: 0,
      failing_names: [],
    },
    generated_at: operationsCardsGeneratedAt,
    source_last_success_at: null,
    source_error: null,
  };

  try {
    const jobsRes = await fetchJson('/api/cron/health', API_PORT, REQUEST_TIMEOUT_MS, controllers);
    if (!jobsRes.ok) throw new Error(`Unexpected status ${jobsRes.statusCode}`);
    const parsed = JSON.parse(jobsRes.body);
    const crons = Array.isArray(parsed) ? parsed : [];
    const DAY_MS = 24 * 60 * 60 * 1000;
    const enabledCrons = crons.filter((cron) => cron?.enabled === true);
    const fired = enabledCrons.filter((cron) => {
      const lastRunAtMs = Number(cron?.lastRunAtMs);
      if (!Number.isFinite(lastRunAtMs) || lastRunAtMs <= 0) return false;
      const ageMs = Date.now() - lastRunAtMs;
      const scheduleIntervalMs = Number(
        cron?.scheduleIntervalMs
          || cron?.intervalMs
          || cron?.runIntervalMs
          || cron?.everyMs
      );
      const expectedWindowMs = Number.isFinite(scheduleIntervalMs) && scheduleIntervalMs > 0
        ? Math.min(scheduleIntervalMs * 2, DAY_MS)
        : DAY_MS;
      return ageMs <= expectedWindowMs;
    }).length;
    const missed = enabledCrons.filter((cron) => {
      const lastRunAtMs = Number(cron?.lastRunAtMs);
      if (!Number.isFinite(lastRunAtMs) || lastRunAtMs <= 0) return true;
      return (Date.now() - lastRunAtMs) > DAY_MS;
    }).length;
    const failingNames = crons
      .filter((cron) => String(cron?.lastStatus || '').toLowerCase() !== 'ok' || Number(cron?.consecutiveErrors || 0) > 0)
      .map((cron) => String(cron?.name || 'unknown'))
      .filter(Boolean);

    const failingCount = failingNames.length;
    const status = missed > 0 ? 'red' : failingCount > 0 ? 'amber' : 'green';

    jobsCard = {
      status,
      scheduler_health: {
        fired,
        total: enabledCrons.length,
        missed,
      },
      attention: {
        failing_count: failingCount,
        failing_names: failingNames,
      },
      generated_at: operationsCardsGeneratedAt,
      source_last_success_at: operationsCardsGeneratedAt,
      source_error: null,
    };
  } catch (error) {
    jobsCard = {
      status: 'red',
      scheduler_health: {
        fired: 0,
        total: 0,
        missed: 0,
      },
      attention: {
        failing_count: 0,
        failing_names: [],
      },
      generated_at: operationsCardsGeneratedAt,
      source_last_success_at: null,
      source_error: String(error.message || error || 'Request failed'),
    };
  }

  let recoveryCard = {
    status: 'red',
    latest_age_seconds: null,
    latest_name: null,
    snapshot_count: 0,
    freshness: 'none',
    generated_at: operationsCardsGeneratedAt,
    source_last_success_at: null,
    source_error: null,
  };

  try {
    const recoveryRes = await fetchJson('/api/ops/backups', API_PORT, REQUEST_TIMEOUT_MS, controllers);
    if (!recoveryRes.ok) throw new Error(`Unexpected status ${recoveryRes.statusCode}`);
    const parsed = JSON.parse(recoveryRes.body);
    const backups = Array.isArray(parsed)
      ? parsed
      : Array.isArray(parsed?.backups)
        ? parsed.backups
        : [];

    const normalizeTimestampMs = (backup) => {
      const directMs = Number(
        backup?.timestampMs
          || backup?.createdAtMs
          || backup?.lastModifiedMs
          || backup?.ts
      );
      if (Number.isFinite(directMs) && directMs > 0) return directMs;
      const dateString = backup?.timestamp || backup?.createdAt || backup?.created_at || backup?.date;
      const parsedMs = Date.parse(dateString || '');
      return Number.isFinite(parsedMs) ? parsedMs : null;
    };

    const latestBackup = backups.reduce((latest, backup) => {
      const timestampMs = normalizeTimestampMs(backup);
      if (!Number.isFinite(timestampMs)) return latest;
      if (!latest || timestampMs > latest.timestampMs) {
        return { backup, timestampMs };
      }
      return latest;
    }, null);

    let freshness = 'none';
    let status = 'red';
    let latestAgeSeconds = null;
    let latestName = null;
    if (latestBackup) {
      latestAgeSeconds = Math.max(0, Math.round((Date.now() - latestBackup.timestampMs) / 1000));
      latestName = String(latestBackup.backup?.name || latestBackup.backup?.id || latestBackup.backup?.filename || 'latest-backup');
      if (latestAgeSeconds < 86400) {
        freshness = 'fresh';
        status = 'green';
      } else if (latestAgeSeconds <= 172800) {
        freshness = 'aging';
        status = 'amber';
      } else {
        freshness = 'stale';
        status = 'red';
      }
    }

    recoveryCard = {
      status,
      latest_age_seconds: latestAgeSeconds,
      latest_name: latestName,
      snapshot_count: backups.length,
      freshness,
      generated_at: operationsCardsGeneratedAt,
      source_last_success_at: operationsCardsGeneratedAt,
      source_error: null,
    };
  } catch (error) {
    recoveryCard = {
      status: 'red',
      latest_age_seconds: null,
      latest_name: null,
      snapshot_count: 0,
      freshness: 'none',
      generated_at: operationsCardsGeneratedAt,
      source_last_success_at: null,
      source_error: String(error.message || error || 'Request failed'),
    };
  }

  const operations_cards = {
    services: servicesCard,
    jobs: jobsCard,
    recovery: recoveryCard,
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
    operations_cards,
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
