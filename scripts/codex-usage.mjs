#!/usr/bin/env node
import { spawn } from 'node:child_process';

const codexBin = process.env.CODEX_BIN || 'codex';
const NAME = 'Codex CLI';

const proc = spawn(codexBin, ['app-server'], {
  stdio: ['pipe', 'pipe', 'pipe'],
});

let stdoutBuffer = '';
let stderrBuffer = '';
let done = false;
let initialized = false;

const timeout = setTimeout(() => {
  finishError('Timed out waiting for codex app-server response');
}, 10000);

function send(message) {
  try {
    proc.stdin.write(`${JSON.stringify(message)}\n`);
  } catch (err) {
    finishError(err?.message || 'Failed to write to codex app-server');
  }
}

function numOrNull(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function toIsoTimestamp(seconds) {
  const numeric = numOrNull(seconds);
  if (numeric === null) return null;
  if (numeric <= 0) return null;
  return new Date(numeric * 1000).toISOString();
}

function finish(payload, code = 0) {
  if (done) return;
  done = true;
  clearTimeout(timeout);
  try {
    proc.kill('SIGTERM');
  } catch {}
  process.stdout.write(JSON.stringify(payload));
  process.exit(code);
}

function finishError(message) {
  finish(
    {
      name: NAME,
      session_pct: null,
      session_reset: null,
      weekly_pct: null,
      weekly_reset: null,
      credits: null,
      plan: null,
      status: 'error',
      error: message || 'Unknown error',
    },
    1,
  );
}

function handleRateLimits(payload) {
  const data = payload?.rateLimits ?? payload ?? {};
  const primary = data?.primary ?? null;
  const secondary = data?.secondary ?? null;

  const sessionPct = numOrNull(primary?.usedPercent);
  const weeklyPct = numOrNull(secondary?.usedPercent);
  const sessionReset = toIsoTimestamp(primary?.resetsAt);
  const weeklyReset = toIsoTimestamp(secondary?.resetsAt);

  const credits =
    numOrNull(data?.credits) ??
    numOrNull(payload?.credits) ??
    numOrNull(payload?.creditsRemaining) ??
    numOrNull(payload?.balance?.credits) ??
    null;
  const plan = typeof (data?.plan ?? payload?.plan) === 'string' ? data?.plan ?? payload?.plan : null;

  let status = 'ok';
  if (sessionPct !== null && sessionPct >= 100) status = 'rate_limited';

  finish({
    name: NAME,
    session_pct: sessionPct,
    session_reset: sessionReset,
    weekly_pct: weeklyPct,
    weekly_reset: weeklyReset,
    credits,
    plan,
    status,
    error: null,
  });
}

function handleMessage(message) {
  if (message?.id === 0 && !initialized) {
    initialized = true;
    send({ method: 'initialized', params: {} });
    send({ method: 'account/rateLimits/read', id: 1, params: {} });
    return;
  }

  if (message?.id === 1) {
    if (message.error) {
      finishError(message.error?.message || 'account/rateLimits/read failed');
      return;
    }
    handleRateLimits(message.result ?? message.data ?? null);
  }
}

function processStdout() {
  let idx = stdoutBuffer.indexOf('\n');
  while (idx !== -1) {
    const line = stdoutBuffer.slice(0, idx).trim();
    stdoutBuffer = stdoutBuffer.slice(idx + 1);
    if (line) {
      try {
        const msg = JSON.parse(line);
        handleMessage(msg);
      } catch {}
    }
    idx = stdoutBuffer.indexOf('\n');
  }
}

proc.stderr.on('data', (chunk) => {
  stderrBuffer += chunk.toString('utf8');
});

proc.on('error', (err) => {
  finishError(err?.message || 'Failed to start codex app-server');
});

proc.on('exit', (code, signal) => {
  if (done) return;
  const reason = stderrBuffer.trim();
  const detail = reason || `codex app-server exited (${code ?? signal ?? 'unknown'})`;
  finishError(detail);
});

proc.stdout.on('data', (chunk) => {
  stdoutBuffer += chunk.toString('utf8');
  processStdout();
});

send({
  method: 'initialize',
  id: 0,
  params: {
    clientInfo: {
      name: 'clawd',
      title: 'Clawd Control',
      version: '1.0.0',
    },
  },
});
