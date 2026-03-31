#!/usr/bin/env node
'use strict';
const fs = require('fs');
const { execSync } = require('child_process');
const HISTORY_FILE = '/tmp/ops-health-history.json';
const SNAPSHOT_FILE = '/tmp/ops-health-metrics.json';
const MAX_HISTORY = 60;
const GATEWAY_PORT = 18789;
const GATEWAY_SERVICE = 'openclaw';

function safeExec(cmd, timeout = 5000) {
  try { return execSync(cmd, { encoding: 'utf8', timeout }).trim(); }
  catch { return ''; }
}
function readHistory() {
  try { const arr = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8')); return Array.isArray(arr) ? arr : []; }
  catch { return []; }
}
function atomicWrite(filepath, data) {
  const tmp = filepath + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data), 'utf8');
  fs.renameSync(tmp, filepath);
}
function collectDisk() {
  const line = safeExec("df -P / | tail -1");
  if (!line) return { used_pct: -1, free_bytes: -1, total_bytes: -1, used_bytes: -1 };
  const p = line.split(/\s+/);
  return {
    used_pct: parseInt((p[4] || '').replace('%', ''), 10) || 0,
    free_bytes: (parseInt(p[3], 10) || 0) * 1024,
    total_bytes: (parseInt(p[1], 10) || 0) * 1024,
    used_bytes: (parseInt(p[2], 10) || 0) * 1024
  };
}
function collectMemory() {
  const mi = safeExec("cat /proc/meminfo");
  const get = (k) => { const m = mi.match(new RegExp('^' + k + ':\\s+(\\d+)', 'm')); return m ? parseInt(m[1], 10) * 1024 : -1; };
  return { total_bytes: get('MemTotal'), available_bytes: get('MemAvailable'), free_bytes: get('MemFree') };
}
function collectGatewayProcess() {
  const pidStr = safeExec('systemctl show -p MainPID ' + GATEWAY_SERVICE + ' | cut -d= -f2');
  const pid = parseInt(pidStr, 10) || 0;
  if (pid <= 1) return { pid: 0, rss_bytes: -1, vm_size_bytes: -1 };
  const st = safeExec('cat /proc/' + pid + '/status 2>/dev/null');
  const getRss = () => { const m = st.match(/^VmRSS:\s+(\d+)/m); return m ? parseInt(m[1], 10) * 1024 : -1; };
  const getVm = () => { const m = st.match(/^VmSize:\s+(\d+)/m); return m ? parseInt(m[1], 10) * 1024 : -1; };
  return { pid, rss_bytes: getRss(), vm_size_bytes: getVm() };
}
function collectLatency() {
  try {
    const start = Date.now();
    execSync('curl -s -o /dev/null -w "" --max-time 3 http://127.0.0.1:' + GATEWAY_PORT + '/health', { encoding: 'utf8', timeout: 5000 });
    return Date.now() - start;
  } catch { return -1; }
}
function collectErrors() {
  const lines = safeExec('journalctl -u ' + GATEWAY_SERVICE + ' --since "60 seconds ago" --no-pager -q 2>/dev/null');
  const fatalCount = (lines.match(/FATAL|uncaughtException/gi) || []).length;
  const dmesg = safeExec("dmesg --time-format iso --since '60 seconds ago' 2>/dev/null || dmesg -T 2>/dev/null | tail -20");
  const oomKill = dmesg.includes('oom-kill') || dmesg.includes('Out of memory');
  return { fatal_count: fatalCount, oom_kill: oomKill };
}
function computeP95(history) {
  const vals = history.slice(-5).map(s => s.gateway_latency_ms).filter(v => v >= 0).sort((a, b) => a - b);
  if (!vals.length) return -1;
  return vals[Math.max(0, Math.ceil(0.95 * vals.length) - 1)];
}
function computeIncidents(history) {
  let n = 0;
  for (let i = 1; i < history.length; i++) {
    const prev = history[i - 1], curr = history[i];
    if (curr.gateway_pid !== prev.gateway_pid && prev.gateway_pid > 0 && curr.gateway_pid > 0) {
      if (prev.fatal_count > 0 || prev.oom_kill) n++;
    }
  }
  return n;
}
function computeStatus(snap) {
  let disk = 'green';
  if (snap.disk.free_bytes < 2147483648 || snap.disk.used_pct > 90) disk = 'red';
  else if (snap.disk.free_bytes < 4294967296 || snap.disk.used_pct > 80) disk = 'amber';
  let gwMem = 'green', gwSig = '';
  if (snap.gateway.rss_bytes > 838860800) { gwMem = 'red'; gwSig = 'gateway red'; }
  else if (snap.gateway.rss_bytes > 524288000) { gwMem = 'amber'; gwSig = 'gateway amber'; }
  let sysMem = 'green';
  if (snap.system_memory.available_bytes < 524288000) sysMem = 'red';
  else if (snap.system_memory.available_bytes < 1073741824) sysMem = 'amber';
  const rank = { green: 0, amber: 1, red: 2 };
  let memSt, memSig;
  if (rank[sysMem] > rank[gwMem]) { memSt = sysMem; memSig = 'system ' + sysMem; }
  else if (rank[gwMem] > rank[sysMem]) { memSt = gwMem; memSig = gwSig; }
  else { memSt = gwMem; memSig = ''; }
  let lat = 'green';
  if (snap.latency_p95_ms < 0) lat = 'unavailable';
  else if (snap.latency_p95_ms > 500) lat = 'red';
  else if (snap.latency_p95_ms > 150) lat = 'amber';
  let err = snap.incidents_1h > 0 ? 'red' : 'green';
  return { disk, memory: memSt, memory_signal: memSig, latency: lat, errors: err };
}
function main() {
  const now = new Date().toISOString();
  const disk = collectDisk();
  const sysMem = collectMemory();
  const gw = collectGatewayProcess();
  const latency = collectLatency();
  const errors = collectErrors();
  const sample = {
    sampled_at: now, disk_used_pct: disk.used_pct, disk_free_bytes: disk.free_bytes,
    disk_total_bytes: disk.total_bytes, disk_used_bytes: disk.used_bytes,
    system_mem_total_bytes: sysMem.total_bytes, system_mem_available_bytes: sysMem.available_bytes,
    gateway_pid: gw.pid, gateway_rss_bytes: gw.rss_bytes, gateway_vm_bytes: gw.vm_size_bytes,
    gateway_latency_ms: latency, fatal_count: errors.fatal_count, oom_kill: errors.oom_kill
  };
  const history = readHistory();
  history.push(sample);
  while (history.length > MAX_HISTORY) history.shift();
  atomicWrite(HISTORY_FILE, history);
  const p95 = computeP95(history);
  const incidents = computeIncidents(history);
  const snapshot = {
    sampled_at: now,
    disk: { used_pct: disk.used_pct, free_bytes: disk.free_bytes, total_bytes: disk.total_bytes, used_bytes: disk.used_bytes },
    system_memory: { total_bytes: sysMem.total_bytes, available_bytes: sysMem.available_bytes },
    gateway: { pid: gw.pid, rss_bytes: gw.rss_bytes },
    latency_p95_ms: p95, latency_last_ms: latency, incidents_1h: incidents, status: {}
  };
  snapshot.status = computeStatus(snapshot);
  atomicWrite(SNAPSHOT_FILE, snapshot);
  const mb = (b) => b > 0 ? Math.round(b / 1048576) + 'MB' : '?';
  console.log('disk=' + disk.used_pct + '% gw_rss=' + mb(gw.rss_bytes) + ' sys_avail=' + mb(sysMem.available_bytes) + ' lat_p95=' + p95 + 'ms incidents=' + incidents);
}
main();
