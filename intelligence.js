'use strict';

const $ = s => document.querySelector(s);
const FETCH_OPTS = { credentials: 'same-origin' };
let analyticsData = null;
let tokenData = null;
let sentinelData = null;
let limitsData = [];
let budgetData = {};
let cronHealthData = [];
let costMode = 'daily';
let zone2AgentFilter = 'all';
let quotaInterval = null;
let lastAnalyticsLoad = 0;
const ANALYTICS_THROTTLE_MS = 10000;
const PANEL_STORAGE_KEY = 'intelligence-panels';

const BUILTIN_PRICING_MODELS = new Set([
  'gemini-2.5-flash',
  'gemini-2.0-flash',
  'claude-opus-4-5',
  'claude-sonnet-4-5',
  'claude-haiku-4-5',
  'gpt-4o',
  'gpt-4o-mini'
]);
const BUILTIN_PRICING_RATES = {
  'gemini-2.5-flash': { input: 0.15, output: 0.60, cacheRead: 0.0375, cacheWrite: 0.15 },
  'gemini-2.0-flash': { input: 0.10, output: 0.40, cacheRead: 0.025, cacheWrite: 0.10 },
  'claude-opus-4-5': { input: 15.00, output: 75.00, cacheRead: 1.50, cacheWrite: 15.00 },
  'claude-sonnet-4-5': { input: 3.00, output: 15.00, cacheRead: 0.30, cacheWrite: 3.00 },
  'claude-haiku-4-5': { input: 0.80, output: 4.00, cacheRead: 0.08, cacheWrite: 0.80 },
  'gpt-4o': { input: 2.50, output: 10.00, cacheRead: 1.25, cacheWrite: 2.50 },
  'gpt-4o-mini': { input: 0.15, output: 0.60, cacheRead: 0.075, cacheWrite: 0.15 }
};

let settingsState = {
  pricing: {},
  budget: {},
  sentinel: {},
  rateLimits: []
};

function toggleSettingsPanel() {
  const overlay = $('#settingsOverlay');
  if (!overlay) return;
  const isOpen = overlay.style.display !== 'none';
  if (isOpen) {
    overlay.style.display = 'none';
    return;
  }
  overlay.style.display = 'block';
  loadSettingsData();
}

async function loadSettingsData() {
  const pricingSection = $('#settingsPricing');
  const budgetSection = $('#settingsBudget');
  const sentinelSection = $('#settingsSentinel');
  const rateLimitsSection = $('#settingsRateLimits');
  const loadingHtml = '<div class="loading-state"><div class="icon">⏳</div><p>Loading settings...</p></div>';
  pricingSection.innerHTML = loadingHtml;
  budgetSection.innerHTML = loadingHtml;
  sentinelSection.innerHTML = loadingHtml;
  rateLimitsSection.innerHTML = loadingHtml;

  try {
    const [pricingRes, budgetRes, sentinelRes, rateLimitsRes] = await Promise.all([
      fetch('/api/config/pricing', FETCH_OPTS),
      fetch('/api/config/budget', FETCH_OPTS),
      fetch('/api/config/sentinel', FETCH_OPTS),
      fetch('/api/config/rate-limits', FETCH_OPTS),
    ]);

    settingsState.pricing = pricingRes.ok ? await pricingRes.json() : {};
    settingsState.budget = budgetRes.ok ? await budgetRes.json() : {};
    settingsState.sentinel = sentinelRes.ok ? await sentinelRes.json() : {};
    settingsState.rateLimits = rateLimitsRes.ok ? await rateLimitsRes.json() : [];

    renderPricingSettings();
    renderBudgetSettings();
    renderSentinelSettings();
    renderRateLimitsSettings();
    refreshIcons();
  } catch (e) {
    console.error('Failed loading settings:', e);
    if (typeof showToast === 'function') showToast('Failed to load settings', 'error');
  }
}

function settingError(id, msg = '') {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg;
  el.style.display = msg ? 'block' : 'none';
}

function clearSettingErrors(sectionId) {
  document.querySelectorAll(`#${sectionId} .settings-error`).forEach(el => {
    el.textContent = '';
    el.style.display = 'none';
  });
}

document.addEventListener('input', (e) => {
  if (e.target.classList.contains('settings-input')) {
    const errId = e.target.dataset.error;
    if (errId) settingError(errId, '');
  }
});

function renderPricingSettings() {
  const root = $('#settingsPricing');
  if (!root) return;
  const customEntries = settingsState.pricing || {};
  const knownModels = new Set(Object.keys(analyticsData?.byModel || {}));
  const customModels = new Set(Object.keys(customEntries || {}));
  const rows = [];

  for (const model of knownModels) {
    if (!BUILTIN_PRICING_MODELS.has(model) && !customModels.has(model)) {
      rows.push({ model, source: 'no-pricing', rates: {} });
    }
  }
  for (const model of BUILTIN_PRICING_MODELS) rows.push({ model, source: 'built-in', rates: BUILTIN_PRICING_RATES[model] || {} });
  for (const [model, rates] of Object.entries(customEntries || {})) {
    rows.push({ model, source: 'custom', rates: rates || {} });
  }

  root.innerHTML = `
    <div class="settings-section-title">Model Pricing</div>
    <table class="settings-table">
      <thead>
        <tr><th>Model</th><th>Input</th><th>Output</th><th>Cache Read</th><th>Cache Write</th><th>Source</th><th></th></tr>
      </thead>
      <tbody id="pricingRows">
        ${rows.map((row, idx) => pricingRowHtml(row, idx)).join('')}
      </tbody>
    </table>
    <div class="settings-error" id="pricingError"></div>
    <button class="settings-add-btn" onclick="addPricingRow()">Add Model</button>
    <button class="settings-save-btn" onclick="savePricingSettings()">Save Pricing</button>
  `;
}

function pricingRowHtml(row, idx) {
  const isCustom = row.source !== 'built-in';
  const readOnly = isCustom ? '' : 'readonly';
  const disabledDelete = isCustom ? '' : 'disabled';
  const modelValue = row.model || '';
  const inVal = row.rates.input ?? '';
  const outVal = row.rates.output ?? '';
  const crVal = row.rates.cacheRead ?? '';
  const cwVal = row.rates.cacheWrite ?? '';
  const badgeClass = row.source === 'no-pricing' ? 'no-pricing-badge' : 'source-badge';
  return `
    <tr class="pricing-row" data-source="${row.source}" data-index="${idx}">
      <td><input class="settings-input" data-key="model" value="${escapeHtml(modelValue)}" ${row.source === 'built-in' ? 'readonly' : ''}></td>
      <td><input class="settings-input" data-key="input" type="number" min="0" step="0.000001" value="${inVal}" ${readOnly}></td>
      <td><input class="settings-input" data-key="output" type="number" min="0" step="0.000001" value="${outVal}" ${readOnly}></td>
      <td><input class="settings-input" data-key="cacheRead" type="number" min="0" step="0.000001" value="${crVal}" ${readOnly}></td>
      <td><input class="settings-input" data-key="cacheWrite" type="number" min="0" step="0.000001" value="${cwVal}" ${readOnly}></td>
      <td><span class="${badgeClass}">${row.source}</span></td>
      <td>${isCustom ? `<button class="settings-row-delete" onclick="removePricingRow(this)">Delete</button>` : `<button class="settings-row-delete" ${disabledDelete}>Delete</button>`}</td>
    </tr>
  `;
}

function addPricingRow() {
  const tbody = $('#pricingRows');
  if (!tbody) return;
  const idx = tbody.querySelectorAll('tr').length;
  tbody.insertAdjacentHTML('beforeend', pricingRowHtml({ model: '', source: 'custom', rates: {} }, idx));
}

function removePricingRow(btn) {
  const row = btn?.closest('tr');
  if (row) row.remove();
}

async function savePricingSettings() {
  settingError('pricingError', '');
  const rows = [...document.querySelectorAll('#pricingRows tr')];
  const payload = {};

  for (const row of rows) {
    const source = row.dataset.source;
    if (source === 'built-in') continue;
    const model = row.querySelector('[data-key="model"]').value.trim();
    if (!model) {
      settingError('pricingError', 'Model name is required for custom pricing rows.');
      return;
    }
    const rates = {};
    for (const key of ['input', 'output', 'cacheRead', 'cacheWrite']) {
      const raw = row.querySelector(`[data-key="${key}"]`).value.trim();
      if (!raw) {
        settingError('pricingError', 'All pricing fields must be provided for custom rows.');
        return;
      }
      const num = Number(raw);
      if (!Number.isFinite(num) || num <= 0) {
        settingError('pricingError', 'Pricing values must be positive numbers.');
        return;
      }
      rates[key] = num;
    }
    payload[model] = rates;
  }

  try {
    const res = await fetch('/api/config/pricing', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('pricing_save_failed');
    if (typeof showToast === 'function') showToast('Pricing settings saved', 'success');
    await loadAnalytics();
    await loadSettingsData();
  } catch (e) {
    console.error(e);
    if (typeof showToast === 'function') showToast('Failed to save pricing settings', 'error');
  }
}

function renderBudgetSettings() {
  const root = $('#settingsBudget');
  if (!root) return;
  root.innerHTML = `
    <div class="settings-section-title">Budget Thresholds</div>
    <div class="settings-field">
      <label class="settings-label">Daily Budget ($)</label>
      <input class="settings-input" id="budgetDailyInput" data-error="budgetError" type="number" min="0" step="0.01" value="${settingsState.budget?.daily ?? ''}">
    </div>
    <div class="settings-field">
      <label class="settings-label">Weekly Budget ($)</label>
      <input class="settings-input" id="budgetWeeklyInput" data-error="budgetError" type="number" min="0" step="0.01" value="${settingsState.budget?.weekly ?? ''}">
    </div>
    <div class="settings-error" id="budgetError"></div>
    <button class="settings-save-btn" onclick="saveBudgetSettings()">Save Budget</button>
  `;
}

async function saveBudgetSettings() {
  settingError('budgetError', '');
  const dailyRaw = $('#budgetDailyInput')?.value.trim() || '';
  const weeklyRaw = $('#budgetWeeklyInput')?.value.trim() || '';
  const payload = {};

  if (dailyRaw) {
    const daily = Number(dailyRaw);
    if (!Number.isFinite(daily) || daily < 0) return settingError('budgetError', 'Daily budget must be a non-negative number.');
    payload.daily = daily;
  }
  if (weeklyRaw) {
    const weekly = Number(weeklyRaw);
    if (!Number.isFinite(weekly) || weekly < 0) return settingError('budgetError', 'Weekly budget must be a non-negative number.');
    payload.weekly = weekly;
  }

  try {
    const res = await fetch('/api/config/budget', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('budget_save_failed');
    if (typeof showToast === 'function') showToast('Budget settings saved', 'success');
  } catch (e) {
    console.error(e);
    if (typeof showToast === 'function') showToast('Failed to save budget settings', 'error');
  }
}

function renderSentinelSettings() {
  const root = $('#settingsSentinel');
  if (!root) return;
  const s = settingsState.sentinel || {};
  const fields = [
    ['agentConcentrationWarn', 'Agent Concentration Warn (%)'],
    ['agentConcentrationCritical', 'Agent Concentration Critical (%)'],
    ['dailyBudgetWarn', 'Daily Budget Warn ($)'],
    ['dailyBudgetCritical', 'Daily Budget Critical ($)'],
    ['sessionVolumeWarn', 'Session Volume Warn'],
    ['sessionVolumeCritical', 'Session Volume Critical'],
    ['weeklyTrendMultiplier', 'Weekly Trend Multiplier (x)'],
    ['alertCooldownHours', 'Alert Cooldown (hours)']
  ];

  root.innerHTML = `
    <div class="settings-section-title">Sentinel Thresholds</div>
    ${fields.map(([key, label]) => `
      <div class="settings-field">
        <label class="settings-label">${label}</label>
        <input class="settings-input" type="number" min="0" step="0.01" data-sentinel-key="${key}" data-error="sentinelError" value="${s[key] ?? ''}">
      </div>
    `).join('')}
    <div class="settings-error" id="sentinelError"></div>
    <button class="settings-save-btn" onclick="saveSentinelSettings()">Save Sentinel</button>
  `;
}

async function saveSentinelSettings() {
  settingError('sentinelError', '');
  const payload = {};
  const inputs = [...document.querySelectorAll('[data-sentinel-key]')];
  for (const input of inputs) {
    const key = input.dataset.sentinelKey;
    const raw = input.value.trim();
    if (!raw) continue;
    const num = Number(raw);
    if (!Number.isFinite(num) || num < 0) {
      settingError('sentinelError', 'Sentinel values must be non-negative numbers.');
      return;
    }
    if (key === 'weeklyTrendMultiplier' && num <= 0) {
      settingError('sentinelError', 'Weekly trend multiplier must be greater than 0.');
      return;
    }
    payload[key] = num;
  }

  try {
    const res = await fetch('/api/config/sentinel', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('sentinel_save_failed');
    if (typeof showToast === 'function') showToast('Sentinel settings saved', 'success');
  } catch (e) {
    console.error(e);
    if (typeof showToast === 'function') showToast('Failed to save sentinel settings', 'error');
  }
}

function renderRateLimitsSettings() {
  const root = $('#settingsRateLimits');
  if (!root) return;
  const rows = Array.isArray(settingsState.rateLimits) ? settingsState.rateLimits : [];
  root.innerHTML = `
    <div class="settings-section-title">Rate Limits</div>
    <table class="settings-table">
      <thead>
        <tr><th>Provider</th><th>Model</th><th>Type</th><th>Label</th><th>Limit</th><th>Source</th><th></th></tr>
      </thead>
      <tbody id="rateLimitRows">
        ${rows.map((row, idx) => rateLimitRowHtml(row, idx)).join('')}
      </tbody>
    </table>
    <div class="settings-error" id="rateLimitError"></div>
    <button class="settings-add-btn" onclick="addRateLimitRow()">Add Rate Limit</button>
    <button class="settings-save-btn" onclick="saveRateLimitsSettings()">Save Rate Limits</button>
  `;
}

function rateLimitRowHtml(row = {}, idx = 0) {
  return `
    <tr data-index="${idx}">
      <td><input class="settings-input" data-key="provider" value="${escapeHtml(String(row.provider || ''))}"></td>
      <td><input class="settings-input" data-key="model" value="${escapeHtml(String(row.model || ''))}"></td>
      <td><input class="settings-input" data-key="limitType" value="${escapeHtml(String(row.limitType || ''))}"></td>
      <td><input class="settings-input" data-key="label" value="${escapeHtml(String(row.label || ''))}"></td>
      <td><input class="settings-input" data-key="limit" type="number" min="0" step="1" value="${Number.isFinite(Number(row.limit)) ? Number(row.limit) : ''}"></td>
      <td><input class="settings-input" data-key="source" value="${escapeHtml(String(row.source || 'manual'))}"></td>
      <td><button class="settings-row-delete" onclick="removeRateLimitRow(this)">Delete</button></td>
    </tr>
  `;
}

function addRateLimitRow() {
  const tbody = $('#rateLimitRows');
  if (!tbody) return;
  tbody.insertAdjacentHTML('beforeend', rateLimitRowHtml({}, tbody.querySelectorAll('tr').length));
}

function removeRateLimitRow(btn) {
  const row = btn?.closest('tr');
  if (row) row.remove();
}

async function saveRateLimitsSettings() {
  settingError('rateLimitError', '');
  const rows = [...document.querySelectorAll('#rateLimitRows tr')];
  const payload = [];

  for (const row of rows) {
    const provider = row.querySelector('[data-key="provider"]').value.trim();
    const model = row.querySelector('[data-key="model"]').value.trim();
    const limitType = row.querySelector('[data-key="limitType"]').value.trim();
    const label = row.querySelector('[data-key="label"]').value.trim();
    const source = row.querySelector('[data-key="source"]').value.trim();
    const limitRaw = row.querySelector('[data-key="limit"]').value.trim();

    if (!provider || !model || !limitType || !label || !limitRaw) {
      settingError('rateLimitError', 'Provider, model, limit type, label, and limit are required.');
      return;
    }

    const limit = Number(limitRaw);
    if (!Number.isFinite(limit) || limit <= 0) {
      settingError('rateLimitError', 'Rate limit value must be a positive number.');
      return;
    }

    payload.push({ provider, model, limitType, label, limit, source: source || 'manual' });
  }

  try {
    const res = await fetch('/api/config/rate-limits', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(payload)
    });
    if (!res.ok) throw new Error('rate_limits_save_failed');
    if (typeof showToast === 'function') showToast('Rate limit settings saved', 'success');
  } catch (e) {
    console.error(e);
    if (typeof showToast === 'function') showToast('Failed to save rate limit settings', 'error');
  }
}

function isTrendsPanelOpen() {
  const panel = document.querySelector('.zone3-panel[data-panel="trends"]');
  return !!panel && panel.classList.contains('open');
}

function persistPanelState() {
  try {
    const states = {};
    document.querySelectorAll('.zone3-panel').forEach(panel => {
      const panelId = panel.dataset.panel;
      states[panelId] = panel.classList.contains('open');
    });
    localStorage.setItem(PANEL_STORAGE_KEY, JSON.stringify(states));
  } catch (_) {
    // ignore storage access errors
  }
}

function togglePanel(panelId) {
  const panel = document.querySelector(`.zone3-panel[data-panel="${panelId}"]`);
  if (!panel) return;
  const body = panel.querySelector('.zone3-panel-body');
  if (!body) return;

  const shouldOpen = !panel.classList.contains('open');
  panel.classList.toggle('open', shouldOpen);
  body.style.display = shouldOpen ? 'block' : 'none';
  persistPanelState();

  if (shouldOpen && panelId === 'trends') {
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        renderCostOverTime();
        renderAgentCostChart();
      });
    });
  }
}

function initPanelStates() {
  let savedStates = {};
  try {
    const raw = localStorage.getItem(PANEL_STORAGE_KEY);
    savedStates = raw ? JSON.parse(raw) : {};
  } catch (_) {
    savedStates = {};
  }

  document.querySelectorAll('.zone3-panel').forEach(panel => {
    const panelId = panel.dataset.panel;
    const body = panel.querySelector('.zone3-panel-body');
    const isOpen = savedStates[panelId] === true;
    panel.classList.toggle('open', isOpen);
    if (body) body.style.display = isOpen ? 'block' : 'none';
  });
}

// ═══════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════

document.addEventListener('layout:snapshot', () => {
  initPanelStates();
  populateAgentSelect();
  throttledLoadAnalytics();
});


document.querySelectorAll('.time-pill').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.time-pill').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    loadAnalytics();
  });
});

// Visibility-aware polling: pause when tab is hidden, resume when visible
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    stopQuotaPolling();
  } else {
    startQuotaPolling();
    throttledLoadAnalytics();
  }
});

setTimeout(() => {
  startQuotaPolling();
  if (!analyticsData) loadAnalytics();
}, 500);

let resizeTimer;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    if (analyticsData) {
      renderAll();
      renderTokenUsageChart();
      renderApiCostChart();
      if (isTrendsPanelOpen()) {
        renderCostOverTime();
        renderAgentCostChart();
      }
    }
  }, 200);
});

function populateAgentSelect() {
  const select = $('#agentSelect');
  const ids = Object.keys(agentState).sort();
  const agentOptions = ids.map(id => {
    const a = agentState[id];
    return `<option value="${id}">${a.emoji || '🤖'} ${a.name || id}</option>`;
  }).join('');
  select.innerHTML = '<option value="all">All Agents</option>' + agentOptions;
}

function setCostMode(mode, btn) {
  costMode = mode;
  document.querySelectorAll('.view-toggle button').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderCostOverTime();
}

function startQuotaPolling() {
  stopQuotaPolling();
  loadLimits();
  quotaInterval = setInterval(loadLimits, 30000);
}

function stopQuotaPolling() {
  if (quotaInterval) {
    clearInterval(quotaInterval);
    quotaInterval = null;
  }
}

function throttledLoadAnalytics() {
  const now = Date.now();
  if (now - lastAnalyticsLoad < ANALYTICS_THROTTLE_MS) return;
  lastAnalyticsLoad = now;
  loadAnalytics();
}

window.cleanupAnalyticsPage = function() {
  stopQuotaPolling();
};

function quotaColor(pct) {
  if (pct >= 80) return '#f87171';
  if (pct >= 60) return '#facc15';
  return '#4ade80';
}

function updateQuotaBar(labelId, fillId, used = 0, limit = 0) {
  const labelEl = $(labelId);
  const fillEl = $(fillId);
  if (!labelEl || !fillEl) return;
  const safeUsed = Number.isFinite(used) ? used : 0;
  const safeLimit = Number.isFinite(limit) ? limit : 0;
  const pct = safeLimit > 0 ? (safeUsed / safeLimit) * 100 : 0;
  const boundedPct = Math.min(pct, 100);

  labelEl.textContent = `${safeUsed} / ${safeLimit} (${Math.round(pct)}%)`;
  fillEl.style.width = `${boundedPct}%`;
  fillEl.style.backgroundColor = quotaColor(pct);
}

async function loadLimits() {
  try {
    const res = await fetch('/api/limits', FETCH_OPTS);
    if (!res.ok) throw new Error('limits_not_ok');
    const data = await res.json();
    limitsData = Array.isArray(data) ? data : [];
  } catch (e) {
    console.error('Limits fetch failed:', e);
    limitsData = [];
  }
  renderRateLimits();
}

// ═══════════════════════════════════════════
// LOAD DATA (both endpoints)
// ═══════════════════════════════════════════

function getSelectedRange() {
  const active = document.querySelector('.time-pill.active');
  return active ? active.dataset.range : '7';
}

async function loadAnalytics() {
  const range = getSelectedRange();
  const agent = $('#agentSelect').value;

  try {
    const [aRes, tRes, sRes, lRes, bRes, cRes] = await Promise.all([
      fetch(`/api/analytics?range=${range}&agent=${agent}`),
      fetch(`/api/tokens?range=${range}&agent=${agent}`),
      fetch('/api/costs/sentinel', FETCH_OPTS),
      fetch('/api/limits', FETCH_OPTS),
      fetch('/api/costs/budget', FETCH_OPTS),
      fetch('/api/cron/health', FETCH_OPTS)
    ]);
    analyticsData = await aRes.json();
    tokenData = await tRes.json();
    sentinelData = await sRes.json();
    limitsData = lRes.ok ? await lRes.json() : [];
    budgetData = bRes.ok ? await bRes.json() : {};
    const cronPayload = cRes.ok ? await cRes.json() : [];
    cronHealthData = Array.isArray(cronPayload) ? cronPayload : [];
    renderAll();
  } catch (e) {
    budgetData = {};
    cronHealthData = [];
    console.error('Failed to load analytics:', e);
    if (typeof showToast === 'function') showToast('Failed to load analytics data', 'error');
  }
}

// ═══════════════════════════════════════════
// RENDER ALL
// ═══════════════════════════════════════════

function renderAll() {
  if (!analyticsData) return;

  renderCostVelocity();
  renderRateLimits();
  renderBudgetBars();
  renderZone2Tabs();
  renderConcentrationBanner();
  renderTokenUsageChart();
  renderApiCostChart();
  renderCronHealth();
  renderStats();
  renderCostBreakdown();
  renderBySource();
  renderInsight();
  renderCostByAgent();
  renderTokenBreakdown();
  renderCostOverTime();
  renderTopSessions();
  renderCostByModel();
  renderProjections();
  renderAgentCostChart();
  renderTopCrons();
  renderCostSentinel();

  refreshIcons();
}

function pricingMeta() {
  const coverage = analyticsData?.pricingCoverage || 'full';
  return {
    coverage,
    isNone: coverage === 'none',
    isPartial: coverage === 'partial',
    suffix: coverage === 'partial' ? ' (partial)' : ''
  };
}

function renderCostVelocity() {
  const container = $('#costVelocityCard');
  if (!container || !analyticsData) return;
  const timeline = analyticsData.overTime || [];
  const today = timeline[timeline.length - 1] || { tokens: 0, cost: 0 };
  const elapsedHours = Math.max((Date.now() - new Date(new Date().toISOString().split('T')[0]).getTime()) / 36e5, 1);
  const tokenProjection = (today.tokens || 0) / elapsedHours * 24;
  const costProjection = (today.cost || 0) / elapsedHours * 24;
  const last7 = timeline.slice(-7);
  const avgTokens = last7.length ? last7.reduce((s, d) => s + (d.tokens || 0), 0) / last7.length : 0;
  const avgCost = last7.length ? last7.reduce((s, d) => s + (d.cost || 0), 0) / last7.length : 0;
  const tokenDelta = avgTokens > 0 ? ((tokenProjection - avgTokens) / avgTokens) * 100 : 0;
  const deltaClass = tokenProjection > avgTokens * 2 ? 'delta-critical' : tokenProjection > avgTokens * 1.5 ? 'delta-warn' : 'delta-good';
  const pm = pricingMeta();

  $('#velocityCoverage').innerHTML = pm.isNone ? 'No pricing data' : (pm.isPartial ? '<span class="partial-badge">partial pricing</span>' : 'Pricing coverage: full');
  container.innerHTML = `
    <div class="velocity-metric primary">
      <div class="velocity-label">Tokens today</div>
      <div class="velocity-value">${formatNumber(today.tokens || 0)} tokens</div>
      <div class="velocity-sub">24h projection ${formatNumber(tokenProjection)} · 7d avg ${formatNumber(avgTokens)}
        <span class="delta-badge ${deltaClass}">${tokenDelta >= 0 ? '+' : ''}${tokenDelta.toFixed(0)}%</span>
      </div>
    </div>
    <div class="velocity-metric">
      <div class="velocity-label">Cost today ${pm.isPartial ? '<span class="partial-badge">partial</span>' : ''}</div>
      <div class="velocity-value">${pm.isNone ? 'No pricing data' : `$${(today.cost || 0).toFixed(2)}`}</div>
      <div class="velocity-sub">7d avg ${pm.isNone ? '—' : `$${avgCost.toFixed(2)}`}</div>
    </div>
    <div class="velocity-metric">
      <div class="velocity-label">24h projection</div>
      <div class="velocity-value">${pm.isNone ? formatNumber(tokenProjection) + ' tok' : `$${costProjection.toFixed(2)}`}</div>
      <div class="velocity-sub">${pm.isNone ? 'Token pace extrapolated' : 'Cost pace extrapolated'}</div>
    </div>
  `;
}

function renderRateLimits() {
  const container = $('#rateLimitsList');
  if (!container) return;
  if (!Array.isArray(limitsData) || limitsData.length === 0) {
    container.innerHTML = '<div class="empty-state" style="padding:18px 20px"><p>No rate limit data</p></div>';
    return;
  }
  const sourceLabel = { verified: 'Live', header: 'Tracked', 'self-tracked': 'Est.' };
  const rows = [...limitsData].map(item => {
    const used = Number(item.used) || 0;
    const limit = Number(item.limit) || 0;
    const pct = limit > 0 ? (used / limit) * 100 : 0;
    return { ...item, used, limit, pct };
  }).sort((a, b) => b.pct - a.pct);

  container.innerHTML = rows.map(row => {
    const color = quotaColor(row.pct);
    const pct = Math.max(0, Math.min(100, row.pct));
    const model = row.model ? String(row.model) : 'unknown';
    const limitType = (row.limitType || '').toUpperCase();
    return `<div class="limit-row">
      <div class="limit-head">
        <div class="limit-name">${escapeHtml(model)} — ${escapeHtml(limitType)}</div>
        <div class="limit-meta">${row.used} / ${row.limit} (${Math.round(row.pct)}%) <span class="source-badge">${escapeHtml(sourceLabel[row.source] || 'Tracked')}</span></div>
      </div>
      <div class="quota-track"><div class="quota-fill" style="width:${pct}%;background:${color}"></div></div>
    </div>`;
  }).join('');
}


function renderBudgetBars() {
  const section = $('#budgetBarsSection');
  if (!section || !analyticsData) return;

  const pm = pricingMeta();

  if (pm.isNone) {
    section.style.display = '';
    section.innerHTML = '<div class="budget-no-config">Budget tracking requires pricing data. Enable pricing to compare spend against daily/weekly budgets.</div>';
    return;
  }

  section.innerHTML = `
    <div class="budget-bar-row">
      <div class="budget-bar-label">
        <span class="budget-bar-name">Daily Budget</span>
        <span class="budget-bar-values" id="budgetDailyValues">—</span>
      </div>
      <div class="quota-track"><div class="quota-fill" id="budgetDailyFill" style="width:0%"></div></div>
    </div>
    <div class="budget-bar-row">
      <div class="budget-bar-label">
        <span class="budget-bar-name">Weekly Budget</span>
        <span class="budget-bar-values" id="budgetWeeklyValues">—</span>
      </div>
      <div class="quota-track"><div class="quota-fill" id="budgetWeeklyFill" style="width:0%"></div></div>
    </div>
  `;

  const safeBudget = budgetData && typeof budgetData === 'object' ? budgetData : {};
  const hasDaily = Number(safeBudget.daily) > 0;
  const hasWeekly = Number(safeBudget.weekly) > 0;

  if (!hasDaily && !hasWeekly) {
    section.innerHTML = '<div class="budget-no-config">No budget set. Configure daily and weekly budgets in Settings to track spend progress.</div>';
    section.style.display = '';
    return;
  }

  const timeSeries = Array.isArray(analyticsData.overTime) ? analyticsData.overTime : [];
  const todaySpend = Number(timeSeries[timeSeries.length - 1]?.cost) || 0;
  const weeklySpend = getSelectedRange() === '7'
    ? (Number(analyticsData.totalCost) || 0)
    : timeSeries.slice(-7).reduce((sum, day) => sum + (Number(day?.cost) || 0), 0);

  const dailyValuesEl = $('#budgetDailyValues');
  const weeklyValuesEl = $('#budgetWeeklyValues');
  const dailyFillEl = $('#budgetDailyFill');
  const weeklyFillEl = $('#budgetWeeklyFill');

  if (dailyValuesEl && dailyFillEl) {
    if (hasDaily) {
      const pct = (todaySpend / Number(safeBudget.daily)) * 100;
      dailyValuesEl.textContent = `${formatCurrency(todaySpend)} / ${formatCurrency(Number(safeBudget.daily))} (${Math.round(pct)}%)`;
      dailyFillEl.style.width = `${Math.max(0, Math.min(100, pct))}%`;
      dailyFillEl.style.backgroundColor = quotaColor(pct);
    } else {
      dailyValuesEl.textContent = 'Not set';
      dailyFillEl.style.width = '0%';
    }
  }

  if (weeklyValuesEl && weeklyFillEl) {
    if (hasWeekly) {
      const pct = (weeklySpend / Number(safeBudget.weekly)) * 100;
      weeklyValuesEl.textContent = `${formatCurrency(weeklySpend)} / ${formatCurrency(Number(safeBudget.weekly))} (${Math.round(pct)}%)`;
      weeklyFillEl.style.width = `${Math.max(0, Math.min(100, pct))}%`;
      weeklyFillEl.style.backgroundColor = quotaColor(pct);
    } else {
      weeklyValuesEl.textContent = 'Not set';
      weeklyFillEl.style.width = '0%';
    }
  }

  section.style.display = '';
}

function renderCostSentinel() {
  const container = $('#costSentinelCard');
  if (!container) return;

  const checks = sentinelData?.checks && typeof sentinelData.checks === 'object' ? sentinelData.checks : null;
  if (!sentinelData || sentinelData.error === 'no_data' || !checks) {
    container.innerHTML = `
      <div class="empty-state" style="padding:22px 20px">
        <div class="icon">🕒</div>
        <p>Sentinel: No data</p>
      </div>
    `;
    return;
  }

  const statusPriority = { ok: 0, skip: 1, warn: 2, critical: 3 };
  const checkOrder = [
    ['agent_concentration', 'Agent Concentration'],
    ['daily_budget', 'Daily Budget'],
    ['cron_error_loop', 'Cron Error Loop'],
    ['session_volume', 'Session Volume'],
    ['weekly_trend', 'Weekly Trend']
  ];

  let overall = 'ok';
  const rows = checkOrder.map(([key, label]) => {
    const item = checks[key] || {};
    const status = ['ok', 'warn', 'critical', 'skip'].includes(item.status) ? item.status : 'skip';
    if ((statusPriority[status] || 0) > (statusPriority[overall] || 0)) {
      overall = status;
    }
    return {
      label,
      status,
      detail: item.detail || 'No detail provided',
      threshold: item.threshold || '—'
    };
  });

  const formatTs = (value) => value ? new Date(value).toLocaleString() : 'none';

  container.innerHTML = `
    <div class="sentinel-header">
      <div class="sentinel-overall">
        <span class="sentinel-dot sentinel-status-${overall}"></span>
        Overall: ${overall}
      </div>
    </div>
    <div class="sentinel-list">
      ${rows.map(row => `
        <div class="sentinel-row">
          <div class="sentinel-label-wrap">
            <div class="sentinel-label">
              <span class="sentinel-dot sentinel-status-${row.status}"></span>
              ${escapeHtml(row.label)}
            </div>
            <div class="sentinel-threshold">Threshold: ${escapeHtml(String(row.threshold))}</div>
          </div>
          <div class="sentinel-detail">${escapeHtml(row.detail)}</div>
        </div>
      `).join('')}
    </div>
    <div class="sentinel-footer">
      <span>Last run: ${escapeHtml(formatTs(sentinelData.timestamp || null))}</span>
      <span>Last alert: ${escapeHtml(formatTs(sentinelData.alerts_sent ? sentinelData.timestamp : null))}</span>
    </div>
  `;
}


function formatRelativeTime(ms) {
  const ts = Number(ms) || 0;
  if (ts <= 0) return 'never';
  const diff = Math.max(Date.now() - ts, 0);
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

function formatDurationMs(ms) {
  const value = Number(ms) || 0;
  if (value <= 0) return '—';
  const totalSec = Math.round(value / 1000);
  if (totalSec < 60) return `${totalSec}s`;
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return s === 0 ? `${m}m` : `${m}m ${s}s`;
}

function estimateCronCostPerRun(job) {
  if (!analyticsData || !Array.isArray(analyticsData.byAgent)) return null;
  if (job?.sessionTarget !== 'isolated') return null;
  const name = String(job?.name || '').toLowerCase();
  if (!name) return null;

  for (const agent of analyticsData.byAgent) {
    const id = String(agent?.agentId || '').toLowerCase();
    if (!id || !id.includes(name)) continue;
    const totalCost = Number(agent?.cost) || 0;
    const runs = Number(agent?.sessions) || 0;
    if (totalCost > 0 && runs > 0) return totalCost / runs;
  }
  return null;
}

function renderCronHealth() {
  const panel = $('#cronHealthPanel');
  const container = $('#cronHealthList');
  if (!panel || !container) return;

  if (!Array.isArray(cronHealthData) || cronHealthData.length === 0) {
    panel.style.display = '';
    container.innerHTML = '<div class="empty-state" style="padding:18px 20px"><p>No cron data available</p></div>';
    return;
  }

  const enabledJobs = cronHealthData
    .filter(job => job && job.enabled)
    .sort((a, b) => {
      const aErr = (Number(a?.consecutiveErrors) || 0) > 0 ? 1 : 0;
      const bErr = (Number(b?.consecutiveErrors) || 0) > 0 ? 1 : 0;
      if (aErr !== bErr) return bErr - aErr;
      return String(a?.name || '').localeCompare(String(b?.name || ''));
    });

  if (enabledJobs.length === 0) {
    panel.style.display = '';
    container.innerHTML = '<div class="empty-state" style="padding:18px 20px"><p>No enabled cron jobs</p></div>';
    return;
  }

  const firstError = enabledJobs.find(job => (Number(job?.consecutiveErrors) || 0) > 0);
  const expensive = enabledJobs
    .map(job => ({ job, est: estimateCronCostPerRun(job) }))
    .find(item => Number(item.est) > 0.1);

  const banners = [];
  if (firstError) {
    banners.push(`<div class="cron-error-banner">⚠ ${escapeHtml(firstError.name || 'cron job')}: ${Number(firstError.consecutiveErrors) || 0} consecutive errors — still enabled</div>`);
  }
  if (expensive) {
    banners.push(`<div class="cron-cost-banner">💸 ${escapeHtml(expensive.job.name || 'cron job')}: estimated ${formatCurrency(expensive.est, 3, '$0.000')} per run</div>`);
  }

  const rows = enabledJobs.map(job => {
    const errors = Number(job?.consecutiveErrors) || 0;
    const lastRunMs = Number(job?.lastRunAtMs) || 0;
    const lastStatus = String(job?.lastStatus || '').toLowerCase();
    const neverRun = lastRunMs <= 0;
    const statusKey = neverRun ? 'never' : (lastStatus === 'ok' ? 'ok' : 'error');
    const statusLabel = statusKey === 'ok' ? 'ok' : statusKey === 'never' ? 'never run' : 'error';
    const scheduleLabel = String(job?.scheduleHuman || job?.schedule || '—');

    return `<div class="cron-job-row">
      <div class="cron-job-main">
        <div class="cron-job-name">${escapeHtml(job?.name || 'unnamed-job')}</div>
        <div class="cron-job-schedule">${escapeHtml(scheduleLabel)}</div>
      </div>
      <div class="cron-job-meta">
        <span class="cron-job-status"><span class="cron-status-dot cron-status-${statusKey}"></span>${escapeHtml(statusLabel)}</span>
        <span class="cron-errors${errors > 0 ? ' error' : ''}">${errors} errors</span>
        <span>${escapeHtml(formatDurationMs(job?.lastDurationMs))}</span>
        <span>${escapeHtml(formatRelativeTime(lastRunMs))}</span>
        ${job?.modelOverride ? `<span class="cron-model-badge">${escapeHtml(job.modelOverride)}</span>` : ''}
      </div>
    </div>`;
  }).join('');

  panel.style.display = '';
  container.innerHTML = `${banners.join('')}${rows}`;
}

function renderStats() {
  const d = analyticsData;
  const pm = pricingMeta();

  $('#statTotalCost').textContent = pm.isNone ? 'No pricing data' : (d.totalCost > 0 ? `$${d.totalCost.toFixed(2)}` : '$0.00');
  $('#statCostSub').textContent = d.range === 'all' ? `All time${pm.suffix}` : `Last ${d.range} days${pm.suffix}`;

  $('#statTotalTokens').textContent = formatNumber(d.totalTokens);
  $('#statTokensSub').textContent = `${formatNumber(d.inputTokens + d.outputTokens)} in/out`;

  $('#statApiCalls').textContent = formatNumber(d.apiCalls);
  $('#statCallsSub').textContent = 'Messages sent';

  const days = d.overTime?.length || 1;
  const dailyAvg = d.totalCost / days;
  const monthly = dailyAvg * 30;
  $('#statProjected').textContent = pm.isNone ? 'No pricing data' : (monthly > 0 ? `$${monthly.toFixed(2)}` : '$0.00');
  $('#statProjectedSub').textContent = pm.isNone ? 'Token-only tracking' : `$${dailyAvg.toFixed(3)}/day avg${pm.suffix}`;

  const avgSession = d.totalSessions > 0 ? (d.totalCost / d.totalSessions) : 0;
  $('#statAvgSession').textContent = pm.isNone ? formatNumber((d.totalTokens || 0) / Math.max(d.totalSessions || 1, 1)) + ' tok' : `$${avgSession.toFixed(3)}`;
  $('#statAvgSessionSub').textContent = `${d.totalSessions || 0} sessions`;

  const avgMsg = d.totalMessages > 0 ? (d.totalCost / d.totalMessages) : 0;
  $('#statAvgMsg').textContent = pm.isNone ? formatNumber((d.totalTokens || 0) / Math.max(d.totalMessages || 1, 1)) + ' tok' : `$${avgMsg.toFixed(4)}`;
  $('#statAvgMsgSub').textContent = `${d.totalMessages || 0} messages`;
}


function renderCostBreakdown() {
  const container = $('#costBreakdownChart');
  const cc = analyticsData.costComponents;
  if (!cc) { container.innerHTML = '<div class="empty-state"><div class="icon">📭</div><p>No data</p></div>'; return; }

  const items = [
    { label: 'Cache Write', desc: 'First msg per session', color: '#ef4444', value: cc.cacheWrite || 0 },
    { label: 'Output', desc: "Agent's responses", color: '#22c55e', value: cc.output || 0 },
    { label: 'Cache Read', desc: 'Cached context (90% off)', color: '#c9a44a', value: cc.cacheRead || 0 },
    { label: 'Input', desc: 'Your messages', color: '#3b82f6', value: cc.input || 0 }
  ];

  const total = items.reduce((sum, item) => sum + item.value, 0);
  items.sort((a, b) => b.value - a.value);

  container.innerHTML = items.map(item => {
    const pct = total > 0 ? (item.value / total * 100) : 0;
    return `
      <div class="cost-component">
        <div class="cost-component-color" style="background:${item.color}"></div>
        <div class="cost-component-info">
          <div class="cost-component-label">${item.label}</div>
          <div class="cost-component-desc">${item.desc}</div>
        </div>
        <div class="cost-component-right">
          <div class="cost-component-amount">${formatCurrency(item.value, 2, "No pricing")}</div>
          <div class="cost-component-pct">(${pct.toFixed(0)}%)</div>
        </div>
      </div>
    `;
  }).join('');
}

function renderBySource() {
  const container = $('#bySourceChart');
  const sources = analyticsData.bySource || [];

  if (sources.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="icon">📭</div><p>No source data</p></div>';
    return;
  }

  const sourceColors = { 'Cron': '#f59e0b', 'Telegram': '#3b82f6', 'Direct': '#22c55e' };
  const total = sources.reduce((sum, src) => sum + src.cost, 0);

  container.innerHTML = sources.map(src => {
    const pct = total > 0 ? (src.cost / total * 100) : 0;
    const color = sourceColors[src.source] || '#8b5cf6';
    return `
      <div class="source-item">
        <div class="source-color" style="background:${color}"></div>
        <div class="source-name">${escapeHtml(src.source)}</div>
        <div class="source-stats">
          <div class="source-cost">${formatCurrency(src.cost, 2, "No pricing")} (${pct.toFixed(0)}%)</div>
          <div class="source-meta">${src.sessions}s</div>
        </div>
      </div>
    `;
  }).join('');
}

function renderInsight() {
  const card = $('#insightCard');
  const container = $('#insightContent');
  const cc = analyticsData.costComponents;
  const d = analyticsData;

  if (!cc || d.totalCost === 0) { card.style.display = 'none'; return; }

  const total = (cc.input || 0) + (cc.output || 0) + (cc.cacheRead || 0) + (cc.cacheWrite || 0);
  if (total === 0) { card.style.display = 'none'; return; }

  let tip = '';
  const cacheWritePct = ((cc.cacheWrite || 0) / total) * 100;
  const cacheReadPct = ((cc.cacheRead || 0) / total) * 100;
  const outputPct = ((cc.output || 0) / total) * 100;

  if (cacheWritePct > 50) {
    tip = `<span class="insight-icon">💡</span> Cache writes are ${cacheWritePct.toFixed(0)}% of your LLM costs. Longer sessions save money via cache reads, but watch session size.`;
  } else if (outputPct > 60) {
    tip = `<span class="insight-icon">💡</span> Output tokens are ${outputPct.toFixed(0)}% of your costs. Consider shorter responses or switching verbose tasks to a cheaper model.`;
  } else if (cacheReadPct > 40) {
    tip = `<span class="insight-icon">✅</span> Strong cache efficiency — ${cacheReadPct.toFixed(0)}% of costs are discounted cache reads. Your session strategy is working.`;
  } else if (d.totalSessions > 0 && d.totalCost / d.totalSessions > 0.50) {
    tip = `<span class="insight-icon">⚠️</span> Average session cost is ${formatCurrency((d.totalCost / d.totalSessions), 2, "No pricing")}. Consider breaking expensive sessions into smaller runs.`;
  }

  if (!tip) { card.style.display = 'none'; return; }

  card.style.display = '';
  container.innerHTML = tip;
}

function renderCostByAgent() {
  const container = $('#costByAgentChart');
  const agents = analyticsData.byAgent;

  if (!agents || agents.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="icon">📭</div><p>No cost data</p></div>';
    return;
  }

  const maxCost = Math.max(...agents.map(a => a.cost));

  container.innerHTML = agents.map(a => {
    const pct = maxCost > 0 ? (a.cost / maxCost * 100) : 0;
    const agentInfo = agentState[a.agentId] || {};
    const emoji = agentInfo.emoji || '🤖';
    const name = agentInfo.name || a.agentId;
    return `
      <div class="bar-item">
        <div class="bar-label" title="${name}">${emoji} ${truncate(name, 10)}</div>
        <div class="bar-track">
          <div class="bar-fill" style="width:${pct}%">${formatCurrency(a.cost, 2, "No pricing")}</div>
        </div>
        <div class="bar-value">${formatNumber(a.tokens)} tok</div>
      </div>
    `;
  }).join('');
}

function renderTokenBreakdown() {
  const container = $('#tokenBreakdownChart');
  const d = analyticsData;

  const total = d.inputTokens + d.outputTokens + d.cacheReadTokens;
  if (total === 0) {
    container.innerHTML = '<div class="empty-state"><div class="icon">📭</div><p>No token data</p></div>';
    return;
  }

  const items = [
    { label: 'Input Tokens', value: d.inputTokens, class: 'input' },
    { label: 'Output Tokens', value: d.outputTokens, class: 'output' },
    { label: 'Cache Reads', value: d.cacheReadTokens, class: 'cache' },
  ];

  container.innerHTML = items.map(item => {
    const pct = (item.value / total * 100).toFixed(1);
    return `
      <div class="token-item">
        <div class="token-header">
          <span class="token-label">${item.label}</span>
          <span class="token-value">${formatNumber(item.value)} (${pct}%)</span>
        </div>
        <div class="token-bar">
          <div class="token-fill ${item.class}" style="width:${pct}%"></div>
        </div>
      </div>
    `;
  }).join('');
}

function renderZone2Tabs() {
  const container = $('#zone2AgentTabs');
  if (!container || !analyticsData) return;
  const agents = Array.isArray(analyticsData.byAgent) ? analyticsData.byAgent : [];
  const tabs = ['<button class="zone2-tab' + (zone2AgentFilter === 'all' ? ' active' : '') + '" data-agent="all">All Agents</button>'];

  agents.forEach(agent => {
    const agentInfo = agentState[agent.agentId] || {};
    const label = `${agentInfo.emoji || '🤖'} ${agentInfo.name || agent.agentId}`;
    tabs.push(`<button class="zone2-tab${zone2AgentFilter === agent.agentId ? ' active' : ''}" data-agent="${agent.agentId}">${escapeHtml(label)}</button>`);
  });

  container.innerHTML = tabs.join('');

  if (!container.dataset.bound) {
    container.addEventListener('click', (e) => {
      const btn = e.target.closest('.zone2-tab');
      if (!btn) return;
      const nextFilter = btn.dataset.agent || 'all';
      if (nextFilter === zone2AgentFilter) return;
      zone2AgentFilter = nextFilter;
      renderZone2Tabs();
      renderConcentrationBanner();
      renderTokenUsageChart();
      renderApiCostChart();
    });
    container.dataset.bound = '1';
  }
}

function renderConcentrationBanner() {
  const banner = $('#concentrationBanner');
  if (!banner || !analyticsData) return;
  if (zone2AgentFilter !== 'all') {
    banner.style.display = 'none';
    return;
  }

  const agents = Array.isArray(analyticsData.byAgent) ? analyticsData.byAgent : [];
  const totalTokens = Number(analyticsData.totalTokens) || 0;
  if (totalTokens <= 0 || agents.length === 0) {
    banner.style.display = 'none';
    return;
  }

  let highest = null;
  for (const agent of agents) {
    const share = (Number(agent.tokens) || 0) / totalTokens;
    if (!highest || share > highest.share) {
      highest = { agent, share };
    }
  }

  if (!highest || highest.share < 0.7) {
    banner.style.display = 'none';
    return;
  }

  const info = agentState[highest.agent.agentId] || {};
  const name = info.name || highest.agent.agentId;
  const pct = (highest.share * 100).toFixed(1);
  banner.classList.toggle('critical', highest.share > 0.9);
  banner.innerHTML = `⚠ ${escapeHtml(name)}: ${pct}% of tokens (${formatNumber(highest.agent.tokens || 0)} of ${formatNumber(totalTokens)})`;
  banner.style.display = '';
}

function renderTokenUsageChart() {
  const canvas = $('#tokenUsageChart');
  const tooltip = $('#tokenUsageTooltip');
  if (!canvas || !tooltip) return;

  const ctx = canvas.getContext('2d');
  const parent = canvas.parentElement;
  canvas.width = parent.clientWidth * 2;
  canvas.height = parent.clientHeight * 2;
  canvas.style.width = parent.clientWidth + 'px';
  canvas.style.height = parent.clientHeight + 'px';
  ctx.scale(2, 2);
  ctx.clearRect(0, 0, parent.clientWidth, parent.clientHeight);

  const w = parent.clientWidth;
  const h = parent.clientHeight;
  const padding = { top: 20, right: 20, bottom: 34, left: 55 };
  const chartW = w - padding.left - padding.right;
  const chartH = h - padding.top - padding.bottom;
  const styles = getComputedStyle(document.documentElement);
  const textColor = styles.getPropertyValue('--text-secondary').trim();
  const subtleText = styles.getPropertyValue('--text-tertiary').trim();
  const borderColor = styles.getPropertyValue('--border-subtle').trim();

  const seriesByAgent = tokenData?.agentTimeSeries || {};
  const isAllAgents = zone2AgentFilter === 'all';
  const isSingleAgent = !isAllAgents && seriesByAgent[zone2AgentFilter];

  let dates = [];
  let stacks = [];

  if (isAllAgents) {
    const allDates = new Set();
    for (const rows of Object.values(seriesByAgent)) {
      for (const row of rows || []) {
        if (row?.date) allDates.add(row.date);
      }
    }
    dates = Array.from(allDates).sort((a, b) => new Date(a) - new Date(b));

    const agentIds = Object.keys(seriesByAgent);
    const lookup = {};
    for (const id of agentIds) {
      lookup[id] = {};
      for (const row of seriesByAgent[id] || []) {
        lookup[id][row.date] = Number(row.tokens) || 0;
      }
    }

    stacks = dates.map((date) => {
      const segments = agentIds.map((agentId) => ({
        key: agentId,
        label: agentId,
        color: agentIdToHslColor(agentId),
        value: lookup[agentId]?.[date] || 0
      }));
      return { date, segments };
    });
  } else if (isSingleAgent) {
    const rows = [...(seriesByAgent[zone2AgentFilter] || [])].sort((a, b) => new Date(a.date) - new Date(b.date));
    dates = rows.map(r => r.date);
    stacks = rows.map((row) => {
      const input = Number(row.inputTokens) || 0;
      const output = Number(row.outputTokens) || 0;
      return {
        date: row.date,
        segments: [
          { key: 'inputTokens', label: 'Input Tokens', color: '#3b82f6', value: input },
          { key: 'outputTokens', label: 'Output Tokens', color: '#22c55e', value: output }
        ]
      };
    });
  }

  if (dates.length === 0 || stacks.length === 0) {
    ctx.fillStyle = subtleText;
    ctx.font = '12px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('No token usage data available', w / 2, h / 2);
    tooltip.classList.add('hidden');
    canvas.onmousemove = null;
    canvas.onmouseleave = null;
    return;
  }

  const totals = stacks.map(day => day.segments.reduce((sum, seg) => sum + (Number(seg.value) || 0), 0));
  const maxTotal = Math.max(...totals, 0);
  if (maxTotal <= 0) {
    ctx.fillStyle = subtleText;
    ctx.font = '12px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('No token usage data available', w / 2, h / 2);
    tooltip.classList.add('hidden');
    canvas.onmousemove = null;
    canvas.onmouseleave = null;
    return;
  }

  ctx.strokeStyle = borderColor;
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padding.top + (chartH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padding.left, y);
    ctx.lineTo(padding.left + chartW, y);
    ctx.stroke();

    const value = Math.round(maxTotal * (1 - i / 4));
    ctx.fillStyle = textColor;
    ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(formatNumber(value), padding.left - 8, y + 3);
  }

  const slotW = chartW / stacks.length;
  const barW = Math.max(8, Math.min(36, slotW * 0.7));
  const baseY = padding.top + chartH;
  const bars = [];

  stacks.forEach((day, i) => {
    const xCenter = padding.left + slotW * i + slotW / 2;
    const x = xCenter - barW / 2;
    let yCursor = baseY;
    const drawnSegments = [];

    day.segments.forEach((segment) => {
      const value = Number(segment.value) || 0;
      if (value <= 0) return;
      const height = (value / maxTotal) * chartH;
      yCursor -= height;
      ctx.fillStyle = segment.color;
      ctx.fillRect(x, yCursor, barW, height);
      drawnSegments.push({ ...segment, y: yCursor, height });
    });

    bars.push({ xCenter, x, width: barW, date: day.date, segments: day.segments, drawnSegments, total: totals[i] });
  });

  ctx.fillStyle = textColor;
  ctx.font = '10px Inter, sans-serif';
  ctx.textAlign = 'center';
  const step = Math.max(1, Math.floor(stacks.length / 7));
  stacks.forEach((d, i) => {
    if (i % step === 0 || i === stacks.length - 1) {
      ctx.fillText(formatDate(d.date), bars[i].xCenter, baseY + 18);
    }
  });

  canvas.onmousemove = (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;

    let closest = null;
    let minDist = Infinity;
    for (const bar of bars) {
      const dist = Math.abs(bar.xCenter - mx);
      if (dist < minDist) {
        minDist = dist;
        closest = bar;
      }
    }

    if (!closest || minDist > Math.max(20, slotW / 1.5)) {
      tooltip.classList.add('hidden');
      return;
    }

    const dateLabel = closest.date;
    let rows = `<div class="tooltip-date">${escapeHtml(dateLabel)}</div>`;

    if (isAllAgents) {
      closest.segments.forEach((segment) => {
        const value = Number(segment.value) || 0;
        if (value <= 0) return;
        const info = agentState[segment.key] || {};
        const agentName = `${info.emoji ? info.emoji + ' ' : ''}${info.name || segment.label}`.trim();
        rows += `<div class="tooltip-row"><span><span class="tooltip-dot" style="background:${segment.color}"></span><span class="tooltip-label">${escapeHtml(truncate(agentName, 28))}</span></span><span class="tooltip-val">${formatNumber(value)}</span></div>`;
      });
    } else {
      closest.segments.forEach((segment) => {
        rows += `<div class="tooltip-row"><span><span class="tooltip-dot" style="background:${segment.color}"></span><span class="tooltip-label">${escapeHtml(segment.label)}</span></span><span class="tooltip-val">${formatNumber(Number(segment.value) || 0)}</span></div>`;
      });
    }

    rows += `<div class="tooltip-row" style="border-top:1px solid var(--border-subtle);padding-top:4px;margin-top:4px"><span class="tooltip-label">Total</span><span class="tooltip-val">${formatNumber(closest.total)}</span></div>`;

    tooltip.classList.remove('hidden');
    tooltip.innerHTML = rows;
    const tx = Math.min(e.clientX - rect.left + 12, rect.width - 210);
    tooltip.style.left = tx + 'px';
    tooltip.style.top = Math.max(e.clientY - rect.top - 70, 0) + 'px';
  };

  canvas.onmouseleave = () => tooltip.classList.add('hidden');
}

function renderApiCostChart() {
  const canvas = $('#apiCostChart');
  const tooltip = $('#apiCostTooltip');
  const subtitle = $('#apiCostSubtitle');
  if (!canvas || !tooltip || !subtitle) return;
  const ctx = canvas.getContext('2d');
  const parent = canvas.parentElement;
  canvas.width = parent.clientWidth * 2;
  canvas.height = parent.clientHeight * 2;
  canvas.style.width = parent.clientWidth + 'px';
  canvas.style.height = parent.clientHeight + 'px';
  ctx.scale(2, 2);
  ctx.clearRect(0, 0, parent.clientWidth, parent.clientHeight);

  const pm = pricingMeta();
  subtitle.textContent = pm.isPartial ? 'Daily cost (partial pricing)' : 'Daily cost';

  if (pm.isNone) {
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-tertiary').trim();
    ctx.font = '12px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('No pricing data available', parent.clientWidth / 2, parent.clientHeight / 2);
    tooltip.classList.add('hidden');
    canvas.onmousemove = null;
    canvas.onmouseleave = null;
    return;
  }

  const timeline = zone2AgentFilter === 'all'
    ? (analyticsData?.overTime || [])
    : (tokenData?.agentTimeSeries?.[zone2AgentFilter] || []);

  if (timeline.length === 0) {
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-tertiary').trim();
    ctx.font = '12px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('No data available', parent.clientWidth / 2, parent.clientHeight / 2);
    tooltip.classList.add('hidden');
    canvas.onmousemove = null;
    canvas.onmouseleave = null;
    return;
  }

  const w = parent.clientWidth;
  const h = parent.clientHeight;
  const padding = { top: 20, right: 20, bottom: 30, left: 55 };
  const chartW = w - padding.left - padding.right;
  const chartH = h - padding.top - padding.bottom;

  const styles = getComputedStyle(document.documentElement);
  const accentColor = styles.getPropertyValue('--accent').trim();
  const textColor = styles.getPropertyValue('--text-secondary').trim();
  const borderColor = styles.getPropertyValue('--border-subtle').trim();

  const maxCost = Math.max(...timeline.map(d => Number(d.cost) || 0), 0.01);

  ctx.strokeStyle = borderColor;
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padding.top + (chartH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padding.left, y);
    ctx.lineTo(padding.left + chartW, y);
    ctx.stroke();
    const value = maxCost * (1 - i / 4);
    ctx.fillStyle = textColor;
    ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(`$${value < 1 ? value.toFixed(3) : value.toFixed(2)}`, padding.left - 8, y + 3);
  }

  const baseY = padding.top + chartH;
  const points = timeline.map((d, i) => {
    const x = padding.left + (chartW / (timeline.length - 1 || 1)) * i;
    const cost = Number(d.cost) || 0;
    const y = padding.top + chartH - (cost / maxCost * chartH);
    return { x, y, cost, date: d.date, tokens: Number(d.tokens) || 0 };
  });

  const gradient = ctx.createLinearGradient(0, padding.top, 0, baseY);
  gradient.addColorStop(0, accentColor + '30');
  gradient.addColorStop(1, accentColor + '00');
  ctx.fillStyle = gradient;
  ctx.beginPath();
  ctx.moveTo(points[0].x, baseY);
  points.forEach(p => ctx.lineTo(p.x, p.y));
  ctx.lineTo(points[points.length - 1].x, baseY);
  ctx.closePath();
  ctx.fill();

  ctx.strokeStyle = accentColor;
  ctx.lineWidth = 2;
  ctx.lineJoin = 'round';
  ctx.lineCap = 'round';
  ctx.beginPath();
  points.forEach((p, i) => i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y));
  ctx.stroke();

  points.forEach(p => {
    ctx.fillStyle = accentColor;
    ctx.beginPath();
    ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
    ctx.fill();
  });

  ctx.fillStyle = textColor;
  ctx.font = '10px Inter, sans-serif';
  ctx.textAlign = 'center';
  const step = Math.max(1, Math.floor(timeline.length / 7));
  timeline.forEach((d, i) => {
    if (i % step === 0 || i === timeline.length - 1) {
      ctx.fillText(formatDate(d.date), points[i].x, baseY + 18);
    }
  });

  canvas.onmousemove = (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    let closest = null;
    let minDist = Infinity;
    for (const p of points) {
      const dist = Math.abs(p.x - mx);
      if (dist < minDist) {
        minDist = dist;
        closest = p;
      }
    }

    if (closest && minDist < 30) {
      tooltip.classList.remove('hidden');
      tooltip.innerHTML = `
        <div class="tooltip-date">${closest.date}</div>
        <div class="tooltip-row"><span class="tooltip-label">Daily Cost</span><span class="tooltip-val" style="color:var(--accent)">${formatCurrency(closest.cost, 4, 'No pricing')}</span></div>
        <div class="tooltip-row"><span class="tooltip-label">Tokens</span><span class="tooltip-val">${formatNumber(closest.tokens)}</span></div>
      `;
      const tx = Math.min(e.clientX - rect.left + 12, rect.width - 180);
      tooltip.style.left = tx + 'px';
      tooltip.style.top = Math.max(e.clientY - rect.top - 58, 0) + 'px';
    } else {
      tooltip.classList.add('hidden');
    }
  };
  canvas.onmouseleave = () => tooltip.classList.add('hidden');
}

function renderCostOverTime() {
  const canvas = $('#costOverTimeChart');
  const ctx = canvas.getContext('2d');
  const tooltip = $('#costTooltip');
  const timeline = analyticsData.overTime || [];

  const parent = canvas.parentElement;
  canvas.width = parent.clientWidth * 2;
  canvas.height = parent.clientHeight * 2;
  canvas.style.width = parent.clientWidth + 'px';
  canvas.style.height = parent.clientHeight + 'px';
  ctx.scale(2, 2);

  if (timeline.length === 0) {
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-tertiary');
    ctx.font = '12px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('No data available', parent.clientWidth / 2, parent.clientHeight / 2);
    return;
  }

  const w = parent.clientWidth;
  const h = parent.clientHeight;
  const padding = { top: 20, right: 20, bottom: 30, left: 55 };
  const chartW = w - padding.left - padding.right;
  const chartH = h - padding.top - padding.bottom;

  const accentColor = getComputedStyle(document.documentElement).getPropertyValue('--accent').trim();
  const textColor = getComputedStyle(document.documentElement).getPropertyValue('--text-secondary').trim();
  const borderColor = getComputedStyle(document.documentElement).getPropertyValue('--border-subtle').trim();
  const isCumulative = costMode === 'cumulative';

  // Build cumulative data
  let running = 0;
  const cumData = timeline.map(d => { running += d.cost; return { ...d, cumulative: running }; });
  const maxCost = isCumulative
    ? Math.max(running, 0.01)
    : Math.max(...timeline.map(d => d.cost), 0.01);

  // Grid
  ctx.strokeStyle = borderColor;
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padding.top + (chartH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padding.left, y);
    ctx.lineTo(padding.left + chartW, y);
    ctx.stroke();
    const value = maxCost * (1 - i / 4);
    ctx.fillStyle = textColor;
    ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(`$${value < 1 ? value.toFixed(3) : value.toFixed(2)}`, padding.left - 8, y + 3);
  }

  const baseY = padding.top + chartH;
  const costPoints = cumData.map((d, i) => {
    const x = padding.left + (chartW / (timeline.length - 1 || 1)) * i;
    const val = isCumulative ? d.cumulative : d.cost;
    const y = padding.top + chartH - (val / maxCost * chartH);
    return { x, y, cost: d.cost, cumulative: d.cumulative, date: d.date, tokens: d.tokens };
  });

  // Area
  ctx.fillStyle = accentColor + '20';
  ctx.beginPath();
  ctx.moveTo(costPoints[0].x, baseY);
  costPoints.forEach(p => ctx.lineTo(p.x, p.y));
  ctx.lineTo(costPoints[costPoints.length - 1].x, baseY);
  ctx.closePath();
  ctx.fill();

  // Line
  ctx.strokeStyle = accentColor;
  ctx.lineWidth = 2;
  ctx.lineJoin = 'round';
  ctx.lineCap = 'round';
  ctx.beginPath();
  costPoints.forEach((p, i) => i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y));
  ctx.stroke();

  // Dots
  costPoints.forEach(p => {
    ctx.fillStyle = accentColor;
    ctx.beginPath();
    ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
    ctx.fill();
  });

  // X-axis
  ctx.fillStyle = textColor;
  ctx.font = '10px Inter, sans-serif';
  ctx.textAlign = 'center';
  const step = Math.max(1, Math.floor(timeline.length / 7));
  timeline.forEach((d, i) => {
    if (i % step === 0 || i === timeline.length - 1) {
      ctx.fillText(formatDate(d.date), costPoints[i].x, baseY + 18);
    }
  });

  // Tooltip
  canvas.onmousemove = (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    let closest = null, minDist = Infinity;
    for (const p of costPoints) {
      const dist = Math.abs(p.x - mx);
      if (dist < minDist) { minDist = dist; closest = p; }
    }
    if (closest && minDist < 30) {
      tooltip.classList.remove('hidden');
      tooltip.innerHTML = `
        <div class="tooltip-date">${closest.date}</div>
        <div class="tooltip-row"><span class="tooltip-label">Daily Cost</span><span class="tooltip-val" style="color:var(--accent)">${formatCurrency(closest.cost, 4, "No pricing")}</span></div>
        <div class="tooltip-row"><span class="tooltip-label">Running Total</span><span class="tooltip-val">${formatCurrency(closest.cumulative, 4, "No pricing")}</span></div>
        <div class="tooltip-row"><span class="tooltip-label">Tokens</span><span class="tooltip-val">${formatNumber(closest.tokens)}</span></div>
      `;
      const tx = Math.min(e.clientX - rect.left + 12, rect.width - 180);
      tooltip.style.left = tx + 'px';
      tooltip.style.top = Math.max(e.clientY - rect.top - 70, 0) + 'px';
    } else {
      tooltip.classList.add('hidden');
    }
  };
  canvas.onmouseleave = () => tooltip.classList.add('hidden');
}

function renderTopSessions() {
  const container = $('#topSessionsList');
  const sessions = analyticsData.topSessions || [];

  if (sessions.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="icon">📭</div><p>No sessions found</p></div>';
    return;
  }

  const sourceClass = (src) => {
    if (src === 'Cron') return 'source-cron';
    if (src === 'Telegram') return 'source-telegram';
    return 'source-direct';
  };

  container.innerHTML = sessions.slice(0, 8).map(s => {
    const agentInfo = agentState[s.agentId] || {};
    const emoji = agentInfo.emoji || '🤖';
    const name = agentInfo.name || s.agentId;
    const badges = [
      s.source ? `<span class="session-badge ${sourceClass(s.source)}">${escapeHtml(s.source)}</span>` : '',
      s.model ? `<span class="session-badge model-badge">${escapeHtml(truncate(s.model, 16))}</span>` : ''
    ].filter(Boolean).join('');

    const wasteBadges = (s.flags || []).map(flag => {
      const labels = {
        'LOOP': 'loop', 'BLOAT': 'bloat', 'ABANDONED': 'abandoned',
        'CACHE_MISS': 'cache miss', 'ERROR': 'error'
      };
      const classes = {
        'LOOP': 'loop', 'BLOAT': 'bloat', 'ABANDONED': 'abandoned',
        'CACHE_MISS': 'cache-miss', 'ERROR': 'error'
      };
      return `<span class="waste-badge ${classes[flag] || ''}">${labels[flag] || flag}</span>`;
    }).join('');

    return `
      <div class="session-list-item">
        <div class="session-agent">
          <span class="session-agent-emoji">${emoji}</span>
          <span>${truncate(name, 12)}</span>
          ${badges}
        </div>
        <div class="session-meta">
          ${wasteBadges}
          ${s.messages ? `<span>${s.messages} msgs</span>` : ''}
          <span class="session-tokens">${formatNumber(s.tokens)} tok</span>
          ${s.cost == null ? `<span class="session-badge no-pricing-badge">no pricing</span>` : `<span class="session-cost">${formatCurrency(s.cost, 3, "No pricing data")}</span>`}
        </div>
      </div>
    `;
  }).join('');
}

function renderTopCrons() {
  const section = $('#topCronSection');
  const sessions = (analyticsData.topSessions || []).filter(s => s.source === 'Cron');

  if (sessions.length === 0) {
    section.style.display = 'none';
    return;
  }
  section.style.display = '';

  const container = $('#topCronList');
  container.innerHTML = sessions.slice(0, 8).map(s => {
    const agentInfo = agentState[s.agentId] || {};
    const emoji = agentInfo.emoji || '🤖';
    const name = agentInfo.name || s.agentId;
    const wasteBadges = (s.flags || []).map(flag => {
      const labels = {
        'LOOP': 'loop', 'BLOAT': 'bloat', 'ABANDONED': 'abandoned',
        'CACHE_MISS': 'cache miss', 'ERROR': 'error'
      };
      const classes = {
        'LOOP': 'loop', 'BLOAT': 'bloat', 'ABANDONED': 'abandoned',
        'CACHE_MISS': 'cache-miss', 'ERROR': 'error'
      };
      return `<span class="waste-badge ${classes[flag] || ''}">${labels[flag] || flag}</span>`;
    }).join('');

    return `
      <div class="session-list-item">
        <div class="session-agent">
          <span class="session-agent-emoji">${emoji}</span>
          <span>${truncate(name, 12)}</span>
        </div>
        <div class="session-meta">
          <span class="session-badge source-cron">Cron</span>
          ${s.model ? `<span class="session-badge model-badge">${truncate(s.model, 16)}</span>` : ''}
          ${wasteBadges}
          <span class="session-tokens">${formatNumber(s.tokens)} tok</span>
          ${s.cost == null ? `<span class="session-badge no-pricing-badge">no pricing</span>` : `<span class="session-cost">${formatCurrency(s.cost, 3, "No pricing data")}</span>`}
        </div>
      </div>
    `;
  }).join('');
}

function renderCostByModel() {
  const container = $('#costByModelChart');
  const models = tokenData?.byModel || analyticsData?.byModel || [];

  if (models.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="icon">📭</div><p>No model data</p></div>';
    return;
  }

  const maxCost = Math.max(...models.map(m => m.cost || 0), 0.001);
  const colors = ['#3b82f6', '#22c55e', '#c9a44a', '#ef4444', '#8b5cf6', '#f59e0b', '#06b6d4', '#ec4899'];

  container.innerHTML = models.slice(0, 8).map((m, i) => {
    const pct = ((m.cost || 0) / maxCost * 100);
    const color = colors[i % colors.length];
    const tokens = (m.tokens || m.inputTokens || 0) + (m.outputTokens || 0) + (m.cacheReadTokens || 0);
    const costPer1k = (m.cost != null && tokens > 0) ? ((m.cost || 0) / tokens * 1000) : null;
    const cleanModel = (m.model || '').replace('anthropic/', '').replace('openai/', '').replace('google/', '');

    return `
      <div class="cost-model-item">
        <div class="cost-model-color" style="background:${color}"></div>
        <div style="flex:1;min-width:0">
          <div class="cost-model-name">${escapeHtml(truncate(cleanModel, 24))}</div>
          <div class="cost-model-rate">${formatNumber(tokens)} tok ${m.pricingAvailable === false ? '· <span class="no-pricing-badge">no pricing</span>' : `· $${(costPer1k || 0).toFixed(4)}/1K`}</div>
        </div>
        <div style="text-align:right">
          <div class="cost-model-amount">${m.pricingAvailable === false ? '<span class="no-pricing-badge">no pricing</span>' : formatCurrency(m.cost || 0, 3, 'No pricing data')}</div>
        </div>
        <div class="cost-model-bar">
          <div class="cost-model-fill" style="width:${pct}%;background:${color}"></div>
        </div>
      </div>
    `;
  }).join('');
}

function renderProjections() {
  const container = $('#projectionsPanel');
  const d = analyticsData;
  const pm = pricingMeta();
  const timeline = d.overTime || [];

  if (timeline.length === 0) {
    container.innerHTML = '<div class="empty-state"><div class="icon">📭</div><p>No data for projections</p></div>';
    return;
  }

  const days = timeline.length;
  const dailyAvg = d.totalCost / days;
  const weekly = dailyAvg * 7;
  const monthly = dailyAvg * 30;
  const yearly = dailyAvg * 365;

  // Trend: compare last 7 days vs previous 7 days
  const last7 = timeline.slice(-7).reduce((s, d) => s + d.cost, 0);
  const prev7 = timeline.slice(-14, -7).reduce((s, d) => s + d.cost, 0);
  const trendPct = prev7 > 0 ? ((last7 - prev7) / prev7 * 100) : 0;
  const trendDir = trendPct > 5 ? '📈' : trendPct < -5 ? '📉' : '➡️';
  const trendColor = trendPct > 5 ? 'var(--warning)' : trendPct < -5 ? 'var(--success)' : 'var(--text-secondary)';

  // Cost per API call
  const costPerCall = d.apiCalls > 0 ? (d.totalCost / d.apiCalls) : 0;

  // Peak day
  const peakDay = timeline.reduce((max, d) => d.cost > max.cost ? d : max, timeline[0]);

  container.innerHTML = `
    <div class="projection-item">
      <div class="projection-value">${pm.isNone ? "No pricing" : formatCurrency(monthly, 2, "No pricing")}</div>
      <div class="projection-label">Monthly Estimate</div>
      <div class="projection-sub">${pm.isNone ? `${formatNumber(d.totalTokens)} tokens in range` : `${formatCurrency(yearly,2)}/year · ${formatCurrency(weekly,2)}/week`}</div>
    </div>
    <div class="projection-item">
      <div class="projection-value" style="color:${trendColor}">${trendDir} ${Math.abs(trendPct).toFixed(0)}%</div>
      <div class="projection-label">Week-over-Week</div>
      <div class="projection-sub">${pm.isNone ? "Token trend only" : `${formatCurrency(last7,3)} vs ${formatCurrency(prev7,3)}`}</div>
    </div>
    <div class="projection-item">
      <div class="projection-value" style="font-size:1.4rem">${pm.isNone ? "Token-only" : formatCurrency(costPerCall,4,"No pricing")}</div>
      <div class="projection-label">Cost per API Call</div>
      <div class="projection-sub">${pm.isNone ? `Peak tokens day: ${formatDate(peakDay.date)}` : `Peak: ${formatCurrency(peakDay.cost,3)} on ${formatDate(peakDay.date)}`}</div>
    </div>
  `;
}

function renderAgentCostChart() {
  const section = $('#agentCostSection');
  const agentTS = tokenData?.agentTimeSeries || {};
  const agentIds = Object.keys(agentTS);

  if ($('#agentSelect').value !== 'all' || agentIds.length < 2) {
    section.style.display = 'none';
    return;
  }
  section.style.display = '';

  const canvas = $('#agentCostChart');
  const ctx = canvas.getContext('2d');
  const tooltip = $('#agentCostTooltip');

  const parent = canvas.parentElement;
  canvas.width = parent.clientWidth * 2;
  canvas.height = parent.clientHeight * 2;
  canvas.style.width = parent.clientWidth + 'px';
  canvas.style.height = parent.clientHeight + 'px';
  ctx.scale(2, 2);

  const w = parent.clientWidth;
  const h = parent.clientHeight;
  const padding = { top: 20, right: 20, bottom: 40, left: 55 };
  const chartW = w - padding.left - padding.right;
  const chartH = h - padding.top - padding.bottom;

  const textColor = getComputedStyle(document.documentElement).getPropertyValue('--text-secondary').trim();
  const borderColor = getComputedStyle(document.documentElement).getPropertyValue('--border-subtle').trim();
  const agentColors = ['#3b82f6', '#22c55e', '#c9a44a', '#ef4444', '#8b5cf6', '#f59e0b', '#06b6d4', '#ec4899'];

  // Build unified date axis
  const allDates = new Set();
  for (const id of agentIds) for (const dp of agentTS[id]) allDates.add(dp.date);
  const dates = [...allDates].sort();
  if (dates.length === 0) { section.style.display = 'none'; return; }

  // Build lookup
  const lookup = {};
  for (const id of agentIds) {
    lookup[id] = {};
    for (const dp of agentTS[id]) lookup[id][dp.date] = dp.cost;
  }

  // Stacked bar chart — compute stacked totals per date
  const stackedMax = Math.max(...dates.map(date =>
    agentIds.reduce((sum, id) => sum + (lookup[id]?.[date] || 0), 0)
  ), 0.001);

  // Grid
  ctx.strokeStyle = borderColor;
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padding.top + (chartH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padding.left, y);
    ctx.lineTo(padding.left + chartW, y);
    ctx.stroke();
    const value = stackedMax * (1 - i / 4);
    ctx.fillStyle = textColor;
    ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(`$${value < 1 ? value.toFixed(3) : value.toFixed(2)}`, padding.left - 8, y + 3);
  }

  const baseY = padding.top + chartH;
  const barW = Math.max(2, Math.min(20, chartW / dates.length - 2));

  // Draw stacked bars
  dates.forEach((date, i) => {
    const x = padding.left + (chartW / (dates.length - 1 || 1)) * i - barW / 2;
    let stackY = baseY;

    agentIds.forEach((id, idx) => {
      const cost = lookup[id]?.[date] || 0;
      if (cost <= 0) return;
      const barH = (cost / stackedMax) * chartH;
      ctx.fillStyle = agentColors[idx % agentColors.length];
      ctx.fillRect(x, stackY - barH, barW, barH);
      stackY -= barH;
    });
  });

  // X-axis
  ctx.fillStyle = textColor;
  ctx.font = '10px Inter, sans-serif';
  ctx.textAlign = 'center';
  const step = Math.max(1, Math.floor(dates.length / 7));
  dates.forEach((d, i) => {
    if (i % step === 0 || i === dates.length - 1) {
      const x = padding.left + (chartW / (dates.length - 1 || 1)) * i;
      ctx.fillText(formatDate(d), x, baseY + 18);
    }
  });

  // Legend
  let legendX = padding.left;
  agentIds.forEach((id, idx) => {
    const color = agentColors[idx % agentColors.length];
    const info = window.agentState?.[id] || {};
    const label = (info.emoji || '') + ' ' + (info.name || id);
    ctx.fillStyle = color;
    ctx.fillRect(legendX, baseY + 28, 10, 10);
    ctx.fillStyle = textColor;
    ctx.font = '10px Inter, sans-serif';
    ctx.textAlign = 'left';
    ctx.fillText(truncate(label, 12), legendX + 14, baseY + 37);
    legendX += 100;
  });

  // Tooltip
  canvas.onmousemove = (e) => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    let closestIdx = 0, minDist = Infinity;
    dates.forEach((_, i) => {
      const x = padding.left + (chartW / (dates.length - 1 || 1)) * i;
      const dist = Math.abs(x - mx);
      if (dist < minDist) { minDist = dist; closestIdx = i; }
    });
    if (minDist < 30) {
      const date = dates[closestIdx];
      const total = agentIds.reduce((s, id) => s + (lookup[id]?.[date] || 0), 0);
      tooltip.classList.remove('hidden');
      let rows = `<div class="tooltip-date">${date}</div>`;
      agentIds.forEach((id, idx) => {
        const cost = lookup[id]?.[date] || 0;
        if (cost <= 0) return;
        const info = window.agentState?.[id] || {};
        const color = agentColors[idx % agentColors.length];
        rows += `<div class="tooltip-row"><span><span class="tooltip-dot" style="background:${color}"></span><span class="tooltip-label">${escapeHtml(info.name || id)}</span></span><span class="tooltip-val" style="color:var(--accent)">$${cost.toFixed(4)}</span></div>`;
      });
      rows += `<div class="tooltip-row" style="border-top:1px solid var(--border-subtle);padding-top:4px;margin-top:4px"><span class="tooltip-label">Total</span><span class="tooltip-val">$${total.toFixed(4)}</span></div>`;
      tooltip.innerHTML = rows;
      const tx = Math.min(e.clientX - rect.left + 12, rect.width - 180);
      tooltip.style.left = tx + 'px';
      tooltip.style.top = Math.max(e.clientY - rect.top - 60, 0) + 'px';
    } else {
      tooltip.classList.add('hidden');
    }
  };
  canvas.onmouseleave = () => tooltip.classList.add('hidden');
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ═══════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════

function formatCurrency(value, digits = 2, fallback = 'No pricing data') {
  const pm = pricingMeta();
  if (pm.isNone || value == null || !Number.isFinite(value)) return fallback;
  return `$${value.toFixed(digits)}${pm.isPartial ? ' (partial)' : ''}`;
}

function formatNumber(n) {
  if (n > 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n > 1e3) return (n / 1e3).toFixed(1) + 'K';
  return n.toString();
}

function formatDate(dateStr) {
  const d = new Date(dateStr);
  const month = (d.getMonth() + 1).toString().padStart(2, '0');
  const day = d.getDate().toString().padStart(2, '0');
  return `${month}/${day}`;
}

function agentIdToHslColor(agentId) {
  const id = String(agentId || 'agent');
  let hash = 0;
  for (let i = 0; i < id.length; i++) {
    hash = ((hash << 5) - hash + id.charCodeAt(i)) | 0;
  }
  const hue = Math.abs(hash) % 360;
  return `hsl(${hue}, 65%, 55%)`;
}

function truncate(str, max) {
  if (str.length <= max) return str;
  return str.slice(0, max - 1) + '…';
}


