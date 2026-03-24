/**
 * layout.js — Shared layout module for Clawd Control
 *
 * Injects sidebar + topbar + design-system CSS into every page.
 * Manages SSE connection and keyboard shortcuts.
 *
 * Usage: include <script src="/layout.js"></script> after <main class="main">
 *        Each page wraps its content in <main class="main">...</main>
 */
(function () {
  'use strict';

  // ════════════════════════════════════════════════════
  // STATE
  // ════════════════════════════════════════════════════

  const agentState = (window.agentState = window.agentState || {});
  window.hostState = window.hostState || {};
  let evtSource = null;
  let securityBadgeTimer = null;
  let watcherBadgeTimer = null;
  let tasksBadgeTimer = null;

  // ════════════════════════════════════════════════════
  // PAGE DETECTION
  // ════════════════════════════════════════════════════

  const path = window.location.pathname;
  const PAGE_MAP = {
    '/': 'dashboard',
    '/dashboard.html': 'dashboard',
    '/agents.html': 'agents',
    '/sessions.html': 'sessions',
    '/tasks.html': 'tasks',
    '/ops.html': 'ops',
    '/security.html': 'security',
    '/analytics.html': 'analytics',
    '/cortex.html': 'cortex',
    '/cortex': 'cortex',
    '/memory.html': 'memory',
    '/memory': 'memory',
    '/chat.html': 'chat',
  };
  const PAGE_META = {
    dashboard:  { title: 'Overview', subtitle: 'System health at a glance. Green means go home.', color: '#2dd4bf' },
    tasks:      { title: 'Tasks', subtitle: 'All durable work, from proposal to archive.', color: '#6366f1' },
    agents:     { title: 'Agents', subtitle: 'Agent fleet status and per-agent workspace.', color: '#f59e0b' },
    analytics:  { title: 'Usage', subtitle: 'Where tokens and money go.', color: '#2dd4bf' },
    ops:        { title: 'Operations', subtitle: 'Infrastructure health, jobs, recovery, and learning.', color: '#ef4444' },
    security:   { title: 'Security', subtitle: 'Security posture and enforcement status.', color: '#ef4444' },
    cortex:     { title: 'CORTEX', subtitle: 'Model routing, workload controls, and configuration.', color: '#7c3aed' },
    sessions:   { title: 'Sessions', subtitle: 'Active and recent gateway sessions.', color: '#6366f1' },
    memory:     { title: 'Memory', subtitle: 'What the system knows. Pipeline health and knowledge.', color: '#10b981' },
    chat:       { title: 'Chat', subtitle: 'Conversation with Jarvis.', color: '#2dd4bf' },
    'agent-detail': { title: 'Agent Detail', subtitle: 'Per-agent workspace.', color: '#f59e0b' },
  };

  const activePage = PAGE_MAP[path] || (path.startsWith('/agent/') ? 'agent-detail' : 'other');
  const activeAgentId =
    activePage === 'agent-detail'
      ? decodeURIComponent(path.split('/').filter(Boolean).pop())
      : null;

  window.layoutActivePage = activePage;
  window.layoutActiveAgentId = activeAgentId;

  // ════════════════════════════════════════════════════
  // CSS INJECTION
  // ════════════════════════════════════════════════════

  const LAYOUT_CSS = `
/* ═══════════════════════════════════════════
   CLAWD CONTROL — Design System & Layout
   Injected by layout.js
   ═══════════════════════════════════════════ */

:root {
  --bg-primary: #0a0c10;
  --bg-secondary: #13151a;
  --bg-tertiary: #1a1d27;
  --surface: #232732;
  --surface-hover: #2a2f3d;
  --border: #363b4d;
  --border-subtle: #252835;

  --text-primary: #f4f4f5;
  --text-secondary: #a1a1aa;
  --text-tertiary: #71717a;
  --text-nav-muted: #7c8aa0;

  --success: #22c55e;
  --success-bg: rgba(34, 197, 94, 0.1);
  --error: #ef4444;
  --error-bg: rgba(239, 68, 68, 0.1);
  --warning: #f59e0b;
  --warning-bg: rgba(245, 158, 11, 0.1);
  --info: #3b82f6;
  --info-bg: rgba(59, 130, 246, 0.1);

  --accent: #c9a44a;
  --accent-hover: #d4b05f;
  --accent-bg: rgba(201, 164, 74, 0.1);

  --success-dim: rgba(34, 197, 94, 0.06);
  --error-dim: rgba(239, 68, 68, 0.06);
  --warning-dim: rgba(245, 158, 11, 0.06);
  --accent-dim: rgba(201, 164, 74, 0.06);

  --sidebar-w: 232px;

  --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
  --font-mono: 'SF Mono', 'Consolas', 'Monaco', monospace;
  --font: var(--font-sans);

  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 14px;

  --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.3);
  --shadow-md: 0 4px 12px rgba(0, 0, 0, 0.4);
  --shadow-lg: 0 12px 40px rgba(0, 0, 0, 0.5);

  --transition-fast: 150ms cubic-bezier(0.4, 0, 0.2, 1);
  --transition-base: 250ms cubic-bezier(0.4, 0, 0.2, 1);
}

/* ── Reset & Base ──────────────────────── */

*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
html { font-size: 16px; -webkit-font-smoothing: antialiased; color-scheme: dark; }

h1, h2, h3 { line-height: 1.2; font-weight: 700; letter-spacing: -0.02em; }

/* ── App Layout (CSS Grid) ─────────────── */

body {
  font-family: var(--font-sans);
  color: var(--text-primary);
  background: var(--bg-primary);
  line-height: 1.5;
  height: 100vh;
  overflow: hidden;
  display: grid;
  grid-template-rows: auto 1fr;
  grid-template-columns: var(--sidebar-w) 1fr;
  transition: background-color 0.35s ease, color 0.35s ease;
}

/* ── Topbar ────────────────────────────── */

.topbar {
  grid-column: 2;
  padding: 0 20px;
  height: 48px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid var(--border-subtle);
  background: var(--bg-secondary);
  z-index: 100;
}
.topbar-left { display: flex; align-items: center; gap: 10px; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

.topbar-right { display: flex; align-items: center; gap: 2px; }


/* ── Sidebar ───────────────────────────── */

.sidebar {
  grid-row: 2;
  background: var(--bg-secondary);
  border-right: 1px solid var(--border-subtle);
  display: flex;
  flex-direction: column;
  overflow-y: auto;
  overflow-x: hidden;
  transition: width 0.25s ease;
  padding-top: 16px;
}

.nav-item {
  display: flex; align-items: center; gap: 10px;
  padding: 7px 12px; margin: 1px 8px;
  border-radius: var(--radius-sm);
  font-size: 0.8rem; font-weight: 500; color: var(--text-secondary);
  cursor: pointer; transition: all var(--transition-fast);
  text-decoration: none; position: relative;
}
.nav-item:hover { background: var(--surface); color: var(--text-primary); }
.nav-item.active {
  background: var(--surface);
  color: var(--text-primary);
  font-weight: 600;
  border-left: 3px solid #2dd4bf;
}
.nav-item.active .nav-icon {
  opacity: 1;
}
.nav-item .nav-icon { width: 16px; height: 16px; opacity: 0.6; flex-shrink: 0; }
.nav-item .nav-label { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* Tier typography */
.nav-item.tier-1 { color: var(--text-primary); font-weight: 500; }
.nav-item.tier-1 .nav-icon { opacity: 0.8; }
.nav-item.tier-2 { color: var(--text-secondary); font-weight: 400; }
.nav-item.tier-2 .nav-icon { opacity: 0.65; }
.nav-item.tier-3 { color: var(--text-nav-muted); font-weight: 400; }
.nav-item.tier-3 .nav-icon { opacity: 0.55; }

/* Hover promotes one step */
.nav-item.tier-2:hover { color: var(--text-primary); }
.nav-item.tier-2:hover .nav-icon { opacity: 0.8; }
.nav-item.tier-3:hover { color: var(--text-secondary); }
.nav-item.tier-3:hover .nav-icon { opacity: 0.65; }

/* Active overrides tier */
.nav-item.active { color: var(--text-primary); font-weight: 600; }
.nav-item.active .nav-icon { opacity: 1; }

/* Tier gaps */
.nav-tier-gap { height: 16px; }

/* Sidebar header */
.sidebar-header { padding: 0 12px 12px; }
.sidebar-header .sidebar-name {
  font-size: 14px; font-weight: 700; color: var(--text-primary);
  text-shadow: 0 0 12px rgba(245,158,11,0.7), 0 0 4px rgba(245,158,11,0.4);
}
.sidebar-header .sidebar-product {
  font-size: 12px; color: var(--text-tertiary); font-weight: 400;
}

/* Nav indicator badges (informational counts) */
.nav-count-badge {
  background: var(--surface);
  color: var(--text-secondary);
  border: 1px solid var(--border-subtle);
  border-radius: 9999px;
  padding: 0 6px;
  font-size: 10px;
  font-weight: 600;
  font-family: var(--font-mono);
  min-width: 18px;
  height: 16px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

/* Nav health dots (status indicators) */
.nav-health-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  flex-shrink: 0;
  background: var(--text-tertiary);
}
.nav-health-dot.green { background: #22c55e; }
.nav-health-dot.amber { background: #f59e0b; }
.nav-health-dot.red { background: #ef4444; }

/* Sidebar footer (minimal) */
.sidebar-footer-minimal {
  padding: 12px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.sidebar-footer-minimal .logout-link {
  display: flex; align-items: center; gap: 6px;
  color: var(--text-tertiary); font-size: 13px; font-weight: 400;
  cursor: pointer; text-decoration: none;
  transition: color var(--transition-fast);
}
.sidebar-footer-minimal .logout-link:hover { color: var(--text-secondary); }
.sidebar-footer-minimal .logout-link .nav-icon { width: 14px; height: 14px; opacity: 0.6; }
.sidebar-footer-minimal .version-label {
  font-size: 11px; color: var(--text-tertiary); font-family: var(--font-mono);
}

/* Topbar Chat button */
.topbar-chat-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: var(--surface);
  border: 1px solid var(--border-subtle);
  border-radius: 9999px;
  padding: 6px 14px;
  color: var(--text-secondary);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  text-decoration: none;
  transition: all var(--transition-fast);
}
.topbar-chat-btn:hover { border-color: #2dd4bf; color: var(--text-primary); }
.topbar-chat-btn.active {
  background: rgba(45, 212, 191, 0.1);
  border-color: #2dd4bf;
  color: var(--text-primary);
}
.topbar-chat-btn .nav-icon { width: 14px; height: 14px; }

/* Incident Banner */
.incident-banner {
  display: none;
  padding: 8px 16px;
  font-size: 13px;
  font-weight: 500;
  text-align: center;
  grid-column: 1 / -1;
}
.incident-banner a { color: inherit; text-decoration: underline; }
.incident-banner.issues {
  display: block;
  background: rgba(239, 68, 68, 0.08);
  border-bottom: 1px solid rgba(239, 68, 68, 0.2);
  color: #ef4444;
}
.incident-banner.stale {
  display: block;
  background: rgba(245, 158, 11, 0.08);
  border-bottom: 1px solid rgba(245, 158, 11, 0.2);
  color: #f59e0b;
}

/* ── Main Content ──────────────────────── */

.main {
  grid-row: 2;
  overflow-y: auto;
  padding: 20px 24px;
  background: var(--bg-primary);
  background-image: radial-gradient(ellipse at 50% 0%, rgba(201, 164, 74, 0.03) 0%, transparent 50%);
}

/* ── Toast ─────────────────────────────── */

.toast {
  position: fixed; bottom: 24px; right: 24px; padding: 10px 18px;
  background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-md);
  font-size: 0.8rem; z-index: 200; box-shadow: var(--shadow-lg);
  animation: slideIn 0.3s ease;
}
.toast.success { border-color: var(--success); color: var(--success); }
.toast.error { border-color: var(--error); color: var(--error); }

/* ── Animations ────────────────────────── */

@keyframes slideIn { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
@keyframes fadeUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
.fade-up { animation: fadeUp 0.4s cubic-bezier(0.16, 1, 0.3, 1) both; }

/* ── Scrollbar ─────────────────────────── */

::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.08); border-radius: 10px; }
::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.16); }

/* ── Responsive ────────────────────────── */

@media (max-width: 900px) {
  .main { padding: 16px; }
}

/* ── Accessibility ─────────────────────── */

.nav-item:focus-visible {
  outline: 2px solid var(--accent); outline-offset: 2px;
}
*:focus:not(:focus-visible) { outline: none; }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
}

/* ── Lucide Icons (base) ───────────────── */

[data-lucide] {
  width: 1em; height: 1em; display: inline-block;
  vertical-align: -0.125em; flex-shrink: 0;
}
`;

  const styleEl = document.createElement('style');
  styleEl.id = 'layout-css';
  styleEl.textContent = LAYOUT_CSS;
  // Prepend so page-specific styles can override
  document.head.insertBefore(styleEl, document.head.firstChild);

  // ════════════════════════════════════════════════════
  // DOM INJECTION
  // ════════════════════════════════════════════════════

  function init() {
    const main = document.querySelector('main.main');
    if (!main) {
      console.warn('[layout.js] No <main class="main"> element found');
      return;
    }

    const banner = document.createElement('div');
    banner.className = 'incident-banner';
    banner.id = 'incidentBanner';
    main.parentNode.insertBefore(banner, main);

    // ── Topbar ──
    const topbar = document.createElement('div');
    topbar.className = 'topbar';
    const meta = PAGE_META[activePage] || PAGE_META.dashboard;
    const chatActive = activePage === 'chat' ? ' active' : '';
    topbar.innerHTML = `
      <div class="topbar-left">
        <h1 style="font-size:20px;font-weight:700;color:var(--text-primary);text-shadow:0 0 8px ${meta.color}80;margin:0;line-height:1.2">${meta.title}</h1>
        <span style="font-size:13px;color:var(--text-secondary);font-weight:400;margin-left:12px">${meta.subtitle}</span>
      </div>
      <div class="topbar-right">
        <a href="/chat.html" class="topbar-chat-btn${chatActive}" id="topbarChatBtn">
          <i data-lucide="message-circle" class="nav-icon"></i>
          <span>Chat</span>
        </a>
      </div>
    `;

    // ── Sidebar ──
    const sidebar = document.createElement('aside');
    sidebar.className = 'sidebar';
    sidebar.id = 'sidebar';
    sidebar.innerHTML = buildSidebarHTML();

    // Insert before main: topbar first, then sidebar
    main.parentNode.insertBefore(topbar, main);
    main.parentNode.insertBefore(sidebar, main);

    // Start SSE
    connectSSE();

    // Start clock
    updateClock();
    setInterval(updateClock, 30000);

    // Start security nav badge polling
    initSecurityBadgePolling();

    // Start WATCHER nav badge polling
    initWatcherBadgePolling();

    // Start tasks nav badge polling
    initTasksBadgePolling();

    // Start Cortex badge polling
    initCortexBadgePolling();

    // Start incident banner polling
    refreshIncidentBanner();
    setInterval(refreshIncidentBanner, 60000);

    // Refresh lucide icons if already loaded
    refreshIcons();

    // Initialize agents badge (SSE may not have fired yet)
    const agentsBadge = document.getElementById('agentsNavBadge');
    if (agentsBadge) agentsBadge.textContent = String(Object.keys(agentState).length);
  }

  function buildSidebarHTML() {
    const isActive = (page) => (activePage === page ? ' active' : '');
    return `
      <div class="sidebar-header">
        <div class="sidebar-name">JARVIS</div>
        <div class="sidebar-product">Clawd Control</div>
      </div>

      <a href="/" class="nav-item tier-1${isActive('dashboard')}">
        <i data-lucide="layout-dashboard" class="nav-icon"></i>
        <span class="nav-label">Overview</span>
      </a>
      <a href="/tasks.html" class="nav-item tier-1${isActive('tasks')}">
        <i data-lucide="check-square" class="nav-icon"></i>
        <span class="nav-label">Tasks</span>
        <span class="nav-count-badge" id="tasksNavBadge">—</span>
      </a>
      <a href="/agents.html" class="nav-item tier-1${isActive('agents')}">
        <i data-lucide="bot" class="nav-icon"></i>
        <span class="nav-label">Agents</span>
        <span class="nav-count-badge" id="agentsNavBadge">—</span>
      </a>

      <div class="nav-tier-gap"></div>

      <a href="/analytics.html" class="nav-item tier-2${isActive('analytics')}">
        <i data-lucide="bar-chart-3" class="nav-icon"></i>
        <span class="nav-label">Usage</span>
      </a>
      <a href="/ops.html" class="nav-item tier-2${isActive('ops')}">
        <i data-lucide="settings" class="nav-icon"></i>
        <span class="nav-label">Operations</span>
        <span class="nav-health-dot" id="opsNavDot"></span>
      </a>
      <a href="/security.html" class="nav-item tier-2${isActive('security')}">
        <i data-lucide="shield" class="nav-icon"></i>
        <span class="nav-label">Security</span>
        <span class="nav-health-dot" id="securityNavDot"></span>
      </a>

      <div class="nav-tier-gap"></div>

      <a href="/cortex" class="nav-item tier-3${isActive('cortex')}">
        <i data-lucide="brain" class="nav-icon"></i>
        <span class="nav-label">CORTEX</span>
        <span class="nav-count-badge" id="cortexNavBadge">—</span>
      </a>
      <a href="/sessions.html" class="nav-item tier-3${isActive('sessions')}">
        <i data-lucide="terminal" class="nav-icon"></i>
        <span class="nav-label">Sessions</span>
      </a>
      <a href="/memory" class="nav-item tier-3${isActive('memory')}">
        <i data-lucide="database" class="nav-icon"></i>
        <span class="nav-label">Memory</span>
      </a>

      <div style="flex:1"></div>

      <div class="sidebar-footer-minimal">
        <div class="logout-link" onclick="window._layoutLogout()">
          <i data-lucide="log-out" class="nav-icon"></i>
          <span>Logout</span>
        </div>
        <span class="version-label">v2.4.0</span>
      </div>
    `;
  }

  // ════════════════════════════════════════════════════
  // SSE CONNECTION
  // ════════════════════════════════════════════════════


  async function updateCortexBadge() {
    const el = document.getElementById('cortexNavBadge');
    if (!el) return;
    try {
      const res = await fetch('/api/cortex/status', { credentials: 'same-origin' });
      if (!res.ok) throw new Error('status');
      const data = await res.json();
      const count = Array.isArray(data?.ladder) ? data.ladder.filter((m) => m?.enabled !== false).length : 0;
      el.textContent = String(count);
      el.classList.remove('unknown');
    } catch {
      el.textContent = '—';
      el.classList.add('unknown');
    }
  }

  function initCortexBadgePolling() {
    updateCortexBadge();
    window.setInterval(updateCortexBadge, 60000);
  }

  function connectSSE() {
    evtSource = new EventSource('/api/stream');

    evtSource.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'snapshot') {
          if (msg.data.agents) {
            for (const [id, st] of Object.entries(msg.data.agents))
              agentState[id] = st;
          }
          if (msg.data.host) window.hostState = msg.data.host;
          renderSidebar();
          updateClock();
          document.dispatchEvent(new CustomEvent('layout:snapshot'));
        } else if (msg.type === 'agent') {
          if (msg.removed || msg.data === null) {
            delete agentState[msg.id];
          } else {
            agentState[msg.id] = msg.data;
          }
          renderSidebar();
          document.dispatchEvent(
            new CustomEvent('layout:agent-update', { detail: { id: msg.id, removed: !!msg.removed } })
          );
        } else if (msg.type === 'host') {
          window.hostState = msg.data;
          document.dispatchEvent(new CustomEvent('layout:host-update'));
        }
      } catch (err) {
        /* ignore parse errors */
      }
    };
    evtSource.onopen = () => {};

    evtSource.onerror = () => {
      setTimeout(() => {
        evtSource?.close();
        connectSSE();
      }, 5000);
    };
  }

  // ════════════════════════════════════════════════════
  // SIDEBAR RENDERING
  // ════════════════════════════════════════════════════

  function renderSidebar() {
    const badge = document.getElementById('agentsNavBadge');
    if (!badge) return;
    badge.textContent = String(Object.keys(agentState).length);
  }

  function mapSecurityStatus(status, stale) {
    if (stale) return '';
    const token = String(status || '').toLowerCase();
    if (token === 'green' || token === 'secure' || token === 'ok' || token === 'success') return 'green';
    if (token === 'yellow' || token === 'warning' || token === 'warn' || token === 'degraded') return 'amber';
    if (token === 'red' || token === 'critical' || token === 'error' || token === 'failed') return 'red';
    return '';
  }

  async function refreshSecurityBadge() {
    const dot = document.getElementById('securityNavDot');
    if (!dot) return;
    try {
      const res = await fetch('/api/security/health', { cache: 'no-store', credentials: 'same-origin' });
      if (!res.ok) throw new Error('health fetch failed');
      const data = await res.json();
      const statusClass = mapSecurityStatus(data.overall_status, data.stale);
      dot.className = `nav-health-dot${statusClass ? ` ${statusClass}` : ''}`;
    } catch {
      dot.className = 'nav-health-dot';
    }
  }

  function initSecurityBadgePolling() {
    if (securityBadgeTimer) clearInterval(securityBadgeTimer);
    refreshSecurityBadge();
    securityBadgeTimer = setInterval(() => refreshSecurityBadge(), 60000);
  }

  function mapWatcherStatus(status, stale) {
    if (stale) return 'amber';
    const token = String(status || '').toLowerCase();
    if (token === 'green' || token === 'healthy' || token === 'ok' || token === 'success') return 'green';
    if (token === 'yellow' || token === 'warning' || token === 'warn' || token === 'stale') return 'amber';
    if (token === 'red' || token === 'critical' || token === 'error' || token === 'failed') return 'red';
    return '';
  }

  async function refreshWatcherBadge() {
    const dot = document.getElementById('opsNavDot');
    if (!dot) return;
    try {
      const res = await fetch('/api/watcher/health', { cache: 'no-store', credentials: 'same-origin' });
      if (!res.ok) throw new Error('health fetch failed');
      const data = await res.json();
      const status = data?.results?.overall_status || (data?.available ? '' : 'red');
      const statusClass = mapWatcherStatus(status, data?.stale);
      dot.className = `nav-health-dot${statusClass ? ` ${statusClass}` : ''}`;
    } catch {
      dot.className = 'nav-health-dot';
    }
  }

  function initWatcherBadgePolling() {
    if (watcherBadgeTimer) clearInterval(watcherBadgeTimer);
    refreshWatcherBadge();
    watcherBadgeTimer = setInterval(() => refreshWatcherBadge(), 60000);
  }

  async function refreshTasksBadge() {
    const badge = document.getElementById('tasksNavBadge');
    if (!badge) return;
    try {
      const res = await fetch('/api/tasks/stats', { cache: 'no-store', credentials: 'same-origin' });
      if (!res.ok) throw new Error('tasks fetch failed');
      const data = await res.json();
      const byStatus = data?.by_status || {};
      const count = Number(byStatus.proposed || 0)
        + Number(byStatus.backlog || 0)
        + Number(byStatus.in_progress || 0)
        + Number(byStatus.review || 0)
        + Number(byStatus.failed || 0);
      badge.textContent = String(count);
    } catch {
      badge.textContent = '—';
    }
  }

  function initTasksBadgePolling() {
    if (tasksBadgeTimer) clearInterval(tasksBadgeTimer);
    refreshTasksBadge();
    tasksBadgeTimer = setInterval(() => refreshTasksBadge(), 60000);
  }

  window.refreshSecurityBadge = refreshSecurityBadge;
  window.refreshWatcherBadge = refreshWatcherBadge;

  async function refreshIncidentBanner() {
    const banner = document.getElementById('incidentBanner');
    if (!banner) return;
    try {
      const res = await fetch('/api/overview/summarizer', { cache: 'no-store', credentials: 'same-origin' });
      if (!res.ok) throw new Error('fetch failed');
      const data = await res.json();
      if (!data || data.available === false) {
        banner.className = 'incident-banner';
        return;
      }

      if (data.current_freshness === 'stale') {
        const ageMin = Math.round((data.age_seconds || 0) / 60);
        banner.className = 'incident-banner stale';
        banner.innerHTML = `Dashboard data is ${ageMin} minutes old.`;
        return;
      }

      const domains = data.domains || {};
      const redDomains = Object.entries(domains).filter(([, d]) => d.health === 'red');
      if (redDomains.length > 0) {
        banner.className = 'incident-banner issues';
        banner.innerHTML = `<a href="/">${redDomains.length} domain${redDomains.length > 1 ? 's' : ''} need${redDomains.length === 1 ? 's' : ''} attention</a>`;
        return;
      }

      banner.className = 'incident-banner';
    } catch {
      banner.className = 'incident-banner';
    }
  }



  // ════════════════════════════════════════════════════
  // HEALTH COMPUTATION (shared across pages)
  // ════════════════════════════════════════════════════

  function computeHealth(a) {
    const checks = [];
    let level = 'healthy';

    // Gateway
    checks.push({
      name: 'Gateway',
      s: a.online ? 'ok' : 'err',
      d: a.online ? 'Connected' : a.error || 'Offline',
    });
    if (!a.online) level = 'down';

    // Channels
    const channels = extractChannels(a);
    if (channels.length > 0) {
      const anyErr = channels.some((c) => c.status === 'error');
      const allOk = channels.every((c) => c.status === 'connected');
      checks.push({
        name: 'Channels',
        s: anyErr ? 'err' : allOk ? 'ok' : 'warn',
        d: `${channels.filter((c) => c.status === 'connected').length}/${channels.length}`,
      });
      if (anyErr && level === 'healthy') level = 'degraded';
    } else {
      checks.push({ name: 'Channels', s: 'off', d: 'None' });
    }

    // Heartbeat
    const hb = getHeartbeatState(a);
    if (hb === 'enabled') {
      const ts = getHeartbeatTs(a);
      const stale = ts && Date.now() - ts > 7200000;
      checks.push({
        name: 'Heartbeat',
        s: stale ? 'warn' : 'ok',
        d: stale ? 'Stale' : 'Active',
      });
      if (stale && level === 'healthy') level = 'degraded';
    } else {
      checks.push({ name: 'Heartbeat', s: 'off', d: 'Disabled' });
      if (level === 'healthy') level = 'idle';
    }

    // Sessions
    const sessions = _extractSessionsBasic(a);
    const recent = sessions.filter((s) => s.ageMs < 3600000);
    checks.push({
      name: 'Sessions',
      s: recent.length > 0 ? 'ok' : 'off',
      d: `${sessions.length} total`,
    });

    // Last poll
    if (a.lastSeen) {
      const ago = Date.now() - a.lastSeen;
      checks.push({
        name: 'Last Poll',
        s: ago < 60000 ? 'ok' : ago < 120000 ? 'warn' : 'err',
        d: timeAgo(a.lastSeen),
      });
    }

    return { level, checks };
  }

  // ── Data extractors ──

  function extractChannels(a) {
    if (!a.channels) return [];
    const ch = a.channels.channels || {};
    if (typeof ch !== 'object') return [];
    return Object.entries(ch).map(([name, info]) => ({
      name,
      status: info?.running
        ? 'connected'
        : info?.lastError
          ? 'error'
          : '',
    }));
  }

  function getHeartbeatState(a) {
    const gwId = a.gatewayAgentId || a.id;
    const agents = a.health?.agents;
    if (Array.isArray(agents)) {
      const m =
        agents.find((ag) => ag.agentId === gwId) ||
        agents.find((ag) => ag.isDefault) ||
        agents[0];
      if (m?.heartbeat?.enabled === true) return 'enabled';
      if (m?.heartbeat?.enabled === false) return 'disabled';
    }
    return 'unknown';
  }

  function getHeartbeatTs(a) {
    if (!a.heartbeat) return null;
    return a.heartbeat.ts || a.heartbeat.sentAt || a.heartbeat.timestamp || null;
  }

  function _extractSessionsBasic(a) {
    if (!a.sessions) return [];
    let list = a.sessions.sessions || a.sessions;
    if (!Array.isArray(list)) {
      if (typeof list === 'object') list = Object.values(list);
      else return [];
    }
    return list
      .filter((s) => s && typeof s === 'object')
      .map((s) => ({
        ageMs: s.ageMs || (s.updatedAt ? Date.now() - s.updatedAt : Infinity),
      }));
  }

  // ── Expose shared functions on window ──
  window.computeHealth = computeHealth;
  window.extractChannels = extractChannels;
  window.getHeartbeatState = getHeartbeatState;
  window.getHeartbeatTs = getHeartbeatTs;

  // ════════════════════════════════════════════════════
  // LOGOUT
  // ════════════════════════════════════════════════════

  window._layoutLogout = async function () {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login';
  };

  // ════════════════════════════════════════════════════
  // CLOCK
  // ════════════════════════════════════════════════════

  function updateClock() {
    window.layoutClock = new Date().toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
    });
  }

  // ════════════════════════════════════════════════════
  // SHARED UTILITIES (exposed on window)
  // ════════════════════════════════════════════════════

  function timeAgo(ts) {
    const d = Date.now() - ts;
    if (d < 60000) return 'just now';
    if (d < 3600000) return Math.floor(d / 60000) + 'm ago';
    if (d < 86400000) return Math.floor(d / 3600000) + 'h ago';
    return Math.floor(d / 86400000) + 'd ago';
  }

  function fmtBytes(b) {
    if (b > 1e9) return (b / 1e9).toFixed(1) + 'GB';
    if (b > 1e6) return (b / 1e6).toFixed(0) + 'MB';
    return (b / 1e3).toFixed(0) + 'KB';
  }

  function formatUptime(s) {
    if (!s) return '—';
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }

  window.timeAgo = timeAgo;
  window.fmtBytes = fmtBytes;
  window.formatUptime = formatUptime;

  window.showToast = function (msg, type = 'success') {
    const t = document.createElement('div');
    t.className = `toast ${type}`;
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 4000);
  };

  window.refreshIcons = function () {
    if (window.lucide) lucide.createIcons();
  };

  // ════════════════════════════════════════════════════
  // KEYBOARD SHORTCUTS
  // ════════════════════════════════════════════════════

  document.addEventListener('keydown', (e) => {
    if (
      e.target.tagName === 'INPUT' ||
      e.target.tagName === 'TEXTAREA' ||
      e.target.tagName === 'SELECT'
    )
      return;
    if (e.key === 'r' || e.key === 'R') location.reload();
    // Number keys: jump to agent
    const num = parseInt(e.key);
    if (num >= 1 && num <= 9) {
      const ids = Object.keys(agentState).sort();
      if (ids[num - 1]) {
        // On dashboard, scroll to card if it exists; otherwise navigate
        const card = document.getElementById(`card-${ids[num - 1]}`);
        if (card) {
          card.scrollIntoView({ behavior: 'smooth', block: 'center' });
        } else {
          window.location.href = `/agent/${encodeURIComponent(ids[num - 1])}`;
        }
      }
    }
  });

  // ════════════════════════════════════════════════════
  // SPA NAVIGATION — keep layout, swap content
  // ════════════════════════════════════════════════════

  // Internal links: fetch page, swap <main>, keep sidebar/topbar/SSE alive
  const SPA_SELECTOR = 'a[href^="/"]';

  function isSpaNavigation(href) {
    // Only SPA-navigate to app pages, not API or external
    if (!href || href.startsWith('/api/') || href.startsWith('/login')) return false;
    return true;
  }

  async function spaNavigate(href, pushState = true) {
    try {
      const currentPath = window.location.pathname;
      if (currentPath === '/security.html' && typeof window.cleanupSecurityTab === 'function') {
        window.cleanupSecurityTab();
      }
      if (currentPath === '/watcher.html' && typeof window.cleanupWatcherTab === 'function') {
        window.cleanupWatcherTab();
      }

      const res = await fetch(href, { credentials: 'same-origin' });
      if (!res.ok || res.redirected) { window.location.href = href; return; }
      const contentType = res.headers.get('content-type') || '';
      if (!contentType.includes('text/html')) { window.location.href = href; return; }

      const html = await res.text();
      const parser = new DOMParser();
      const doc = parser.parseFromString(html, 'text/html');
      const newMain = doc.querySelector('main.main') || doc.querySelector('main');
      const newStyle = doc.querySelector('style');
      const newTitle = doc.querySelector('title')?.textContent;

      if (!newMain) { window.location.href = href; return; }

      // Swap page-specific style
      const oldPageStyle = document.querySelector('style:not(#layout-css)');
      const newPageStyle = newStyle ? newStyle.cloneNode(true) : null;
      if (oldPageStyle && newPageStyle) {
        oldPageStyle.replaceWith(newPageStyle);
      } else if (newPageStyle) {
        document.head.appendChild(newPageStyle);
      }

      // Swap main content
      const currentMain = document.querySelector('main.main') || document.querySelector('main');
      if (currentMain) {
        currentMain.innerHTML = newMain.innerHTML;
      }

      // Update title
      if (newTitle) document.title = newTitle;

      // Update URL
      if (pushState) history.pushState({}, '', href);

      // Update topbar and sidebar active state for SPA navigation
      const newPath = new URL(href, window.location.origin).pathname;
      const newPageMap = {
        '/': 'dashboard', '/dashboard.html': 'dashboard',
        '/agents.html': 'agents', '/sessions.html': 'sessions',
        '/tasks.html': 'tasks', '/ops.html': 'ops',
        '/security.html': 'security', '/analytics.html': 'analytics',
        '/cortex.html': 'cortex', '/cortex': 'cortex',
        '/memory.html': 'memory', '/memory': 'memory',
        '/chat.html': 'chat',
      };
      const newActivePage = newPageMap[newPath] || (newPath.startsWith('/agent/') ? 'agent-detail' : 'other');
      const newMeta = PAGE_META[newActivePage] || PAGE_META.dashboard;

      // Update topbar
      const topbarLeft = document.querySelector('.topbar-left');
      if (topbarLeft) {
        topbarLeft.innerHTML = `<h1 style="font-size:20px;font-weight:700;color:var(--text-primary);text-shadow:0 0 8px ${newMeta.color}80;margin:0;line-height:1.2">${newMeta.title}</h1><span style="font-size:13px;color:var(--text-secondary);font-weight:400;margin-left:12px">${newMeta.subtitle}</span>`;
      }

      // Update Chat button active state
      const chatBtn = document.getElementById('topbarChatBtn');
      if (chatBtn) {
        chatBtn.classList.toggle('active', newActivePage === 'chat');
      }

      // Update sidebar active item
      document.querySelectorAll('.sidebar .nav-item').forEach(item => {
        const itemHref = item.getAttribute('href');
        const itemPage = itemHref ? (newPageMap[itemHref] || '') : '';
        if (itemPage === newActivePage) {
          item.classList.add('active');
        } else {
          item.classList.remove('active');
        }
      });

      // Execute page-specific scripts from the new page in original order.
      // innerHTML does not execute scripts, so run scripts explicitly.
      const newScripts = Array.from(doc.querySelectorAll('script')).filter((script) => {
        const src = (script.getAttribute('src') || '').trim();
        return !/(^|\/)layout\.js(\?.*)?$/.test(src);
      });

      for (const script of newScripts) {
        if (script.src) {
          const scriptEl = document.createElement('script');
          for (const attr of script.attributes) {
            scriptEl.setAttribute(attr.name, attr.value);
          }

          const loadPromise = new Promise((resolve) => {
            scriptEl.onload = () => resolve();
            scriptEl.onerror = () => resolve();
          });

          document.body.appendChild(scriptEl);
          await loadPromise;
          scriptEl.remove();
          continue;
        }

        // Run inline scripts in function scope to avoid cross-page
        // top-level const/let redeclaration errors during SPA navigation.
        const originalAddEventListener = document.addEventListener;
        document.addEventListener = function (type, listener, options) {
          if (type === 'DOMContentLoaded' && document.readyState !== 'loading') {
            try {
              if (typeof listener === 'function') {
                listener.call(document, new Event('DOMContentLoaded'));
              } else if (listener && typeof listener.handleEvent === 'function') {
                listener.handleEvent(new Event('DOMContentLoaded'));
              }
            } catch (err) {
              console.warn('[SPA] DOMContentLoaded listener error:', err);
            }
            return;
          }
          return originalAddEventListener.call(document, type, listener, options);
        };

        try {
          new Function(script.textContent || '')();
        } catch (e) {
          console.warn('[SPA] inline script error:', e);
        } finally {
          document.addEventListener = originalAddEventListener;
        }
      }

      // Re-highlight active sidebar item
      updateSidebarActive(href);

      // Re-render icons
      refreshIcons();

      runPageInitForPath(href);

    } catch (e) {
      console.warn('[SPA] navigation failed, falling back:', e);
      window.location.href = href;
    }
  }

  function runPageInitForPath(href) {
    const pathname = (() => {
      try {
        return new URL(href, window.location.origin).pathname;
      } catch {
        return href;
      }
    })();

    if (pathname === '/ops.html' && typeof window.initOpsTab === 'function') {
      window.initOpsTab();
    }
    if (pathname === '/security.html' && typeof window.initSecurityTab === 'function') {
      window.initSecurityTab();
    }
  }

  function updateSidebarActive(href) {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;
    sidebar.querySelectorAll('.nav-item').forEach(item => {
      item.classList.remove('active');
      const itemHref = item.getAttribute('href');
      if (!itemHref) return;
      if (href === '/' && (itemHref === '/' || itemHref === '/dashboard.html')) {
        item.classList.add('active');
      } else if (itemHref !== '/' && href.startsWith(itemHref)) {
        item.classList.add('active');
      }
    });
  }

  // Intercept clicks on internal links
  document.addEventListener('click', (e) => {
    const link = e.target.closest('a[href]');
    if (!link) return;
    const href = link.getAttribute('href');
    if (!href || !href.startsWith('/')) return;
    if (!isSpaNavigation(href)) return;
    if (e.ctrlKey || e.metaKey || e.shiftKey) return; // allow open in new tab
    e.preventDefault();
    spaNavigate(href);
  });

  // Handle browser back/forward
  window.addEventListener('popstate', () => {
    spaNavigate(window.location.pathname, false);
  });

  // ════════════════════════════════════════════════════
  // INIT — run immediately (script is placed after <main>)
  // ════════════════════════════════════════════════════

  init();
  runPageInitForPath(window.location.pathname);
})();
