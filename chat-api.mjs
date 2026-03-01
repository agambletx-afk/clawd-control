import WebSocket from 'ws';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';

const MAIN_SESSION_KEY = 'agent:main:main';
const SESSION_ROOT_CANDIDATES = [
  '/home/openclaw/.openclaw/agents/main/sessions',
  '/home/ubuntu/.openclaw/agents/main/sessions',
  join(process.env.HOME || '', '.openclaw', 'agents', 'main', 'sessions'),
];

function safeParseJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}

function findSessionRoot() {
  return SESSION_ROOT_CANDIDATES.find((path) => path && existsSync(path)) || SESSION_ROOT_CANDIDATES[0];
}

function firstDefined(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null && value !== '') return value;
  }
  return null;
}

function extractTimestamp(entry) {
  const message = entry?.message && typeof entry.message === 'object' ? entry.message : null;
  const meta = entry?.metadata && typeof entry.metadata === 'object' ? entry.metadata : null;
  const raw = firstDefined(
    entry?.timestamp,
    entry?.ts,
    entry?.createdAt,
    message?.timestamp,
    message?.ts,
    message?.createdAt,
    message?.meta?.timestamp,
    message?.meta?.ts,
    meta?.timestamp,
    meta?.ts,
    meta?.createdAt,
  );
  if (!raw) return null;
  // Normalize: if it's a number, treat as epoch (ms if > 1e12, else seconds)
  if (typeof raw === 'number') {
    const ms = raw > 1e12 ? raw : raw * 1000;
    return new Date(ms).toISOString();
  }
  // If it's a string that parses to a valid date, return it
  const d = new Date(raw);
  if (!isNaN(d.getTime())) return d.toISOString();
  return null;
}

function extractChannel(entry) {
  const message = entry?.message && typeof entry.message === 'object' ? entry.message : null;
  const meta = message?.metadata && typeof message.metadata === 'object' ? message.metadata : null;
  const rootMeta = entry?.metadata && typeof entry.metadata === 'object' ? entry.metadata : null;
  return firstDefined(
    message?.channel,
    message?.provider,
    message?.source,
    meta?.channel,
    meta?.provider,
    meta?.source,
    rootMeta?.channel,
    rootMeta?.provider,
    entry?.channel,
    entry?.provider,
  );
}

function isAborted(entry) {
  const message = entry?.message && typeof entry.message === 'object' ? entry.message : null;
  return Boolean(
    entry?.aborted ||
    entry?.abort ||
    message?.aborted ||
    message?.abort ||
    message?.metadata?.aborted ||
    message?.metadata?.abort,
  );
}

function normalizeRoleEntry(entry) {
  if (!entry || typeof entry !== 'object') return null;

  if (entry.type === 'message' && entry.message && typeof entry.message === 'object') {
    return {
      role: entry.message.role,
      content: entry.message.content,
      timestamp: extractTimestamp(entry),
      channel: extractChannel(entry),
      aborted: isAborted(entry),
    };
  }

  return {
    role: entry.role,
    content: entry.content,
    timestamp: extractTimestamp(entry),
    channel: extractChannel(entry),
    aborted: isAborted(entry),
  };
}

function normalizeContent(role, content) {
  if (typeof content === 'string') return content.trim();

  if (Array.isArray(content)) {
    const textParts = [];
    for (const block of content) {
      if (!block || typeof block !== 'object') continue;
      if (role === 'assistant') {
        if (block.type !== 'text') continue;
        if (typeof block.text === 'string') textParts.push(block.text);
        else if (typeof block.content === 'string') textParts.push(block.content);
      } else if (role === 'user') {
        if (block.type === 'text' && typeof block.text === 'string') textParts.push(block.text);
        else if (typeof block.text === 'string') textParts.push(block.text);
        else if (typeof block.content === 'string') textParts.push(block.content);
      }
    }
    return textParts.join('\n').trim();
  }

  if (content && typeof content === 'object') {
    if (typeof content.text === 'string') return content.text.trim();
    if (typeof content.content === 'string') return content.content.trim();
  }

  return '';
}

/** Strip plugin-injected metadata from displayed messages */
function cleanDisplayContent(role, text) {
  if (!text) return text;
  let cleaned = text;
  if (role === 'user') {
    // Strip [STABILITY CONTEXT]..., [CONTINUITY CONTEXT]..., etc.
    cleaned = cleaned.replace(/\[(?:STABILITY|CONTINUITY|MEMORY|CONTEXT)[^\]]*\][^\n]*(?:\n(?!\n)[^\n]*)*/g, '');
    // Strip leading [timestamp] prefix like [Thu 2026-02-26 18:23 UTC]
    cleaned = cleaned.replace(/^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s*(?:UTC)?\]\s*/m, '');
    // Strip <relevant-memories>...</relevant-memories> blocks
    cleaned = cleaned.replace(/<relevant-memories>[\s\S]*?<\/relevant-memories>\s*/g, '');
    // Strip [dashboard] prefix LAST (after other metadata removed)
    cleaned = cleaned.replace(/^\s*\[dashboard\]\s*/i, '');
  }
  if (role === 'assistant') {
    // Strip [[reply_to_current]], [[reply_to:<id>]] prefixes
    cleaned = cleaned.replace(/^\[\[reply_to[^\]]*\]\]\s*/gm, '');
  }
  return cleaned.trim();
}

function shouldSkipNormalizedMessage(normalized, rawText, text) {
  if (normalized.aborted) return true;
  if (normalized.role !== 'user' && normalized.role !== 'assistant') return true;
  if (!text) return true;

  // Skip system-injected cron/heartbeat messages that have role "user"
  if (normalized.role === 'user' && (
    /^System:\s*\[/.test(rawText) ||
    /Read HEARTBEAT\.md/i.test(rawText) ||
    /^Conversation info \(untrusted metadata\)/m.test(rawText) ||
    /Exec failed/i.test(rawText) ||
    /You remember these earlier conversations/i.test(rawText) ||
    /\[GRAPH MEMORY\]/i.test(rawText) ||
    /Speak from this memory naturally/i.test(rawText)
  )) return true;

  // Skip heartbeat responses
  if (normalized.role === 'assistant' && /^(\[\[reply_to[^\]]*\]\]\s*)?HEARTBEAT_OK\b/.test(rawText)) return true;

  return false;
}

export function getLatestMessage() {
  const root = findSessionRoot();
  const sessionsPath = join(root, 'sessions.json');
  if (!existsSync(sessionsPath)) return null;

  const sessions = safeParseJson(readFileSync(sessionsPath, 'utf8')) || {};
  const entry = sessions[MAIN_SESSION_KEY] || sessions.main || sessions.default || null;
  const sessionId = typeof entry === 'string' ? entry : entry?.sessionId || entry?.id || null;
  if (!sessionId) return null;

  const transcriptPath = join(root, `${sessionId}.jsonl`);
  if (!existsSync(transcriptPath)) return null;

  const lines = readFileSync(transcriptPath, 'utf8').split('\n').filter((line) => line.trim());
  for (let index = lines.length - 1; index >= 0; index--) {
    const entry = safeParseJson(lines[index]);
    if (!entry) continue;

    const normalized = normalizeRoleEntry(entry);
    if (!normalized) continue;

    const rawText = normalizeContent(normalized.role, normalized.content);
    const text = cleanDisplayContent(normalized.role, rawText);
    if (shouldSkipNormalizedMessage(normalized, rawText, text)) continue;

    return {
      timestamp: normalized.timestamp || null,
      role: normalized.role,
    };
  }

  return null;
}

export function getChatMessages({ limit = 100, after = null } = {}) {
  const root = findSessionRoot();
  const sessionsPath = join(root, 'sessions.json');
  if (!existsSync(sessionsPath)) {
    return { messages: [], sessionId: null };
  }

  const sessions = safeParseJson(readFileSync(sessionsPath, 'utf8')) || {};
  const entry = sessions[MAIN_SESSION_KEY] || sessions.main || sessions.default || null;
  const sessionId = typeof entry === 'string' ? entry : entry?.sessionId || entry?.id || null;
  if (!sessionId) {
    return { messages: [], sessionId: null };
  }

  const transcriptPath = join(root, `${sessionId}.jsonl`);
  if (!existsSync(transcriptPath)) {
    return { messages: [], sessionId };
  }

  const afterTs = after ? Date.parse(after) : null;
  const parsedLimit = Number.isFinite(limit) ? Math.max(1, Math.min(500, limit)) : 100;

  const lines = readFileSync(transcriptPath, 'utf8').split('\n').filter((line) => line.trim());
  const messages = [];

  for (let index = 0; index < lines.length; index++) {
    const entry = safeParseJson(lines[index]);
    if (!entry) continue;

    const normalized = normalizeRoleEntry(entry);
    if (!normalized) continue;

    const rawText = normalizeContent(normalized.role, normalized.content);
    const text = cleanDisplayContent(normalized.role, rawText);
    if (shouldSkipNormalizedMessage(normalized, rawText, text)) continue;

    const timestamp = normalized.timestamp || null;
    if (afterTs && timestamp) {
      const ts = Date.parse(timestamp);
      if (Number.isFinite(ts) && ts <= afterTs) continue;
    }

    messages.push({
      id: index,
      role: normalized.role,
      content: text,
      timestamp,
      channel: normalized.channel,
    });
  }

  const finalMessages = after ? messages : messages.slice(-parsedLimit);
  return { messages: finalMessages, sessionId };
}

export class ChatGatewayClient {
  constructor({ configPath, host = '127.0.0.1', port = 18789 } = {}) {
    this.configPath = configPath;
    this.host = host;
    this.port = port;
    this.token = null;
    this.ws = null;
    this.pending = new Map();
    this.counter = 0;
    this.connected = false;
    this.reconnectTimer = null;
    this.connectPromise = null;
    // Agent streaming state for typing indicator
    this.agentStreaming = false;
    this._streamingTimeout = null;
    this._keepalive = null;
  }

  /** True when the agent is actively generating a response for the main session */
  isAgentStreaming() {
    return this.agentStreaming;
  }

  start() {
    if (this.connectPromise) return this.connectPromise;
    this.connectPromise = this._connect();
    return this.connectPromise;
  }

  _loadToken() {
    if (process.env.CC_GATEWAY_TOKEN) return process.env.CC_GATEWAY_TOKEN;
    if (!this.configPath || !existsSync(this.configPath)) return null;
    const config = safeParseJson(readFileSync(this.configPath, 'utf8'));
    return config?.agents?.[0]?.token || null;
  }

  _nextId() {
    this.counter += 1;
    return `chat-${Date.now()}-${this.counter}`;
  }

  _send(frame) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return false;
    if (frame.method !== 'connect') {
      console.log('📤 Gateway send:', JSON.stringify(frame).substring(0, 200));
    }
    this.ws.send(JSON.stringify(frame));
    return true;
  }

  _scheduleReconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => {
      this.connectPromise = null;
      this.start().catch(() => {});
    }, 5000);
  }

  _rejectPending(error) {
    for (const [id, entry] of this.pending.entries()) {
      clearTimeout(entry.timer);
      entry.reject(error);
      this.pending.delete(id);
    }
  }

  async _connect() {
    this.token = this._loadToken();
    if (!this.token || this.token === 'ENV') {
      this.connected = false;
      throw new Error('Gateway token is not configured');
    }

    return new Promise((resolve, reject) => {
      const ws = new WebSocket(`ws://${this.host}:${this.port}`);
      this.ws = ws;

      let handshakeDone = false;
      const onHandshakeError = (err) => {
        if (handshakeDone) return;
        handshakeDone = true;
        this.connected = false;
        reject(err instanceof Error ? err : new Error(String(err || 'Gateway handshake failed')));
      };

      ws.on('message', (data) => {
        const msg = safeParseJson(data.toString());
        if (!msg) return;

        if (msg.type === 'event' && msg.event === 'connect.challenge') {
          this._send({
            type: 'req',
            id: this._nextId(),
            method: 'connect',
            params: {
              minProtocol: 3,
              maxProtocol: 3,
              client: { id: 'openclaw-probe', version: '2.0.0', platform: 'linux', mode: 'probe' },
              auth: { token: this.token },
              role: 'operator',
              scopes: ['operator.read', 'operator.write'],
            },
          });
          return;
        }

        if (msg.type === 'res' && msg.ok && msg.payload?.type === 'hello-ok') {
          this.connected = true;
          console.log('✅ Chat gateway connected to', `ws://${this.host}:${this.port}`);
          // Start keepalive ping
          clearInterval(this._keepalive);
          this._keepalive = setInterval(() => {
            if (this.ws && this.ws.readyState === WebSocket.OPEN) {
              this.ws.ping();
            }
          }, 30000);
          if (!handshakeDone) {
            handshakeDone = true;
            resolve();
          }
          return;
        }

        if (msg.type === 'res' && msg.id && this.pending.has(msg.id)) {
          const pending = this.pending.get(msg.id);
          clearTimeout(pending.timer);
          this.pending.delete(msg.id);
          if (msg.ok) {
            console.log('✅ Gateway request', msg.id, 'succeeded:', JSON.stringify(msg.payload || {}).substring(0, 100));
            pending.resolve(msg.payload || { ok: true });
          } else {
            console.error('❌ Gateway request', msg.id, 'failed:', msg.error?.message || JSON.stringify(msg));
            pending.reject(new Error(msg.error?.message || 'Gateway request failed'));
          }
          return;
        }

        if (msg.type === 'res' && msg.ok === false && !handshakeDone) {
          console.error('❌ Chat gateway handshake rejected:', msg.error?.message || JSON.stringify(msg));
          onHandshakeError(new Error(msg.error?.message || 'Gateway connect rejected'));
          return;
        }

        // Track agent streaming state for typing indicator
        // Actual events use: event:"chat", state:"delta" (streaming) / state:"final" (done)
        if (msg.type === 'event' && msg.event === 'chat') {
          const p = msg.payload;
          if (p?.sessionKey === 'agent:main:main') {
            if (p.state === 'delta' && !this.agentStreaming) {
              this.agentStreaming = true;
              
              clearTimeout(this._streamingTimeout);
              this._streamingTimeout = setTimeout(() => { this.agentStreaming = false; }, 180000);
            } else if (p.state === 'delta') {
              // Already streaming, just reset timeout
              clearTimeout(this._streamingTimeout);
              this._streamingTimeout = setTimeout(() => { this.agentStreaming = false; }, 180000);
            } else if (p.state === 'final') {
              this.agentStreaming = false;
              
              clearTimeout(this._streamingTimeout);
            }
          }
          return;
        }

        // Also track agent lifecycle events if present
        if (msg.type === 'event' && msg.event === 'agent') {
          const p = msg.payload;
          if (p?.sessionKey === 'agent:main:main' && p.stream === 'lifecycle' && p.data?.phase === 'end') {
            this.agentStreaming = false;
            clearTimeout(this._streamingTimeout);
          }
          return;
        }

        // Log any other unhandled messages for debugging
        if (msg.type !== 'event' || !['health', 'presence', 'tick'].includes(msg.event)) {
          console.log('📨 Gateway unhandled msg:', JSON.stringify(msg).substring(0, 200));
        }
      });

      ws.on('open', () => {});

      ws.on('close', () => {
        this.connected = false;
        this.connectPromise = null;
        clearInterval(this._keepalive);
        this._rejectPending(new Error('Gateway disconnected'));
        this._scheduleReconnect();
        console.log('⚠️ Chat gateway disconnected, will reconnect');
      });

      ws.on('error', (err) => {
        this.connected = false;
        if (!handshakeDone) onHandshakeError(err);
      });
    });
  }

  async sendMessage(text) {
    if (!this.connected) {
      try {
        await this.start();
      } catch {
        throw new Error('Gateway not connected');
      }
    }

    // Mark streaming immediately: agent is processing from the moment gateway accepts
    this.agentStreaming = true;
    clearTimeout(this._streamingTimeout);
    this._streamingTimeout = setTimeout(() => { this.agentStreaming = false; }, 180000); // 3 min safety

    const id = this._nextId();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        this.agentStreaming = false; // Reset on timeout
        clearTimeout(this._streamingTimeout);
        reject(new Error('Gateway request timeout'));
      }, 30000);

      this.pending.set(id, { resolve, reject, timer });

      const sent = this._send({
        type: 'req',
        id,
        method: 'chat.send',
        params: {
          sessionKey: 'agent:main:main',
          message: `[dashboard] ${text}`,
          idempotencyKey: `dash-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        },
      });

      if (!sent) {
        clearTimeout(timer);
        this.pending.delete(id);
        this.agentStreaming = false; // Reset on send failure
        clearTimeout(this._streamingTimeout);
        reject(new Error('Gateway not connected'));
      }
    });
  }
}
