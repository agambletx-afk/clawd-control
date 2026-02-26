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
  return firstDefined(
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
    if (normalized.aborted) continue;
    if (normalized.role !== 'user' && normalized.role !== 'assistant') continue;

    const text = normalizeContent(normalized.role, normalized.content);
    if (!text) continue;

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
    this.ws.send(JSON.stringify(frame));
    return true;
  }

  _scheduleReconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => {
      this.connectPromise = null;
      this.start().catch(() => {});
    }, 10000);
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
              client: { id: 'openclaw-probe', version: '2.0.0', platform: 'darwin', mode: 'probe' },
              auth: { token: this.token },
              role: 'operator',
              scopes: ['operator.read', 'operator.write'],
            },
          });
          return;
        }

        if (msg.type === 'res' && msg.ok && msg.payload?.type === 'hello-ok') {
          this.connected = true;
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
          if (msg.ok) pending.resolve(msg.payload || { ok: true });
          else pending.reject(new Error(msg.error?.message || 'Gateway request failed'));
          return;
        }

        if (msg.type === 'res' && msg.ok === false && !handshakeDone) {
          onHandshakeError(new Error(msg.error?.message || 'Gateway connect rejected'));
        }
      });

      ws.on('open', () => {});

      ws.on('close', () => {
        this.connected = false;
        this._rejectPending(new Error('Gateway disconnected'));
        this._scheduleReconnect();
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

    const id = this._nextId();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error('Gateway request timeout'));
      }, 10000);

      this.pending.set(id, { resolve, reject, timer });

      const sent = this._send({
        type: 'req',
        id,
        method: 'chat.send',
        params: { text },
      });

      if (!sent) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(new Error('Gateway not connected'));
      }
    });
  }
}
