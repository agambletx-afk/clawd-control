import crypto from "crypto";
import fs from "fs";
import path from "path";

const TTL_MS = 60 * 60 * 1000;
const MAX_LOG_LINES = 500;
const DEFAULT_LOG_PATH = "/home/openclaw/.openclaw/workspace/.telegram-dedupe-log";

const dedupeState = new Map();

function normalizeContent(content) {
    return String(content || "")
        .trim()
        .toLowerCase()
        .replace(/\s+/g, " ");
}

function isHeartbeatOnly(normalizedContent) {
    if (!normalizedContent) return false;
    const compact = normalizedContent.replace(/[\s_\-:]+/g, "");
    return compact === "heartbeatok" || compact === "heartbeat";
}

function createFingerprint(normalizedContent, to) {
    const keyMaterial = `${normalizedContent}|${String(to || "")}`;
    return crypto.createHash("sha256").update(keyMaterial).digest("hex");
}

function contentPreview(content) {
    return String(content || "").replace(/\s+/g, " ").trim().slice(0, 160);
}

function getLogPath() {
    return process.env.TELEGRAM_DEDUPE_LOG_PATH || DEFAULT_LOG_PATH;
}

function appendJsonLog(record) {
    const logPath = getLogPath();
    const line = `${JSON.stringify(record)}\n`;
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    fs.appendFileSync(logPath, line, "utf8");

    const allLines = fs.readFileSync(logPath, "utf8").split("\n").filter(Boolean);
    if (allLines.length > MAX_LOG_LINES) {
        const trimmed = `${allLines.slice(-MAX_LOG_LINES).join("\n")}\n`;
        fs.writeFileSync(logPath, trimmed, "utf8");
    }
}

export function message_sending(event = {}, ctx = {}) {
    if (ctx.channelId !== "telegram") return {};

    const normalizedContent = normalizeContent(event.content);
    if (!normalizedContent || isHeartbeatOnly(normalizedContent)) {
        return {};
    }

    const now = Date.now();
    const fingerprint = createFingerprint(normalizedContent, event.to);
    const active = dedupeState.get(fingerprint);

    if (active) {
        if (active.expiresAt <= now) {
            dedupeState.delete(fingerprint);
        } else {
            appendJsonLog({
                timestamp: new Date(now).toISOString(),
                event: "dedupe_hit",
                channelId: ctx.channelId,
                to: String(event.to || ""),
                fingerprint_short: fingerprint.slice(0, 12),
                ttl_ms: TTL_MS,
                remaining_ms: active.expiresAt - now,
                content_preview: contentPreview(event.content)
            });
            return { cancel: true };
        }
    }

    dedupeState.set(fingerprint, {
        expiresAt: now + TTL_MS,
        firstSeenAt: now,
        to: String(event.to || ""),
        contentPreview: contentPreview(event.content)
    });

    appendJsonLog({
        timestamp: new Date(now).toISOString(),
        event: "dedupe_miss",
        channelId: ctx.channelId,
        to: String(event.to || ""),
        fingerprint_short: fingerprint.slice(0, 12),
        ttl_ms: TTL_MS,
        remaining_ms: TTL_MS,
        content_preview: contentPreview(event.content)
    });

    return {};
}

export function message_sent(event = {}, ctx = {}) {
    if (ctx.channelId !== "telegram") return;

    appendJsonLog({
        timestamp: new Date().toISOString(),
        event: "delivery_result",
        channelId: ctx.channelId,
        to: String(event.to || ""),
        success: Boolean(event.success),
        error: event.error ? String(event.error) : undefined,
        content_preview: contentPreview(event.content)
    });
}

export default {
    message_sending,
    message_sent
};
