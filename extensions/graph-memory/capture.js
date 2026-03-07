const crypto = require('crypto');

const MAX_FACTS_PER_TURN = 3;

const TTL_SECONDS = {
    permanent: null,
    stable: 90 * 24 * 3600,
    active: 14 * 24 * 3600,
    session: 24 * 3600,
    checkpoint: 4 * 3600,
};

const SENSITIVE_PATTERNS = [
    /password/i,
    /api.?key/i,
    /\bsecret\b/i,
    /token\s+is/i,
    /\bssn\b/i,
    /credit.?card/i,
    /sk-[A-Za-z0-9_-]{6,}/,
    /ghp_[A-Za-z0-9]{10,}/,
    /glpat-[A-Za-z0-9_-]{10,}/,
    /AIza[A-Za-z0-9_-]{10,}/,
    /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/i,
];

function initCapture(api, db, config = {}) {
    if (config.capture === false) {
        api.logger?.info?.('[graph-memory] per-turn capture disabled by config');
        return;
    }

    if (!db) {
        api.logger?.warn?.('[graph-memory] capture unavailable (no database handle)');
        return;
    }

    api.on('agent_end', async (event) => {
        try {
            if (!event?.success) return;

            const messages = Array.isArray(event.messages) ? event.messages : [];
            if (messages.length === 0) return;

            const lastUser = [...messages].reverse().find((m) => m?.role === 'user');
            const lastUserText = extractMessageText(lastUser).trim();
            if (!lastUserText || lastUserText.length < 5) return;

            const assistantTexts = messages
                .filter((m) => m?.role === 'assistant')
                .map((m) => extractMessageText(m))
                .map((s) => s.trim())
                .filter(Boolean);

            let inserted = 0;
            for (const text of assistantTexts) {
                if (inserted >= MAX_FACTS_PER_TURN) break;
                if (!shouldCapture(text)) continue;

                const category = detectCategory(text);
                let { entity, key, value } = extractStructuredFields(text);

                if (!entity || !key || !value) {
                    entity = category === 'system' ? 'Jarvis' : 'Adam';
                    key = 'note';
                    value = text.trim().slice(0, 500);
                }

                if (hasDuplicate(db, entity, key, value)) continue;

                const decayClass = detectDecayClass(entity, key, value);
                insertFact(db, {
                    text,
                    category,
                    entity,
                    key,
                    value,
                    decayClass,
                });

                inserted += 1;
                api.logger?.info?.(`[graph-memory] captured fact: ${entity}.${key} (${category}/${decayClass})`);
            }
        } catch (err) {
            api.logger?.warn?.(`[graph-memory] capture error: ${err.message}`);
        }
    });

    api.logger?.info?.('[graph-memory] per-turn capture hook registered');
}

function extractMessageText(message) {
    if (!message) return '';
    if (typeof message.content === 'string') return message.content;
    if (Array.isArray(message.content)) {
        return message.content
            .filter((part) => part?.type === 'text')
            .map((part) => part.text || '')
            .join(' ');
    }
    return '';
}

function shouldCapture(text) {
    if (!text) return false;
    const trimmed = text.trim();

    if (trimmed.length < 10 || trimmed.length > 500) return false;
    if (hasXmlOrHtml(trimmed)) return false;
    if (hasHeavyMarkdown(trimmed)) return false;
    if (countEmoji(trimmed) > 3) return false;

    return !SENSITIVE_PATTERNS.some((pattern) => pattern.test(trimmed));
}

function hasXmlOrHtml(text) {
    if (/<\/?[A-Za-z][^>]*>/.test(text)) return true;
    if (/\[GRAPH MEMORY\]/i.test(text)) return true;
    if (/relevant-memories/i.test(text)) return true;
    return false;
}

function hasHeavyMarkdown(text) {
    if (/```[\s\S]*?```/.test(text)) return true;

    const hasHeader = /^\s{0,3}#{1,6}\s+/m.test(text);
    const hasBold = /\*\*[^*]+\*\*/.test(text) || /__[^_]+__/.test(text);
    const hasList = /^\s*[-*+]\s+/m.test(text) || /^\s*\d+\.\s+/m.test(text);
    if (hasHeader || (hasBold && hasList)) return true;

    return false;
}

function countEmoji(text) {
    const matches = text.match(/[\u{1F300}-\u{1FAFF}]/gu);
    return matches ? matches.length : 0;
}

function detectCategory(text) {
    const lower = text.toLowerCase();

    if (hasAny(lower, ['decided', 'chose', 'picked', 'decision', 'selected', 'went with'])) return 'decision';
    if (hasAny(lower, ['prefer', 'preference', 'like to', 'use']) && (lower.includes(' over ') || lower.includes(' instead of '))) return 'preference';
    if (hasAny(lower, ['i am', "i'm", 'my name', 'adam', 'we are', 'identity'])) return 'identity';
    if (hasAny(lower, ['server', 'system', 'deploy', 'database', 'config', 'cron', 'plugin', 'api', 'endpoint', 'port'])) return 'system';
    if (hasAny(lower, ['team', 'met', 'relationship', 'partner', 'manager', 'collabor'])) return 'relationship';
    if (hasAny(lower, ['task', 'project', 'work', 'ticket', 'deadline', 'deliver'])) return 'work';
    return 'work';
}

function hasAny(text, terms) {
    return terms.some((term) => text.includes(term));
}

function extractStructuredFields(text) {
    const s = text.trim();

    const decisionMatch = s.match(/\b(?:decided|chose|picked|went with|selected)\s+(.+?)(?:\s+because\s+(.+))?$/i);
    if (decisionMatch) {
        return {
            entity: 'decision',
            key: cleanField(decisionMatch[1]),
            value: cleanField(decisionMatch[2] || 'no rationale recorded'),
        };
    }

    const choiceMatch = s.match(/\b(?:use|using|chose|prefer|picked)\s+(.+?)\s+(?:over|instead of)\s+(.+?)(?:\s+because\s+(.+))?$/i);
    if (choiceMatch) {
        return {
            entity: 'decision',
            key: `${cleanField(choiceMatch[1])} over ${cleanField(choiceMatch[2])}`,
            value: cleanField(choiceMatch[3] || 'preference'),
        };
    }

    const ruleMatch = s.match(/\b(always|never|must|should)\s+(.+)$/i);
    if (ruleMatch) {
        return {
            entity: 'convention',
            key: cleanField(ruleMatch[2]),
            value: /^never$/i.test(ruleMatch[1]) ? 'never' : 'always',
        };
    }

    const possessiveMatch = s.match(/^([A-Za-z][A-Za-z0-9_\-\s]{0,80})'s\s+([A-Za-z][A-Za-z0-9_\-\s]{0,80})\s+is\s+(.+)$/i);
    if (possessiveMatch) {
        return {
            entity: cleanField(possessiveMatch[1]),
            key: normalizeKey(possessiveMatch[2]),
            value: cleanField(possessiveMatch[3]),
        };
    }

    const myPossessiveMatch = s.match(/^my\s+([A-Za-z][A-Za-z0-9_\-\s]{0,80})\s+is\s+(.+)$/i);
    if (myPossessiveMatch) {
        return {
            entity: 'user',
            key: normalizeKey(myPossessiveMatch[1]),
            value: cleanField(myPossessiveMatch[2]),
        };
    }

    const preferenceMatch = s.match(/\bI\s+(?:prefer|like|want)\s+(.+)$/i);
    if (preferenceMatch) {
        return {
            entity: 'user',
            key: 'preference',
            value: cleanField(preferenceMatch[1]),
        };
    }

    const emailMatch = s.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i);
    if (emailMatch) {
        return { entity: null, key: 'email', value: emailMatch[0] };
    }

    const phoneMatch = s.match(/\b(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b/);
    if (phoneMatch) {
        return { entity: null, key: 'phone', value: phoneMatch[0] };
    }

    return { entity: null, key: null, value: null };
}

function normalizeKey(key) {
    return cleanField(key).toLowerCase().replace(/\s+/g, '_');
}

function cleanField(value) {
    return String(value || '').trim().replace(/\s+/g, ' ').slice(0, 500);
}

function detectDecayClass(entity, key, value) {
    const text = `${entity || ''} ${key || ''} ${value || ''}`.toLowerCase();
    const keyLower = (key || '').toLowerCase();
    const entityLower = (entity || '').toLowerCase();

    if (
        entityLower === 'decision' || entityLower === 'convention'
        || containsAny(keyLower, ['name', 'email', 'architecture', 'decision', 'birthday', 'phone', 'language', 'location'])
        || /(decided|architecture|always use|never use)/i.test(text)
    ) {
        return 'permanent';
    }

    if (
        containsAny(keyLower, ['current_file', 'temp', 'debug', 'working_on_right_now'])
        || /(currently debugging|right now|this session)/i.test(text)
    ) {
        return 'session';
    }

    if (
        containsAny(keyLower, ['task', 'todo', 'wip', 'branch', 'sprint', 'blocker'])
        || /(working on|need to|todo|blocker|sprint)/i.test(text)
    ) {
        return 'active';
    }

    if (containsAny(keyLower, ['checkpoint', 'preflight'])) {
        return 'checkpoint';
    }

    return 'stable';
}

function containsAny(text, list) {
    return list.some((item) => text.includes(item));
}

function getExpiresAt(nowSec, decayClass) {
    const ttl = TTL_SECONDS[decayClass];
    return ttl == null ? null : nowSec + ttl;
}

function hasDuplicate(db, entity, key, value) {
    const row = db.prepare(`
        SELECT 1
        FROM facts
        WHERE COALESCE(entity, '') = ?
          AND COALESCE(key, '') = ?
          AND COALESCE(value, '') = ?
        LIMIT 1
    `).get(entity || '', key || '', value || '');

    return !!row;
}

function insertFact(db, fact) {
    const nowSec = Math.floor(Date.now() / 1000);
    const nowIso = new Date(nowSec * 1000).toISOString();

    db.prepare(`
        INSERT INTO facts (
            id, text, category, importance, entity, key, value,
            source, created_at, decay_class, expires_at, last_confirmed_at, confidence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
        crypto.randomUUID(),
        fact.text,
        fact.category,
        0.7,
        fact.entity,
        fact.key,
        fact.value,
        'auto-capture:session',
        nowIso,
        fact.decayClass,
        getExpiresAt(nowSec, fact.decayClass),
        nowSec,
        1.0
    );
}

module.exports = { initCapture };
