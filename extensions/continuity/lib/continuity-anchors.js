/**
 * ContinuityAnchors — Detect and preserve identity moments,
 * contradictions, and tensions across a conversation.
 *
 * Extracted from Clint's tokenOptimizer.js (lines 288-370).
 * Stripped of emergence analysis and arc-tension system.
 * Keyword lists are fully configurable per domain.
 *
 * These anchors are HIGH priority in the context budget —
 * they survive compaction so the agent doesn't lose track
 * of unresolved relational threads.
 */

class ContinuityAnchors {
    /**
     * @param {object} config - anchors config section
     * @param {boolean} config.enabled
     * @param {number} config.maxAge - ms before anchors expire
     * @param {number} config.maxCount - max anchors retained
     * @param {object} config.keywords - { identity, contradiction, tension }
     */
    constructor(config = {}) {
        const anchorsConfig = config.anchors || config;
        this.enabled = anchorsConfig.enabled !== false;
        this.maxAge = anchorsConfig.maxAge || 7200000; // 2 hours
        this.maxCount = anchorsConfig.maxCount || 15;
        this.keywords = anchorsConfig.keywords || {
            identity: ['who am i', 'what am i', 'my name', 'i am', 'identity'],
            contradiction: ['but', 'however', 'contradict', 'conflict', 'tension'],
            tension: ['problem', 'issue', 'challenge', 'struggle', 'confused']
        };

        // Active anchors — persisted across calls within a session
        this._anchors = [];
    }

    /**
     * Scan messages for anchor-worthy moments.
     * Only scans user messages — agent responses don't generate anchors.
     *
     * @param {Array} messages - conversation message array
     * @returns {Array} anchors with { type, priority, text, timestamp, messageIndex }
     */
    detect(messages) {
        if (!this.enabled || !messages || messages.length === 0) {
            return this._anchors;
        }

        const now = Date.now();

        for (let i = 0; i < messages.length; i++) {
            const msg = messages[i];
            if (msg.role !== 'user') continue;

            const text = this._extractText(msg);
            if (!text) continue;

            const lowerText = text.toLowerCase();
            const timestamp = msg.timestamp ? new Date(msg.timestamp).getTime() : now;

            // Check each anchor type
            for (const [type, keywords] of Object.entries(this.keywords)) {
                for (const keyword of keywords) {
                    if (lowerText.includes(keyword.toLowerCase())) {
                        // Avoid duplicate anchors for the same message
                        const isDuplicate = this._anchors.some(
                            a => a.messageIndex === i && a.type === type
                        );
                        if (isDuplicate) continue;

                        this._anchors.push({
                            type,
                            priority: this._priorityForType(type),
                            text: this._truncate(text, 200),
                            timestamp,
                            messageIndex: i,
                            keyword
                        });
                        break; // One anchor per type per message
                    }
                }
            }
        }

        // Prune expired and excess anchors
        this._anchors = this.prune(this._anchors, this.maxAge, this.maxCount);

        return this._anchors;
    }

    /**
     * Format anchors into a prompt-injectable block.
     * @param {Array} [anchors] - optional override; defaults to internal state
     * @returns {string} formatted block or empty string
     */
    format(anchors) {
        const list = anchors || this._anchors;
        if (!list || list.length === 0) return '';

        const lines = ['[CONTINUITY ANCHORS]'];
        for (const anchor of list) {
            const age = this._formatAge(anchor.timestamp);
            const label = anchor.type.toUpperCase();
            lines.push(`${label}: "${anchor.text}" (${age})`);
        }
        return lines.join('\n');
    }

    /**
     * Prune anchors by age and count.
     * Keeps highest priority first, then most recent.
     *
     * @param {Array} anchors
     * @param {number} maxAge - ms
     * @param {number} maxCount
     * @returns {Array} filtered anchors
     */
    prune(anchors, maxAge, maxCount) {
        const now = Date.now();
        const cutoff = now - (maxAge || this.maxAge);

        // Remove expired
        let pruned = anchors.filter(a => a.timestamp >= cutoff);

        // Sort by priority (desc) then recency (desc)
        pruned.sort((a, b) => {
            if (b.priority !== a.priority) return b.priority - a.priority;
            return b.timestamp - a.timestamp;
        });

        // Enforce count limit
        if (pruned.length > (maxCount || this.maxCount)) {
            pruned = pruned.slice(0, maxCount || this.maxCount);
        }

        return pruned;
    }

    /**
     * Get current anchors without modification.
     * @returns {Array}
     */
    getAnchors() {
        return [...this._anchors];
    }

    /**
     * Clear all anchors (e.g., on session reset).
     */
    reset() {
        this._anchors = [];
    }

    // ---------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------

    _priorityForType(type) {
        switch (type) {
            case 'identity': return 1.0;
            case 'contradiction': return 1.0;
            case 'tension': return 0.7;
            default: return 0.5;
        }
    }

    _truncate(text, maxLen) {
        if (text.length <= maxLen) return text;
        return text.substring(0, maxLen - 3) + '...';
    }

    _formatAge(timestamp) {
        const minutes = Math.round((Date.now() - timestamp) / 60000);
        if (minutes < 1) return 'just now';
        if (minutes < 60) return `${minutes}min ago`;
        const hours = Math.round(minutes / 60);
        return `${hours}h ago`;
    }

    _extractText(msg) {
        if (!msg) return '';
        if (typeof msg.content === 'string') return msg.content;
        if (Array.isArray(msg.content)) {
            return msg.content.map(c => c.text || c.content || '').join(' ');
        }
        return String(msg.content || '');
    }
}

module.exports = ContinuityAnchors;
