/**
 * ContextBudget — Token budget allocation with priority tiers.
 *
 * Extracted from Clint's tokenOptimizer.js (budget allocation, lines 1-200)
 * and contextWeighting.js (priority tiers, lines 354-555).
 *
 * Stripped of style detection (DIRECT/EXPLORATORY/etc.) — pool ratios
 * are fixed and configurable. Model-agnostic via TokenEstimator.
 *
 * Priority tiers:
 *   ESSENTIAL (1.0) → Last N turns (always full, never truncated)
 *   HIGH      (0.8) → Continuity anchors
 *   MEDIUM    (0.6) → Recent history (truncated by age)
 *   LOW       (0.4) → Older history (aggressively truncated)
 *   MINIMAL   (0.2) → Archive retrievals (summary only)
 */

const TIERS = {
    ESSENTIAL: 'essential',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
    MINIMAL: 'minimal'
};

const TIER_WEIGHTS = {
    essential: 1.0,
    high: 0.8,
    medium: 0.6,
    low: 0.4,
    minimal: 0.2
};

class ContextBudget {
    /**
     * @param {object} config - full plugin config (reads contextBudget section)
     * @param {TokenEstimator} tokenEstimator
     */
    constructor(config = {}, tokenEstimator) {
        const cb = config.contextBudget || config;
        this.budgetRatio = cb.contextBudgetRatio || 0.65;
        this.recentTurnsAlwaysFull = cb.recentTurnsAlwaysFull || 5;
        this.recentTurnCharLimit = cb.recentTurnCharLimit || 3000;
        this.midTurnCharLimit = cb.midTurnCharLimit || 1500;
        this.olderTurnCharLimit = cb.olderTurnCharLimit || 500;
        this.poolRatios = cb.poolRatios || {
            essential: 0.30,
            high: 0.25,
            medium: 0.25,
            low: 0.15,
            minimal: 0.05
        };

        this.tokenEstimator = tokenEstimator;
    }

    /**
     * Optimize a message array within the token budget.
     *
     * @param {Array} messages - full conversation messages
     * @param {number} [maxTokens] - override ceiling; defaults to tokenEstimator.maxTokens
     * @returns {{ optimizedMessages: Array, tokenCount: number, budgetReport: object }}
     */
    optimize(messages, maxTokens) {
        if (!messages || messages.length === 0) {
            return { optimizedMessages: [], tokenCount: 0, budgetReport: this._emptyReport() };
        }

        const ceiling = maxTokens || this.tokenEstimator.getMaxTokens();
        const totalBudget = Math.floor(ceiling * this.budgetRatio);
        const pools = this._allocatePools(totalBudget);

        // Classify each message into a tier
        const classified = messages.map((msg, idx) => ({
            message: msg,
            tier: this._classifyMessage(msg, idx, messages.length),
            originalIndex: idx
        }));

        // Group by tier
        const groups = {};
        for (const tier of Object.values(TIERS)) {
            groups[tier] = classified.filter(c => c.tier === tier);
        }

        // Build optimized output respecting pool budgets
        const optimized = [];
        const usage = {};
        let totalTokens = 0;

        for (const tier of Object.values(TIERS)) {
            const pool = pools[tier];
            let poolUsed = 0;
            usage[tier] = { allocated: pool, used: 0, messages: 0 };

            for (const item of groups[tier]) {
                const text = this._extractText(item.message);
                const charLimit = this._charLimitForTier(tier, item.originalIndex, messages.length);
                const truncated = this._truncateToLimit(text, charLimit);

                const tokens = this.tokenEstimator.estimate(truncated);

                if (poolUsed + tokens <= pool) {
                    optimized.push({
                        ...item.message,
                        content: truncated,
                        _tier: tier,
                        _originalIndex: item.originalIndex
                    });
                    poolUsed += tokens;
                    totalTokens += tokens;
                    usage[tier].messages++;
                }
            }
            usage[tier].used = poolUsed;
        }

        // Sort back to original order
        optimized.sort((a, b) => a._originalIndex - b._originalIndex);

        return {
            optimizedMessages: optimized,
            tokenCount: totalTokens,
            budgetReport: {
                ceiling,
                totalBudget,
                totalUsed: totalTokens,
                remaining: totalBudget - totalTokens,
                pools: usage
            }
        };
    }

    /**
     * Allocate token pools from total budget.
     * @param {number} totalBudget
     * @returns {object} pool sizes keyed by tier name
     */
    _allocatePools(totalBudget) {
        const pools = {};
        for (const [tier, ratio] of Object.entries(this.poolRatios)) {
            pools[tier] = Math.floor(totalBudget * ratio);
        }
        return pools;
    }

    /**
     * Classify a message into a priority tier based on position.
     *
     * @param {object} msg
     * @param {number} index - position in array
     * @param {number} total - total message count
     * @returns {string} tier name
     */
    _classifyMessage(msg, index, total) {
        // System messages are always essential
        if (msg.role === 'system') return TIERS.ESSENTIAL;

        const distanceFromEnd = total - 1 - index;

        // Last N turns → essential
        if (distanceFromEnd < this.recentTurnsAlwaysFull * 2) { // *2 for user+assistant pairs
            return TIERS.ESSENTIAL;
        }

        // Next N turns → medium
        if (distanceFromEnd < this.recentTurnsAlwaysFull * 4) {
            return TIERS.MEDIUM;
        }

        // Older → low
        if (distanceFromEnd < this.recentTurnsAlwaysFull * 8) {
            return TIERS.LOW;
        }

        // Oldest → minimal
        return TIERS.MINIMAL;
    }

    /**
     * Determine the character truncation limit for a message.
     * @param {string} tier
     * @param {number} index
     * @param {number} total
     * @returns {number}
     */
    _charLimitForTier(tier, index, total) {
        switch (tier) {
            case TIERS.ESSENTIAL:
                return this.recentTurnCharLimit;
            case TIERS.HIGH:
                return this.recentTurnCharLimit;
            case TIERS.MEDIUM:
                return this.midTurnCharLimit;
            case TIERS.LOW:
                return this.olderTurnCharLimit;
            case TIERS.MINIMAL:
                return Math.floor(this.olderTurnCharLimit / 2);
            default:
                return this.olderTurnCharLimit;
        }
    }

    /**
     * Truncate text to a character limit, preserving sentence boundaries where possible.
     * @param {string} text
     * @param {number} charLimit
     * @returns {string}
     */
    _truncateToLimit(text, charLimit) {
        if (!text || text.length <= charLimit) return text;

        // Try to break at a sentence boundary
        const truncated = text.substring(0, charLimit);
        const lastPeriod = truncated.lastIndexOf('.');
        const lastNewline = truncated.lastIndexOf('\n');
        const breakPoint = Math.max(lastPeriod, lastNewline);

        if (breakPoint > charLimit * 0.5) {
            return truncated.substring(0, breakPoint + 1) + ' [...]';
        }

        return truncated + ' [...]';
    }

    _extractText(msg) {
        if (!msg) return '';
        if (typeof msg.content === 'string') return msg.content;
        if (Array.isArray(msg.content)) {
            return msg.content.map(c => c.text || c.content || '').join(' ');
        }
        return String(msg.content || '');
    }

    _emptyReport() {
        return {
            ceiling: 0,
            totalBudget: 0,
            totalUsed: 0,
            remaining: 0,
            pools: {}
        };
    }
}

// Export tier constants for external use
ContextBudget.TIERS = TIERS;
ContextBudget.TIER_WEIGHTS = TIER_WEIGHTS;

module.exports = ContextBudget;
