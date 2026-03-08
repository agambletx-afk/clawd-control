/**
 * TokenEstimator — Model-agnostic token counting.
 *
 * Provides a default heuristic (words * tokensPerWord) that works
 * reasonably well across models. Users can plug in a custom tokenizer
 * (e.g., tiktoken for GPT-4, or a model-specific BPE tokenizer) for
 * precise counts.
 *
 * Also manages the per-prompt token ceiling, which the user can set
 * to match their model's context window.
 */

class TokenEstimator {
    /**
     * @param {object} config - tokenEstimation config section
     * @param {number} config.tokensPerWord - default 1.3
     * @param {number} config.specialCharTokenWeight - default 0.5
     * @param {number} config.defaultMaxTokens - default 8192
     */
    constructor(config = {}) {
        this.tokensPerWord = config.tokensPerWord || 1.3;
        this.specialCharTokenWeight = config.specialCharTokenWeight || 0.5;
        this.maxTokens = config.defaultMaxTokens || 8192;
        this._customTokenizer = null;
    }

    /**
     * Estimate token count for a string.
     * Uses custom tokenizer if set, otherwise the heuristic.
     * @param {string} text
     * @returns {number}
     */
    estimate(text) {
        if (!text) return 0;

        if (this._customTokenizer) {
            try {
                return this._customTokenizer(text);
            } catch (err) {
                console.warn('[TokenEstimator] Custom tokenizer failed, falling back to heuristic:', err.message);
            }
        }

        return this._heuristicEstimate(text);
    }

    /**
     * Estimate tokens for an array of messages.
     * Each message is expected to have a `content` field (string or array).
     * @param {Array} messages
     * @returns {number}
     */
    estimateMessages(messages) {
        if (!messages || !Array.isArray(messages)) return 0;

        let total = 0;
        for (const msg of messages) {
            const text = this._extractText(msg);
            total += this.estimate(text);
            // Overhead per message (role, formatting) ~4 tokens
            total += 4;
        }
        return total;
    }

    /**
     * Replace the default heuristic with a custom tokenizer function.
     * The function must accept a string and return a number (token count).
     * @param {function} fn - (text: string) => number
     */
    setCustomTokenizer(fn) {
        if (typeof fn !== 'function') {
            throw new Error('Custom tokenizer must be a function that accepts a string and returns a number');
        }
        this._customTokenizer = fn;
    }

    /**
     * Remove the custom tokenizer and revert to the heuristic.
     */
    clearCustomTokenizer() {
        this._customTokenizer = null;
    }

    /**
     * Set the per-prompt token ceiling.
     * @param {number} ceiling
     */
    setMaxTokens(ceiling) {
        if (typeof ceiling !== 'number' || ceiling <= 0) {
            throw new Error('Max tokens must be a positive number');
        }
        this.maxTokens = ceiling;
    }

    /**
     * Get the current per-prompt token ceiling.
     * @returns {number}
     */
    getMaxTokens() {
        return this.maxTokens;
    }

    /**
     * Check whether estimated tokens exceed a fraction of the ceiling.
     * @param {string|Array} textOrMessages - string or message array
     * @param {number} ratio - fraction of maxTokens (e.g., 0.8)
     * @returns {boolean}
     */
    isOverBudget(textOrMessages, ratio = 1.0) {
        const threshold = this.maxTokens * ratio;
        const count = Array.isArray(textOrMessages)
            ? this.estimateMessages(textOrMessages)
            : this.estimate(textOrMessages);
        return count > threshold;
    }

    /**
     * Get remaining token budget given current usage.
     * @param {number} currentTokens
     * @returns {number}
     */
    remaining(currentTokens) {
        return Math.max(0, this.maxTokens - currentTokens);
    }

    // ---------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------

    /**
     * Heuristic token estimation.
     * Words * tokensPerWord + special character contribution.
     * @param {string} text
     * @returns {number}
     */
    _heuristicEstimate(text) {
        if (!text) return 0;

        // Word count (split on whitespace)
        const words = text.split(/\s+/).filter(w => w.length > 0);
        const wordTokens = words.length * this.tokensPerWord;

        // Special characters (code, punctuation, etc.) add fractional tokens
        const specialChars = (text.match(/[^a-zA-Z0-9\s]/g) || []).length;
        const specialTokens = specialChars * this.specialCharTokenWeight;

        return Math.ceil(wordTokens + specialTokens);
    }

    /**
     * Extract text content from a message object.
     * Handles both string content and array content (multi-modal messages).
     * @param {object} msg
     * @returns {string}
     */
    _extractText(msg) {
        if (!msg) return '';
        if (typeof msg.content === 'string') return msg.content;
        if (Array.isArray(msg.content)) {
            return msg.content
                .map(c => c.text || c.content || '')
                .join(' ');
        }
        return String(msg.content || '');
    }
}

module.exports = TokenEstimator;
