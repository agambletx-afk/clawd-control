/**
 * Compactor — Threshold-triggered context compression.
 *
 * Extracted from Clint's contextCompactor.js (244 lines).
 * Stripped of emergence-aware compression. Two strategies:
 *
 * 1. Conversational: Budget-aware selection + anchor preservation.
 *    Used for general conversation — compresses by tier priority,
 *    keeping recent turns and continuity anchors intact.
 *
 * 2. Task-aware: Prioritizes original user request, task state,
 *    tool results, and agent reasoning. Used when a task context
 *    message is present in the conversation.
 *
 * Triggers when estimated tokens exceed threshold (default 80%
 * of the token ceiling).
 */

class Compactor {
    /**
     * @param {object} config - full plugin config (reads compaction section)
     * @param {ContextBudget} contextBudget
     * @param {ContinuityAnchors} continuityAnchors
     * @param {TokenEstimator} tokenEstimator
     */
    constructor(config = {}, contextBudget, continuityAnchors, tokenEstimator) {
        const cc = config.compaction || config;
        this.threshold = cc.threshold || 0.80;
        this.fallbackMessages = cc.fallbackMessages || 20;
        this.taskAwareCompaction = cc.taskAwareCompaction !== false;

        this.contextBudget = contextBudget;
        this.continuityAnchors = continuityAnchors;
        this.tokenEstimator = tokenEstimator;
    }

    /**
     * Check whether compaction should trigger.
     *
     * @param {Array} messages
     * @param {number} [maxTokens] - override ceiling
     * @returns {boolean}
     */
    shouldCompact(messages, maxTokens) {
        const ceiling = maxTokens || this.tokenEstimator.getMaxTokens();
        return this.tokenEstimator.isOverBudget(messages, this.threshold);
    }

    /**
     * Compact messages to fit within the token budget.
     *
     * @param {Array} messages
     * @param {number} [maxTokens] - override ceiling
     * @returns {{ compactedMessages: Array, strategy: string, report: object }}
     */
    compact(messages, maxTokens) {
        if (!messages || messages.length === 0) {
            return { compactedMessages: [], strategy: 'none', report: {} };
        }

        const ceiling = maxTokens || this.tokenEstimator.getMaxTokens();

        // Detect task context
        const hasTaskContext = this.taskAwareCompaction && this._hasTaskContext(messages);

        let result;
        if (hasTaskContext) {
            result = this._taskAwareStrategy(messages, ceiling);
        } else {
            result = this._conversationalStrategy(messages, ceiling);
        }

        // Verify we're within budget; if not, use fallback
        if (this.tokenEstimator.isOverBudget(result.compactedMessages, 0.95)) {
            result = this._fallbackStrategy(messages);
        }

        return result;
    }

    /**
     * Conversational strategy: Use ContextBudget for intelligent selection
     * and preserve continuity anchors as a summary block.
     */
    _conversationalStrategy(messages, maxTokens) {
        // 1. Run context budget optimization
        const { optimizedMessages, tokenCount, budgetReport } =
            this.contextBudget.optimize(messages, maxTokens);

        // 2. Extract continuity anchors as a summary
        const anchors = this.continuityAnchors.detect(messages);
        const anchorBlock = this.continuityAnchors.format(anchors);

        // 3. Inject anchor summary as a system message if there are anchors
        const compacted = [...optimizedMessages];
        if (anchorBlock) {
            // Find system message and append, or create one
            const systemIdx = compacted.findIndex(m => m.role === 'system');
            if (systemIdx >= 0) {
                const systemMsg = compacted[systemIdx];
                compacted[systemIdx] = {
                    ...systemMsg,
                    content: this._extractText(systemMsg) + '\n\n' + anchorBlock
                };
            } else {
                compacted.unshift({
                    role: 'system',
                    content: anchorBlock
                });
            }
        }

        return {
            compactedMessages: compacted,
            strategy: 'conversational',
            report: {
                ...budgetReport,
                anchorsPreserved: anchors.length,
                originalMessages: messages.length,
                compactedMessages: compacted.length
            }
        };
    }

    /**
     * Task-aware strategy: Prioritize task-relevant content.
     *
     * Priority order:
     * 1. System message (always kept)
     * 2. Original user request (first user message — always kept)
     * 3. Task state / plan messages (if present)
     * 4. Tool results (last 15)
     * 5. Agent reasoning (last 5)
     */
    _taskAwareStrategy(messages, maxTokens) {
        const budget = Math.floor(maxTokens * this.contextBudget.budgetRatio);
        const compacted = [];
        let tokensUsed = 0;

        // 1. System message
        const systemMsg = messages.find(m => m.role === 'system');
        if (systemMsg) {
            compacted.push(systemMsg);
            tokensUsed += this.tokenEstimator.estimate(this._extractText(systemMsg));
        }

        // 2. First user message (the original request)
        const firstUser = messages.find(m => m.role === 'user');
        if (firstUser) {
            compacted.push(firstUser);
            tokensUsed += this.tokenEstimator.estimate(this._extractText(firstUser));
        }

        // 3. Messages with tool results (last 15)
        const toolMessages = messages.filter(m =>
            m.role === 'tool' || m.role === 'function' ||
            (m.content && typeof m.content === 'string' && m.content.includes('[tool_result]'))
        );
        const recentTools = toolMessages.slice(-15);
        for (const msg of recentTools) {
            const text = this._extractText(msg);
            const tokens = this.tokenEstimator.estimate(text);
            if (tokensUsed + tokens < budget * 0.7) {
                compacted.push(msg);
                tokensUsed += tokens;
            }
        }

        // 4. Recent agent reasoning (last 5 assistant messages)
        const assistantMessages = messages.filter(m => m.role === 'assistant');
        const recentAssistant = assistantMessages.slice(-5);
        for (const msg of recentAssistant) {
            if (compacted.includes(msg)) continue;
            const text = this._extractText(msg);
            const truncated = text.length > 1500 ? text.substring(0, 1500) + ' [...]' : text;
            const tokens = this.tokenEstimator.estimate(truncated);
            if (tokensUsed + tokens < budget * 0.9) {
                compacted.push({ ...msg, content: truncated });
                tokensUsed += tokens;
            }
        }

        // 5. Recent user messages (last 5)
        const userMessages = messages.filter(m => m.role === 'user');
        const recentUser = userMessages.slice(-5);
        for (const msg of recentUser) {
            if (compacted.includes(msg)) continue;
            const tokens = this.tokenEstimator.estimate(this._extractText(msg));
            if (tokensUsed + tokens < budget) {
                compacted.push(msg);
                tokensUsed += tokens;
            }
        }

        // Sort by original position
        const indexMap = new Map(messages.map((m, i) => [m, i]));
        compacted.sort((a, b) => (indexMap.get(a) || 0) - (indexMap.get(b) || 0));

        return {
            compactedMessages: compacted,
            strategy: 'task-aware',
            report: {
                budget,
                tokensUsed,
                originalMessages: messages.length,
                compactedMessages: compacted.length,
                toolMessagesKept: recentTools.length,
                assistantMessagesKept: recentAssistant.length
            }
        };
    }

    /**
     * Fallback: Keep system message + last N messages.
     */
    _fallbackStrategy(messages) {
        const systemMsg = messages.find(m => m.role === 'system');
        const recent = messages.slice(-this.fallbackMessages);
        const compacted = systemMsg ? [systemMsg, ...recent] : recent;

        return {
            compactedMessages: compacted,
            strategy: 'fallback',
            report: {
                originalMessages: messages.length,
                compactedMessages: compacted.length,
                keptLast: this.fallbackMessages
            }
        };
    }

    // ---------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------

    /**
     * Detect if the conversation contains task context.
     * Looks for tool messages, function calls, or task-related content.
     */
    _hasTaskContext(messages) {
        return messages.some(m =>
            m.role === 'tool' ||
            m.role === 'function' ||
            (m.tool_calls && m.tool_calls.length > 0) ||
            (m.function_call)
        );
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

module.exports = Compactor;
