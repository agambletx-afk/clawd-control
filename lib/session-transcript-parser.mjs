function extractTextFromContent(content) {
  if (!Array.isArray(content)) return '';
  return content
    .filter((item) => item && (item.type === 'text' || item.type === 'thinking'))
    .map((item) => String(item.text || item.thinking || ''))
    .join('\n')
    .trim();
}

function shapeEntry(entry, state) {
  const base = {
    id: entry.id || `entry_${state.syntheticId++}`,
    parentId: entry.parentId || null,
    timestamp: entry.timestamp || null,
  };

  if (entry.type === 'session') {
    return [{ ...base, type: 'session_start', version: entry.version || null, cwd: entry.cwd || null }];
  }

  if (entry.type === 'model_change') {
    return [{ ...base, type: 'system_internal', provider: entry.provider || null, modelId: entry.modelId || null }];
  }

  if (entry.type === 'thinking_level_change') {
    return [{ ...base, type: 'system_internal', thinkingLevel: entry.thinkingLevel || null }];
  }

  if (entry.type === 'custom') {
    return [{ ...base, type: 'system_internal', customType: entry.customType || null, data: entry.data || null }];
  }

  if (entry.type === 'compaction') {
    return [{ ...base, type: 'compaction' }];
  }

  if (entry.type === 'branch_summary') {
    state.branchDetected = true;
    return [{ ...base, type: 'branch_summary', summary: entry.summary || '' }];
  }

  if (entry.type === 'message' && entry.message) {
    const msg = entry.message;
    if (msg.role === 'user') {
      return [{ ...base, type: 'user_message', content: extractTextFromContent(msg.content) }];
    }

    if (msg.role === 'assistant') {
      const contentItems = Array.isArray(msg.content) ? msg.content : [];
      const toolCalls = contentItems.filter((item) => item && item.type === 'toolCall');
      const textContent = extractTextFromContent(contentItems);
      const out = [];

      if (textContent) {
        out.push({
          ...base,
          type: 'assistant_message',
          content: textContent,
          usage: msg.usage || null,
          model: msg.model || null,
          stopReason: msg.stopReason || null,
        });
      }

      for (const tc of toolCalls) {
        out.push({
          ...base,
          id: `${base.id}:tool:${tc.id || state.syntheticId++}`,
          type: 'tool_call',
          parentId: base.id,
          toolName: tc.name || 'unknown',
          toolArguments: tc.arguments || null,
          toolCallId: tc.id || null,
          content: textContent || '',
        });
      }

      if (out.length === 0) {
        out.push({ ...base, type: 'assistant_message', content: '', usage: msg.usage || null, model: msg.model || null, stopReason: msg.stopReason || null });
      }
      return out;
    }

    if (msg.role === 'toolResult') {
      return [{
        ...base,
        type: 'tool_result',
        toolCallId: msg.toolCallId || null,
        toolName: msg.toolName || null,
        isError: Boolean(msg.isError),
        content: extractTextFromContent(msg.content),
      }];
    }
  }

  return [{ ...base, type: 'unknown', rawType: entry.type || 'unknown' }];
}

export function parseTranscriptContent(content, { active = false } = {}) {
  const lines = String(content || '').split('\n');
  let lastNonEmptyIndex = -1;
  for (let i = 0; i < lines.length; i += 1) {
    if (lines[i] && lines[i].trim()) lastNonEmptyIndex = i;
  }
  const state = { syntheticId: 1, branchDetected: false };
  const entries = [];
  const errors = [];

  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i];
    if (!raw || !raw.trim()) continue;

    try {
      const parsed = JSON.parse(raw);
      entries.push(...shapeEntry(parsed, state));
    } catch {
      const isFinalLine = i === lastNonEmptyIndex;
      if (isFinalLine) {
        continue;
      }
      errors.push({ index: i, raw });
      entries.push({ id: `corruption_${i}`, parentId: null, type: 'corruption', timestamp: null, message: 'Entry could not be read' });
    }
  }

  return {
    entries,
    corruptionCount: errors.length,
    branchDetected: state.branchDetected,
    transcriptStatus: active ? 'live' : 'available',
  };
}
