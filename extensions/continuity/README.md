# openclaw-plugin-continuity

**Infinite Thread** — persistent, intelligent memory for OpenClaw agents.

Gives your agent the ability to remember conversations across sessions. When a user asks "do you remember that recipe I told you about?", the agent recalls the actual exchange and responds with specific details from the original conversation.

## What it does

- **Cross-session memory**: Archives every conversation, indexes it with semantic embeddings, and retrieves relevant exchanges when the user references past discussions.
- **Context budgeting**: Manages token allocation across priority tiers so important context (recent turns, identity anchors) survives compaction.
- **Continuity anchors**: Detects and preserves identity-defining moments, contradictions, and unresolved tensions across the conversation.
- **Topic tracking**: Monitors which subjects the user keeps returning to, flags fixated topics, and tracks freshness decay.
- **Temporal re-ranking**: Blends semantic similarity with recency so newer exchanges about the same topic outrank older ones — corrections and retractions naturally supersede the statements they correct.
- **AGENTS.md integration**: Memory-recall instructions live in the workspace AGENTS.md (where operating instructions belong), not MEMORY.md (which is the agent's curated memory space).

## Why it works this way

### The proprioceptive problem

Most LLMs, when given retrieved context, treat it as external data rather than their own experience. An agent will see a recalled conversation in its context and still say "I don't have information about that." This is because the model doesn't recognize retrieved data as its own memory — it's an identity integration problem, not a retrieval problem.

This plugin solves it at three levels:

1. **Operating instructions** (AGENTS.md `### Recalled Memories`): The workspace AGENTS.md teaches the agent that recalled exchanges are its own memories — "you were there." AGENTS.md is the agent's operating manual, read every session as project context with system-prompt authority. This is the proper place for behavioral instructions (not MEMORY.md, which is the agent's curated memory space per OpenClaw's design).

2. **Ownership language** (prependContext injection): When recalled exchanges are injected, they use first-person framing — "They told you:" and "You said:" — not third-person disclosure language like "The archive contains:" or "Retrieved context shows:". This is the difference between experiencing a memory and reading a report. Results are sorted chronologically (oldest→newest) so corrections naturally appear after the statements they correct.

3. **Inline behavioral cues** (tool result enrichment): When the model calls `memory_search` and gets sparse results, the plugin enriches the response with archive data and adds "Speak from this memory naturally" as a direct cue next to the data.

### Why `prependContext` and not `systemPrompt`

OpenClaw's `before_agent_start` hook type declares both `systemPrompt` and `prependContext` as return values. However, **the runtime only reads `prependContext`** — `systemPrompt` is never applied. This is a known SDK limitation. All context injection must go through `prependContext`, which gets baked into the user message by OpenClaw before sending to the model.

For higher-authority instructions (identity-level guidance like how to handle recalled memories), the plugin relies on AGENTS.md — the agent's operating manual, which is read every session as project context with system-prompt authority.

### Why temporal re-ranking

Conversation archives accumulate both original statements and later corrections or retractions. A user might share a recipe in one session, then ask to delete it in the next. Pure semantic search returns both exchanges with similar relevance scores, and the model sees contradictory data.

The searcher blends semantic distance with a recency boost:

```
compositeScore = semanticDistance - recencyBoost
recencyBoost = exp(-ageDays / halfLife) * weight
```

With defaults of `halfLife = 14 days` and `weight = 0.15`, an exchange from today gets a ~0.15 boost while one from 2 weeks ago gets ~0.075. This means when two exchanges are semantically similar, the newer one ranks higher — corrections naturally outrank the statements they correct.

The search fetches 2x the requested limit for re-ranking headroom, then returns the top results sorted chronologically for display so the model sees the natural temporal progression.

### Why `tool_result_persist` enrichment

OpenClaw ships with a built-in `memory_search` tool (via the memory-core plugin). When users ask recall questions, the model often calls this tool. For new conversations where the built-in memory hasn't captured much, it returns sparse or empty results — and the model trusts the tool result over injected context.

The plugin intercepts `memory_search` results via the `tool_result_persist` hook and enriches them with archive data. This way the model sees substantive recalled exchanges in the tool response it already trusts, instead of having to reconcile conflicting signals between empty tool results and rich injected context.

### Why the noise filter exists

Conversation archives accumulate meta-exchanges: users asking "do you remember X?", the agent responding "I don't have information about X." These meta-conversations about memory rank higher in semantic search than the actual substantive exchanges they reference, because the query "do you remember my recipe?" is semantically closer to "do you recall my recipe?" (another meta-question) than to "I've been working on a sourdough recipe with 72-hour cold ferment" (the actual content).

The noise filter strips:
- **Agent-side denials**: "I don't have any information", "it looks like I don't", etc.
- **User-side meta-questions**: "do you remember", "can you recall", "did I tell you", etc.
- **Session boilerplate**: greeting prompts, session reset messages

This ensures that when the search returns 30 results and the filter reduces them to 5-8, those survivors are substantive exchanges with real content the agent can reference.

### Why the search limit is 30

Substantive exchanges (the actual recipe, the real conversation) rank lower in semantic search than meta-questions about those exchanges. A limit of 15 often missed the actual content. With 30 results, the real exchanges make it into the result set, and the noise filter removes the meta-noise, leaving the model with the exchanges that matter.

## Installation

### Prerequisites

- OpenClaw installed and running (gateway active)
- Node.js >= 18

### Install dependencies

```bash
cd /path/to/openclaw-plugin-continuity
npm install
```

This installs:
- `better-sqlite3` — synchronous SQLite driver
- `sqlite-vec` — vector search extension for SQLite
- `@chroma-core/default-embed` — embedding model (Xenova/all-MiniLM-L6-v2, 384 dimensions)

All dependencies are self-contained in the plugin's `node_modules`. No global installs required.

### Configure OpenClaw

Add the plugin to your `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "load": {
      "paths": [
        "/path/to/openclaw-plugin-continuity"
      ]
    },
    "entries": {
      "continuity": {
        "enabled": true,
        "config": {}
      }
    }
  }
}
```

### Restart the gateway

```bash
openclaw gateway restart
```

Verify the plugin loaded:

```bash
openclaw logs | grep "Continuity plugin registered"
```

You should see:
```
Continuity plugin registered — context budgeting, topic tracking, archive + semantic search active
```

And the indexer initialization:
```
[Indexer] sqlite-vec loaded: v0.1.7-alpha.2
[Indexer] Database tables ready
[Indexer] Embedding model ready (384 dimensions)
[Indexer] Initialized — SQLite-vec ready
```

## How it works

### Data flow

```
User message arrives
        │
        ▼
before_agent_start (priority 10)
        │
        ├── Build [CONTINUITY CONTEXT] block
        │     ├── Session info (exchange count, duration)
        │     ├── Active topics + fixation status
        │     └── Continuity anchors (identity, tension)
        │
        ├── Detect continuity intent?
        │     └── Search archive (30 results → temporal re-rank → noise filter → top 5)
        │           └── Sort chronologically → Inject "You remember..." block
        │
        └── Return { prependContext } → baked into user message

Model processes message
        │
        ├── May call memory_search tool
        │     ├── before_tool_call: search archive, cache results
        │     └── tool_result_persist: enrich sparse results with cache
        │
        └── Generates response

agent_end
        │
        ├── Update topic tracker
        ├── Refresh continuity anchors
        ├── Archive exchange (deduplicated)
        └── Index today's archive (incremental)

maintenance service (every 5 min)
        │
        ├── Batch-index un-indexed archive dates
        ├── Prune archives older than 90 days
        └── Report health metrics
```

### Continuity intent detection

The plugin scans user messages for recall-related phrases before searching the archive. Only messages containing these indicators trigger archive retrieval:

```
remember, recall, forgot, forget, don't remember, can't remember,
do you recall, you said, you told, i told you, told me,
we were talking, we talked, we discussed, earlier, before,
last time, previously, mentioned, brought up, came up,
lost thread, what did we, what was that, back to, going back, picking up
```

These are configurable via `continuityIndicators` in the config.

### Storage

| Component | Location | Format |
|-----------|----------|--------|
| Daily archives | `data/archive/YYYY-MM-DD.json` | JSON with timestamped messages |
| Semantic index | `data/continuity.db` | SQLite + sqlite-vec (384-dim embeddings) |
| Index log | `data/index-log.json` | Tracks which dates have been indexed |
| Agent instructions | `~/.openclaw/workspace/AGENTS.md` | `### Recalled Memories` section (user-managed) |

### AGENTS.md integration

The plugin expects a `### Recalled Memories (Continuity Plugin)` section in the workspace AGENTS.md. This teaches the agent how to treat recalled exchanges as its own memories. The plugin does **not** auto-write this section — it's added once during setup and the agent (or user) can edit it freely.

The plugin does **not** write to MEMORY.md. That file is the agent's curated memory space per OpenClaw's design — the agent reads, edits, and updates it freely as its own long-term memory.

## Configuration

All configuration is optional. The plugin ships with sensible defaults in `config.default.json`.

```json
{
  "contextBudget": {
    "contextBudgetRatio": 0.65,
    "recentTurnsAlwaysFull": 5,
    "recentTurnCharLimit": 3000,
    "midTurnCharLimit": 1500,
    "olderTurnCharLimit": 500
  },

  "anchors": {
    "enabled": true,
    "maxAge": 7200000,
    "maxCount": 15,
    "keywords": {
      "identity": ["who am i", "what am i", "my name", "i am"],
      "contradiction": ["but", "however", "contradict", "conflict"],
      "tension": ["problem", "issue", "challenge", "confused", "stuck"]
    }
  },

  "topicTracking": {
    "enabled": true,
    "windowSize": 6,
    "fixationThreshold": 3,
    "decayFactor": 0.5,
    "minWordLength": 5
  },

  "compaction": {
    "threshold": 0.80,
    "fallbackMessages": 20,
    "taskAwareCompaction": true
  },

  "archive": {
    "archiveDir": "archive",
    "retentionDays": 90,
    "batchIndexDelay": 100
  },

  "embedding": {
    "model": "Xenova/all-MiniLM-L6-v2",
    "dimensions": 384,
    "dbFile": "continuity.db"
  },

  "search": {
    "recencyHalfLifeDays": 14,
    "recencyWeight": 0.15
  },

  "session": {
    "interruptedGap": 7200000,
    "newSessionGap": 21600000
  }
}
```

Override any values in your OpenClaw config under `plugins.entries.continuity.config`:

```json
{
  "plugins": {
    "entries": {
      "continuity": {
        "config": {
          "topicTracking": {
            "fixationThreshold": 5
          },
          "archive": {
            "retentionDays": 180
          }
        }
      }
    }
  }
}
```

## Architecture

### Modules

```
index.js                 Main plugin — hook registration, orchestration
├── lib/
│   ├── token-estimator.js    Model-agnostic token counting
│   ├── context-budget.js     Priority-tier budget allocation
│   ├── continuity-anchors.js Identity/contradiction/tension detection
│   ├── topic-tracker.js      Topic freshness + fixation tracking
│   └── compactor.js          Threshold-triggered context compression
├── storage/
│   ├── archiver.js           Daily JSON conversation storage + dedup
│   ├── indexer.js            SQLite-vec embedding + exchange pairing
│   └── searcher.js           Semantic retrieval + temporal re-ranking
└── services/
    └── maintenance.js        Background batch indexing + pruning
```

### Hooks registered

| Hook | Priority | Purpose |
|------|----------|---------|
| `before_agent_start` | 10 | Inject continuity context + archive retrieval |
| `before_tool_call` | — | Cache archive search when `memory_search` fires |
| `after_tool_call` | — | Lightweight mid-turn topic tracking |
| `tool_result_persist` | — | Enrich sparse `memory_search` with archive data |
| `agent_end` | — | Archive, index, update topics/anchors |
| `before_compaction` | — | Inject continuity context before compression |

### Gateway methods

| Method | Purpose |
|--------|---------|
| `continuity.getState` | Archive stats, topics, anchors, exchange count |
| `continuity.getConfig` | Full merged config |
| `continuity.search` | Execute archive search (params: text/query, limit) |
| `continuity.getArchiveStats` | Archive statistics |
| `continuity.getTopics` | All topics + fixated topics |

### Background service

The `continuity-maintenance` service runs every 5 minutes:
- Batch-indexes any un-indexed archive dates
- Prunes archives older than the retention period
- Reports health metrics to the gateway log

## Interaction with OpenClaw's built-in memory

This plugin is designed to **complement**, not replace, OpenClaw's built-in memory system (memory-core or memory-lancedb).

- OpenClaw's memory plugins handle short-term recall within a session and `memory_search` / `memory_save` tools
- This plugin handles **cross-session** recall via conversation archiving and semantic search
- When OpenClaw's `memory_search` returns sparse results, this plugin enriches them via `tool_result_persist`
- Memory-recall instructions live in AGENTS.md (the agent's operating manual), which OpenClaw reads every session as project context
- MEMORY.md is left entirely to the agent for curation — the plugin never writes to it
- Both systems coexist — the plugin uses `prependContext` (priority 10, runs after other plugins) to avoid conflicts

### Known SDK limitations

- **`systemPrompt` return is not applied**: The `before_agent_start` hook type declares `systemPrompt` as a return field, but OpenClaw's runtime does not read it. Use `prependContext` for context injection and AGENTS.md for identity-level instructions.
- **`tool_result_persist` is synchronous**: This hook cannot be async. Any data needed must be pre-cached (via `before_tool_call` which IS async).
- **Plugin `console.log` goes to gateway log**: Use `console.error` if you need output in the error log file. `api.logger.warn` output is not visible in either log file.

## Troubleshooting

### Plugin not loading

```bash
openclaw plugins list
openclaw logs | grep "Continuity"
```

Check that the path in `plugins.load.paths` is correct and `plugins.entries.continuity.enabled` is not `false`.

### No archive data

```bash
# Check archive files
ls -la /path/to/plugin/data/archive/

# Check indexed exchange count
openclaw logs | grep "Maintenance"
```

Archives are written at the end of each conversation turn (`agent_end` hook). If the agent crashes or the gateway restarts mid-conversation, the current turn may not be archived.

### Retrieval not firing

The plugin searches the archive on every user turn (minimum 10 characters). Intent detection controls injection verbosity, not search gating. If recalled data exists but isn't being injected, check that the `compositeScore` is below the relevance threshold (default 1.0) or that the user's message contains one of the configured `continuityIndicators`.

To test retrieval directly:

```bash
# Via gateway method
openclaw rpc continuity.search '{"text": "sourdough recipe", "limit": 10}'
```

### Agent says "I don't have information" despite recalled data being present

This is the proprioceptive integration issue. Check:

1. AGENTS.md contains `### Recalled Memories (Continuity Plugin)` section
2. The recalled exchanges appear in the prependContext (visible in the chat UI's injected context)
3. The model is reading AGENTS.md at session start (it should — OpenClaw injects it as project context)

If the model still denies having information, consider upgrading to a more capable model that better follows system-prompt instructions.

## Known Issues

- **Context blocks visible in chat UI**: The `[CONTINUITY CONTEXT]` block injected via `prependContext` is displayed as part of the user message in OpenClaw's web dashboard. This is cosmetic — the model processes it correctly as context, but the dashboard doesn't yet collapse or hide plugin-injected content. This is an OpenClaw dashboard limitation, not a plugin bug.

## Part of the Meta-Cognitive Suite

This plugin is one of six that form a complete meta-cognitive loop for OpenClaw agents:

1. **[stability](https://github.com/CoderofTheWest/openclaw-plugin-stability)** — Entropy monitoring, confabulation detection, principle alignment
2. **[continuity](https://github.com/CoderofTheWest/openclaw-plugin-continuity)** — Cross-session memory, context budgeting, conversation archiving *(this plugin)*
3. **[metabolism](https://github.com/CoderofTheWest/openclaw-plugin-metabolism)** — Conversation processing, implication extraction, knowledge gaps
4. **[nightshift](https://github.com/CoderofTheWest/openclaw-plugin-nightshift)** — Off-hours scheduling for heavy processing
5. **[contemplation](https://github.com/CoderofTheWest/openclaw-plugin-contemplation)** — Multi-pass inquiry from knowledge gaps
6. **[crystallization](https://github.com/CoderofTheWest/openclaw-plugin-crystallization)** — Growth vectors become permanent character traits

Load order: stability → continuity → metabolism → nightshift → contemplation → crystallization

See [openclaw-metacognitive-suite](https://github.com/CoderofTheWest/openclaw-metacognitive-suite) for the full picture.

## License

MIT
