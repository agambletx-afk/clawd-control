# Clawd Control — Shared Contracts

**Version:** 1.0
**Date:** 2026-03-24
**Status:** Authoritative. All dashboard features must reference these contracts.

---

## Contract A: Canonical Agent Identity

### Problem

Agent IDs are inconsistent across stores. Sessions use gateway-scoped IDs. Tasks use free-text. Usage groups by parsed strings. facts.db has no agent column.

### Specification

A canonical agent ID is a lowercase string slug. Format: `[a-z0-9-]+`, max 32 characters.

| Agent | Canonical ID | Display Name |
|-------|-------------|--------------|
| Jarvis | `jarvis` | Jarvis |
| Codex | `codex` | Codex |
| System (crons, timers, infrastructure) | `system` | System |

Post-OCI agents will follow the same pattern: `sentinel`, `triage`, `analyst`, etc. One ID per agent, used everywhere.

### Adoption

Existing stores are not modified. Normalization happens at query time:

- **Gateway sessions:** The gateway `agentId` field is authoritative. Map to canonical ID via a lookup in the summarizer.
- **Tasks:** The `source` or `created_by` field is matched against canonical IDs. Free-text values are normalized at read time (e.g., `"Jarvis"` → `jarvis`, `"codex-cli"` → `codex`).
- **Usage/tokens:** Agent grouping already parses from session metadata. Summarizer uses canonical IDs when aggregating.
- **facts.db:** No agent column exists. Facts are system-scoped. Per-agent memory isolation is a separate brief (session-scoped tagging).

### Rules

- Every API response, summarizer field, and UI label that references an agent uses the canonical ID internally and the display name in UI.
- `system` is the default for events with no agent attribution (cron runs, health checks, infrastructure events).
- Unknown or unmatchable agent references normalize to `unknown` and log a warning.

---

## Contract B: Severity Specification

### Problem

No shared definition of what "green," "amber," and "red" mean across domains. Each tab defines its own thresholds. The summarizer needs a single severity model.

### Two Signal Classes

Every domain badge in the Overview has two independent layers:

1. **Health** — Is the control plane functioning? Can the subsystem do its job?
2. **Attention** — Is a healthy control plane reporting a condition the operator should know about?

These are visually distinct. A health dot (solid, left-positioned) and an attention pip (smaller, secondary, right-positioned). "Agent overspending" (attention from a healthy cost system) must never look like "gateway down" (health failure).

### Health Signals

Health answers: "Is this subsystem's control plane operational?"

| Domain | Green | Amber | Red |
|--------|-------|-------|-----|
| Gateway | API responds <1s | API responds >5s | Unresponsive or down |
| CORTEX | Models routable | Config errors | No models available |
| Sessions | Management responding | Watchdog missed cycle | Watchdog down |
| Memory | facts.db accessible, extraction registered | Size warning | Inaccessible or corrupt |
| Security | Checks executing, critical checks pass | Non-critical failures | Critical check failing |
| Crons | Scheduler on time | Missed 1 cycle | Scheduler down |
| Tasks | API responding | N/A | DB or API error |
| Cost | Usage API up, quota-state fresh | >1h stale | API unresponsive |

### Attention Signals

Attention answers: "Is a healthy subsystem reporting something that needs the operator?"

| Signal | Domain | Trigger | Amber | Red | Clear |
|--------|--------|---------|-------|-----|-------|
| Session Runaway | Sessions | Context/time exceeded | >200KB or >45min | >256KB or >60min | Archived or closed |
| CORTEX Fallback Chain | CORTEX | Consecutive fallbacks | 3 in 1h | 5+ or pool exhausted | Primary resumes |
| Cron Failure Streak | Crons | Same job fails | 3 consecutive | 5+ or critical cron | Job succeeds |
| Gateway Unresponsive | Gateway | Process alive, API dead | N/A | Binary | API responds |
| Token Concentration | Cost | Single agent >70% | >70% | >90% | Below threshold |
| Stale Task | Tasks | In Progress >48h | >48h | >96h | Transitions |
| Memory Pressure | Memory | Size or extraction stale | >24h stale | >48h or size cap | Extraction completes |
| Hook Bypass Attempt | Security | Blocked access | 1 in last hour | 3+ in 1h | None in 1h |

### Rules

- Health is evaluated first. If health is red, attention is suppressed (a broken control plane can't reliably report conditions).
- Attention severity is always the worst active signal for that domain. Multiple amber signals don't escalate to red.
- Each signal has an explicit clear condition. Signals auto-clear when the clear condition is met. No manual acknowledgment required.
- "Cron Failure Streak" is attention, not health. The scheduler firing on time = healthy control plane. A job failing = condition reported by a healthy subsystem.

---

## Contract C: Event Normalization

### Problem

Activity feeds, action queues, and audit logs pull from different stores with different schemas. No shared event format exists.

### Specification

Normalized event shape (query-time transformation, not stored):

```json
{
  "timestamp": "ISO 8601, millisecond precision",
  "source": "tasks|watcher|cron|security|gateway|cortex|memory",
  "type": "state_change|completion|failure|alert|info",
  "agent": "canonical ID or 'system'",
  "title": "One-liner, max 80 chars",
  "detail": "Optional context string",
  "link": "Optional deep-link path (e.g., '/tasks.html#task-42')"
}
```

### Source Mapping

| Store | timestamp field | source | type mapping | agent mapping |
|-------|----------------|--------|-------------|---------------|
| tasks.task_history | `created_at` | `tasks` | `status_from`/`status_to` → `state_change`; done → `completion`; failed → `failure` | `transitioned_by` → canonical ID |
| watcher.db alerts | `detected_at` | `watcher` | `failure`; recovery → `info` | `system` |
| cron logs | `timestamp` | `cron` | exit 0 → `completion`; exit >0 → `failure` | `system` |
| security health | `checked_at` | `security` | status change → `state_change`; critical fail → `alert` | `system` |
| gateway events (SSE) | `timestamp` | `gateway` | connect → `info`; disconnect → `alert` | gateway `agentId` → canonical ID |
| cortex outcome.db | `timestamp` | `cortex` | fallback → `alert`; normal → `info` | session → canonical ID |
| memory facts.db | `created_at` | `memory` | new fact → `info`; extraction failure → `failure` | `system` |

### Rules

- Normalization happens at query time. No new tables. No ETL jobs. Each API endpoint that serves events applies the transformation.
- `timestamp` is always UTC ISO 8601 with millisecond precision. Source timestamps that lack timezone are treated as UTC.
- `title` is max 80 characters. Truncate with ellipsis if the source data exceeds this.
- `detail` is optional. Omit rather than populate with empty strings.
- `link` is a relative path. No absolute URLs. Omit if no meaningful deep-link exists.
- Events older than 7 days are excluded from feeds by default. Callers can override with a `days` parameter.

---

## Document Hierarchy

These contracts are referenced by all dashboard feature briefs. If a feature brief contradicts a contract, the contract wins unless the brief explicitly proposes an amendment with reasoning.

| Document | Authority |
|----------|-----------|
| Dashboard Design Principles v1.1 | Highest (constitutional) |
| Design Guide v1.0 + v1.1 | Implementation specs |
| This document (Shared Contracts) | Data model and severity specs |
| Feature Briefs | What to build (must comply with above) |
| Codex Briefs | How to build it |
