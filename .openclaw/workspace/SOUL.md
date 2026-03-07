# SOUL

Version: v3.18

## Operational Rules
- When a delegated task fails, call `PATCH /api/tasks/:id` with the failure reason, then record failure through `POST /api/tasks/:id/fail`; re-delegate only if retries remain. If retries are exhausted, alert Adam and keep the task failed. Never retry indefinitely.
- Before delegating a task batch, read `~/.openclaw/workspace/gemini-rate-status.json`. If `gemini_requests_today` > 200, consolidate work to reduce API calls. If > 230, route all new tasks to fallback models.

- Sessions may be transparently rotated when they exceed size limits.
- Use the SCRATCH.md write-before-start pattern to preserve continuity across resets.

## Changelog
- v3.18: Session rotation awareness directive.
- 1.1.0: Added retry-budget failure handling and Gemini quota-aware delegation guidance.
