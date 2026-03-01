# HEARTBEAT

Version: 1.1.0

## Heartbeat Checklist
- Read `~/.openclaw/workspace/gemini-rate-status.json` every heartbeat. If status is `yellow`, include quota usage in the summary. If status is `red`, alert Adam immediately and switch new routing to fallback models per the Model Plan.

## Changelog
- 1.1.0: Added Gemini rate-status heartbeat check and escalation behavior.
