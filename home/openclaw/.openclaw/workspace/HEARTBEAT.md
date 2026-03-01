# HEARTBEAT.md

## Version
1.1.0

## Heartbeat Cycle
At the start of every heartbeat cycle, write a process heartbeat file by running: `exec: echo '{"agent":"orchestrator","timestamp":"'$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)'","pid":'$$',"status":"alive","session_id":"unknown","tasks_completed":0}' > /tmp/jarvis/heartbeats/orchestrator.json`.

## Changelog
- 1.1.0: Added orchestrator process heartbeat write instruction for `/tmp/jarvis/heartbeats/orchestrator.json`.
- 1.0.0: Initial heartbeat cycle guidance.
