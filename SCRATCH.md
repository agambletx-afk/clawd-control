COMPLETED: APIs tab for Clawd Control. Service health monitoring with system cron, API key rotation tracking, capability tags. 9 services configured. Feature branch: feature/apis-tab.
COMPLETED: Tasks tab card UI refined for compactness and button removal. Feature branch: feature/tasks-tab.
COMPLETED: Added Cache-Control header for HTML responses in server.mjs. Feature branch: feature/tasks-tab.
COMPLETED: Fixed task detail panel footer overflow in tasks.html. Feature branch: feature/tasks-tab.
COMPLETED: Fixed task detail panel height on mobile in tasks.html (100vh to 100dvh). Feature branch: feature/tasks-tab.
COMPLETED: Operations tab for Clawd Control. Service controls, cron triggers, backup management with retention, activity log. Feature branch: feature/ops-tab. PR ready for review.
DEPLOY NOTE: `scripts/check-cli-usage.sh` now detects Claude Code auth via `$HOME/.claude/.credentials.json`. **Redeploy required:** update the deployed copy at `/usr/local/bin/check-cli-usage.sh` on the VPS to apply this fix.
