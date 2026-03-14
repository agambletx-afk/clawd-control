#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="/home/openclaw/clawd-control"
install -o root -g root -m 755 "$REPO_ROOT/scripts/check-cron-health.sh" /usr/local/bin/check-cron-health.sh
install -o root -g openclaw -m 640 "$REPO_ROOT/etc/jarvis/watcher.json" /etc/jarvis/watcher.json
install -o root -g root -m 644 "$REPO_ROOT/etc/cron.d/openclaw-watcher" /etc/cron.d/openclaw-watcher
echo "WATCHER deployed. First run in <=5 minutes."
