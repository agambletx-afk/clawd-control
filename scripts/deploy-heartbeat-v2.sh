#!/usr/bin/env bash
set -euo pipefail

install -m 755 -o root -g root scripts/heartbeat-lib.sh /usr/local/bin/heartbeat-lib.sh
install -m 755 -o root -g root scripts/session-ops.sh /usr/local/bin/session-ops.sh
install -m 755 -o root -g root scripts/system/security-hook-alert.sh /usr/local/bin/security-hook-alert.sh
install -m 755 -o root -g root scripts/claude-token-refresh.sh /usr/local/bin/claude-token-refresh.sh
install -m 755 -o root -g root scripts/check-cron-health.sh /usr/local/bin/check-cron-health.sh
install -m 644 -o root -g root etc/jarvis/watcher.json /etc/jarvis/watcher.json

find /tmp -maxdepth 1 -type f -name '*-heartbeat.json' -user root -delete
