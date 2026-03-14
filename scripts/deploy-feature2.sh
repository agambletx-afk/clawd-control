#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="/home/openclaw/clawd-control"

install -d -o root -g openclaw -m 750 /etc/jarvis
install -o root -g openclaw -m 640 "$REPO_ROOT/etc/jarvis/session-ops.conf" /etc/jarvis/session-ops.conf
install -o root -g root -m 755 "$REPO_ROOT/scripts/session-ops.sh" /usr/local/bin/session-ops.sh
install -o root -g root -m 644 "$REPO_ROOT/etc/systemd/system/session-ops.service" /etc/systemd/system/session-ops.service
install -o root -g root -m 644 "$REPO_ROOT/etc/systemd/system/session-ops.timer" /etc/systemd/system/session-ops.timer

for script in /usr/local/bin/openclaw-orphan-reaper.sh /usr/local/bin/session-cleanup.sh /usr/local/bin/session-watchdog.sh; do
  if [[ -f "$script" ]]; then
    mv "$script" "$script.archived"
  fi
done

rm -f /etc/cron.d/openclaw-orphan-reaper /etc/cron.d/session-cleanup

systemctl stop session-watchdog.timer 2>/dev/null || true
systemctl disable session-watchdog.timer 2>/dev/null || true
systemctl stop session-watchdog.service 2>/dev/null || true
systemctl disable session-watchdog.service 2>/dev/null || true
rm -f /etc/systemd/system/session-watchdog.timer /etc/systemd/system/session-watchdog.service

systemctl daemon-reload
systemctl enable --now session-ops.timer
