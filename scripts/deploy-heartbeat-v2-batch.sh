#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[1/7] Installing wrapper scripts to /usr/local/bin"
install -m 755 -o root -g root scripts/wrappers/security-health-wrapper.sh /usr/local/bin/security-health-wrapper.sh
install -m 755 -o root -g root scripts/wrappers/bootstrap-audit-wrapper.sh /usr/local/bin/bootstrap-audit-wrapper.sh
install -m 755 -o root -g root scripts/wrappers/memory-ingest-wrapper.sh /usr/local/bin/memory-ingest-wrapper.sh
install -m 755 -o root -g root scripts/wrappers/memory-prune-wrapper.sh /usr/local/bin/memory-prune-wrapper.sh

echo "[2/7] Installing inline heartbeat-migrated scripts"
install -m 755 -o root -g root scripts/check-cli-usage.sh /home/openclaw/clawd-control/scripts/check-cli-usage.sh
install -m 755 -o root -g root scripts/system/check-cost-sentinel.sh /usr/local/bin/check-cost-sentinel.sh
install -m 755 -o root -g root .openclaw/scripts/rate-limit-tracker.sh /home/openclaw/.openclaw/scripts/rate-limit-tracker.sh
install -m 755 -o root -g root usr/local/bin/check-system-health.sh /usr/local/bin/check-system-health.sh
install -m 755 -o root -g root usr/local/bin/check-openclaw-version.sh /usr/local/bin/check-openclaw-version.sh
install -m 755 -o root -g root scripts/system/openclaw-watchdog.sh /usr/local/bin/openclaw-watchdog.sh

echo "[3/7] Installing updated cron.d entries"
install -m 644 -o root -g root etc/cron.d/openclaw-memory-ingest /etc/cron.d/openclaw-memory-ingest
install -m 644 -o root -g root etc/cron.d/openclaw-memory-prune /etc/cron.d/openclaw-memory-prune
install -m 644 -o root -g root etc/cron.d/openclaw-bootstrap-audit /etc/cron.d/openclaw-bootstrap-audit

echo "[4/7] Updating openclaw user crontab security-health command"
crontab_tmp="$(mktemp)"
if crontab -u openclaw -l > "$crontab_tmp" 2>/dev/null; then
  sed -i 's|timeout 45 /usr/local/bin/check-security-health.sh|/usr/local/bin/security-health-wrapper.sh|g' "$crontab_tmp"
  crontab -u openclaw "$crontab_tmp"
  echo "  - openclaw crontab updated"
else
  echo "  - no existing openclaw crontab found; skipping"
fi
rm -f "$crontab_tmp"

echo "[5/7] Installing updated watcher.json"
install -m 644 -o root -g root etc/jarvis/watcher.json /etc/jarvis/watcher.json

echo "[6/7] Removing root-owned heartbeat files in /tmp"
find /tmp -maxdepth 1 -type f -name '*-heartbeat.json' -user root -delete

echo "[7/7] Deployment summary"
echo "  Wrappers: security-health, bootstrap-audit, memory-ingest, memory-prune"
echo "  Inline scripts: cli-usage, cost-sentinel, gemini-rate, system-health, version-check, watchdog"
echo "  Cron updates: openclaw-memory-ingest, openclaw-memory-prune, openclaw-bootstrap-audit"
echo "  Watcher config: heartbeat_v2 enabled for 10 migrated jobs"
