#!/usr/bin/env bash
set -euo pipefail

SUDOERS_FILE="/etc/sudoers.d/clawd-watcher-dashboard"
TMP_FILE="$(mktemp)"

cat > "$TMP_FILE" <<'RULES'
openclaw ALL=(ALL) NOPASSWD: /usr/bin/timeout 120 /usr/bin/openclaw cron run *
openclaw ALL=(ALL) NOPASSWD: /usr/bin/timeout 60 /usr/bin/openclaw cron enable *
openclaw ALL=(ALL) NOPASSWD: /usr/bin/timeout 60 /usr/bin/openclaw cron disable *
RULES

install -m 0440 "$TMP_FILE" "$SUDOERS_FILE"
visudo -cf "$SUDOERS_FILE"
rm -f "$TMP_FILE"

echo "WATCHER sudoers rules deployed: $SUDOERS_FILE"
echo "Restarting clawd-control..."
systemctl restart clawd-control
systemctl --no-pager --full status clawd-control | head -20
