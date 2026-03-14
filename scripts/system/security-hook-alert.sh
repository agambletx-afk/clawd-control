#!/usr/bin/env bash
# security-hook-alert.sh — Telegram alert on new blocked calls
trap 'echo "{"last_success_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","exit_code":$?}" > /tmp/security-hook-heartbeat.json' EXIT
# Runs via cron. Reads security-hook.log, compares line count against
# a watermark file. Sends one Telegram message per run summarizing
# new blocks. Zero tokens consumed.
#
# Install:
#   cp security-hook-alert.sh /usr/local/bin/
#   chmod 755 /usr/local/bin/security-hook-alert.sh
#   chown openclaw:openclaw /usr/local/bin/security-hook-alert.sh
#
# Cron (every 5 minutes, as openclaw user):
#   */5 * * * * /usr/local/bin/security-hook-alert.sh

set -euo pipefail

LOG_FILE="/home/openclaw/.openclaw/logs/security-hook.log"
WATERMARK_FILE="/tmp/security-hook-alert-watermark"
BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
CHAT_ID="${TELEGRAM_CHAT_ID:-}"

# Bail if no Telegram config
if [[ -z "$BOT_TOKEN" || -z "$CHAT_ID" ]]; then
  exit 0
fi

# Bail if log doesn't exist or is empty
if [[ ! -s "$LOG_FILE" ]]; then
  exit 0
fi

CURRENT_LINES=$(wc -l < "$LOG_FILE")

# Read watermark (default 0 on first run)
if [[ -f "$WATERMARK_FILE" ]]; then
  LAST_LINES=$(cat "$WATERMARK_FILE")
else
  LAST_LINES=0
fi

# Nothing new
if (( CURRENT_LINES <= LAST_LINES )); then
  echo "$CURRENT_LINES" > "$WATERMARK_FILE"
  exit 0
fi

NEW_COUNT=$(( CURRENT_LINES - LAST_LINES ))

# Extract new entries
NEW_ENTRIES=$(tail -n "$NEW_COUNT" "$LOG_FILE")

# Build summary: count by matched rule
RULE_SUMMARY=$(echo "$NEW_ENTRIES" | \
  python3 -c "
import sys, json
from collections import Counter
rules = Counter()
agents = Counter()
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        entry = json.loads(line)
        rules[entry.get('matchedRule', 'unknown')] += 1
        agents[entry.get('agentId', 'unknown')] += 1
    except:
        pass
parts = []
if rules:
    parts.append('Rules: ' + ', '.join(f'{r} ({c})' for r, c in rules.most_common(5)))
if agents:
    parts.append('Agents: ' + ', '.join(f'{a} ({c})' for a, c in agents.most_common(5)))
print('\n'.join(parts) if parts else 'Could not parse entries')
" 2>/dev/null || echo "Could not parse entries")

# Send Telegram message
MESSAGE="🛡 Security Hook: ${NEW_COUNT} blocked call(s) in last check

${RULE_SUMMARY}

Log: ~/.openclaw/logs/security-hook.log"

curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
  -d chat_id="$CHAT_ID" \
  -d text="$MESSAGE" \
  -d parse_mode="Markdown" \
  > /dev/null 2>&1 || true

# Update watermark
echo "$CURRENT_LINES" > "$WATERMARK_FILE"
