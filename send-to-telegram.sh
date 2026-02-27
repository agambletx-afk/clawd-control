#!/bin/bash
# send-to-telegram.sh - Sends a message to Adam's Telegram chat
# Usage: bash send-to-telegram.sh "message text here"
# Called by Jarvis when responding to dashboard messages
# Reads bot token and chat ID from openclaw.json - no hardcoded values

set -euo pipefail

MSG="${1:-}"
if [ -z "$MSG" ]; then
  echo "Usage: send-to-telegram.sh \"message\""
  exit 1
fi

CONFIG="/home/openclaw/.openclaw/openclaw.json"
TOKEN=$(python3 -c "import json; c=json.load(open('$CONFIG')); print(c['channels']['telegram']['botToken'])")
CHAT_ID=$(python3 -c "import json; c=json.load(open('$CONFIG')); print(c['channels']['telegram']['allowFrom'][0])")

curl -s -X POST "https://api.telegram.org/bot${TOKEN}/sendMessage" \
  -d chat_id="$CHAT_ID" \
  -d text="$MSG" \
  -d parse_mode="Markdown" > /dev/null 2>&1

echo "Sent to Telegram."
