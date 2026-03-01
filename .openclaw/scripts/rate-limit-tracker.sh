#!/usr/bin/env bash
set -euo pipefail

SESSIONS_DIR="${OPENCLAW_SESSIONS_DIR:-$HOME/.openclaw/sessions}"
OUTPUT_FILE="${OPENCLAW_RATE_STATUS_FILE:-$HOME/.openclaw/workspace/gemini-rate-status.json}"
NOW_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TODAY="$(date -u +%Y-%m-%d)"
DAILY_LIMIT=250
DAILY_WARNING=200
DAILY_HARD_STOP=230

mkdir -p "$(dirname "$OUTPUT_FILE")"

count_today=0
rpm_current=0
rpm_note=""

if [[ -d "$SESSIONS_DIR" ]]; then
  if mapfile -d '' files < <(find "$SESSIONS_DIR" -type f \( -name '*.jsonl' -o -name '*.log' -o -name '*.json' \) -print0 2>/dev/null); then
    if (( ${#files[@]} > 0 )); then
      # Count lines that look like Gemini model calls with today's date in the line.
      count_today=$(cat "${files[@]}" 2>/dev/null \
        | awk -v d="$TODAY" 'index(tolower($0),"gemini") && index($0,d) { c++ } END { print c+0 }')

      # Try to compute requests in last 60 seconds by parsing ISO timestamps in matching lines.
      now_epoch="$(date -u +%s)"
      rpm_current=$(cat "${files[@]}" 2>/dev/null | awk '
        {
          line=tolower($0)
          if (index(line, "gemini") == 0) next
          if (match($0, /[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z/)) {
            print substr($0, RSTART, RLENGTH)
          }
        }
      ' | while read -r ts; do
        t="${ts%%.*}Z"
        epoch=$(date -u -d "$t" +%s 2>/dev/null || true)
        if [[ -n "${epoch:-}" ]] && (( now_epoch - epoch <= 60 )) && (( now_epoch >= epoch )); then
          echo 1
        fi
      done | awk '{c+=$1} END {print c+0}')

      if [[ -z "$rpm_current" ]]; then
        rpm_current=-1
        rpm_note="Unable to parse per-request timestamps from session logs; rpm unavailable."
      fi
    fi
  fi
else
  rpm_current=0
fi

status="green"
if (( count_today >= DAILY_HARD_STOP )); then
  status="red"
elif (( count_today >= DAILY_WARNING )); then
  status="yellow"
fi

if [[ "$rpm_current" == "-1" ]]; then
  cat > "$OUTPUT_FILE" <<JSON
{
  "timestamp": "$NOW_UTC",
  "gemini_requests_today": $count_today,
  "gemini_rpm_current": -1,
  "daily_limit": $DAILY_LIMIT,
  "daily_warning": $DAILY_WARNING,
  "daily_hard_stop": $DAILY_HARD_STOP,
  "status": "$status",
  "rpm_note": "$rpm_note"
}
JSON
else
  cat > "$OUTPUT_FILE" <<JSON
{
  "timestamp": "$NOW_UTC",
  "gemini_requests_today": $count_today,
  "gemini_rpm_current": ${rpm_current:-0},
  "daily_limit": $DAILY_LIMIT,
  "daily_warning": $DAILY_WARNING,
  "daily_hard_stop": $DAILY_HARD_STOP,
  "status": "$status"
}
JSON
fi
