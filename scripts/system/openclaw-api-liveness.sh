#!/usr/bin/env bash
set -euo pipefail
API_URL="${API_URL:-http://127.0.0.1:3000/}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-5}"
LOG_FILE="${LOG_FILE:-/var/log/openclaw-api-liveness.log}"
JSON_STATUS_FILE="${JSON_STATUS_FILE:-/tmp/openclaw-api-liveness.json}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
log_line() {
  local level="$1"
  local message="$2"
  local timestamp
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
  printf '%s [%s] %s\n' "$timestamp" "$level" "$message" >>"$LOG_FILE" 2>/dev/null || printf '%s [%s] %s\n' "$timestamp" "$level" "$message" >&2
}
send_telegram_alert() {
  local message="$1"
  if [[ -z "$TELEGRAM_BOT_TOKEN" || -z "$TELEGRAM_CHAT_ID" ]]; then
    log_line "WARN" "telegram alert skipped (missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID)"
    return 0
  fi
  if curl -sS --max-time 8 -X POST \
    "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_CHAT_ID}" \
    --data-urlencode "text=${message}" >/dev/null; then
    log_line "INFO" "telegram alert sent"
  else
    log_line "WARN" "telegram alert failed"
  fi
}
code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT_SECONDS" "$API_URL" 2>/dev/null || echo 000)"

# Update JSON status file for dashboard (always, before any exit)
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [[ "$code" == "200" || "$code" == "401" ]]; then
  printf '{"checked_at":"%s","api_alive":true,"consecutive_failures":0,"last_restart":null,"disk_alert":null,"locks_cleaned":0}\n' "$NOW" > "$JSON_STATUS_FILE"
  log_line "INFO" "api healthy (HTTP ${code})"
  exit 0
fi

printf '{"checked_at":"%s","api_alive":false,"consecutive_failures":1,"last_restart":null,"disk_alert":null,"locks_cleaned":0}\n' "$NOW" > "$JSON_STATUS_FILE"
log_line "WARN" "api unhealthy (HTTP ${code})"
send_telegram_alert "OpenClaw API liveness alert: ${API_URL} returned HTTP ${code}."
