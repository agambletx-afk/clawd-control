#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-openclaw.service}"
WATCHDOG_LOG="${WATCHDOG_LOG:-/var/log/openclaw-watchdog.log}"
COOLDOWN_SECONDS="${COOLDOWN_SECONDS:-300}"
MEMORY_RESTART_PERCENT="${MEMORY_RESTART_PERCENT:-80}"
API_URL="${API_URL:-http://127.0.0.1:3000/}"
API_TIMEOUT_SECONDS="${API_TIMEOUT_SECONDS:-5}"
RESTART_STATE_FILE="${RESTART_STATE_FILE:-/tmp/openclaw-watchdog.last_restart}"

TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

log_line() {
  local level="$1"
  local message="$2"
  local timestamp
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  mkdir -p "$(dirname "$WATCHDOG_LOG")" 2>/dev/null || true
  printf '%s [%s] %s\n' "$timestamp" "$level" "$message" >>"$WATCHDOG_LOG" 2>/dev/null || printf '%s [%s] %s\n' "$timestamp" "$level" "$message" >&2
}

send_telegram_alert() {
  local message="$1"
  if [[ -z "$TELEGRAM_BOT_TOKEN" || -z "$TELEGRAM_CHAT_ID" ]]; then
    log_line "WARN" "Telegram alert skipped (missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID)"
    return 0
  fi

  if curl -sS --max-time 8 -X POST \
    "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_CHAT_ID}" \
    --data-urlencode "text=${message}" >/dev/null; then
    log_line "INFO" "Telegram alert sent"
  else
    log_line "WARN" "Telegram alert failed"
  fi
}

get_memory_max_bytes() {
  local raw
  raw="$(systemctl show "$SERVICE_NAME" -p MemoryMax --value 2>/dev/null || true)"
  if [[ -z "$raw" || "$raw" == "infinity" || "$raw" == "18446744073709551615" ]]; then
    echo ""
    return 0
  fi
  echo "$raw"
}

get_memory_current_bytes() {
  local main_pid
  main_pid="$(systemctl show "$SERVICE_NAME" -p MainPID --value 2>/dev/null || echo 0)"
  if [[ -z "$main_pid" || "$main_pid" == "0" ]]; then
    echo ""
    return 0
  fi

  if [[ -r "/proc/${main_pid}/status" ]]; then
    awk '/VmRSS:/ {print $2 * 1024}' "/proc/${main_pid}/status"
    return 0
  fi

  echo ""
}

memory_reason() {
  local max_bytes current_bytes threshold
  max_bytes="$(get_memory_max_bytes)"
  current_bytes="$(get_memory_current_bytes)"

  if [[ -z "$max_bytes" || -z "$current_bytes" ]]; then
    return 1
  fi

  threshold=$(( max_bytes * MEMORY_RESTART_PERCENT / 100 ))
  if (( current_bytes >= threshold )); then
    printf 'memory usage high (rss=%sB threshold=%sB memorymax=%sB percent=%s)' \
      "$current_bytes" "$threshold" "$max_bytes" "$MEMORY_RESTART_PERCENT"
    return 0
  fi

  log_line "INFO" "memory ok (rss=${current_bytes}B threshold=${threshold}B memorymax=${max_bytes}B)"
  return 1
}

api_reason() {
  local code
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time "$API_TIMEOUT_SECONDS" "$API_URL" 2>/dev/null || echo 000)"
  if [[ "$code" == "200" || "$code" == "401" ]]; then
    log_line "INFO" "api liveness ok (HTTP ${code})"
    return 1
  fi

  printf 'api liveness failed (url=%s status=%s)' "$API_URL" "$code"
  return 0
}

in_cooldown() {
  local now last
  now="$(date +%s)"
  if [[ ! -f "$RESTART_STATE_FILE" ]]; then
    return 1
  fi
  last="$(cat "$RESTART_STATE_FILE" 2>/dev/null || echo 0)"
  if [[ ! "$last" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  if (( now - last < COOLDOWN_SECONDS )); then
    log_line "WARN" "cooldown active (last_restart=${last} cooldown=${COOLDOWN_SECONDS}s)"
    return 0
  fi
  return 1
}

restart_service() {
  local reason="$1"
  local now
  now="$(date +%s)"

  if in_cooldown; then
    log_line "WARN" "restart skipped due to cooldown: ${reason}"
    return 0
  fi

  send_telegram_alert "OpenClaw watchdog restarting ${SERVICE_NAME}: ${reason}"
  log_line "WARN" "restarting ${SERVICE_NAME}: ${reason}"

  if systemctl restart "$SERVICE_NAME"; then
    printf '%s\n' "$now" >"$RESTART_STATE_FILE"
    log_line "INFO" "restart completed"
  else
    log_line "ERROR" "restart failed"
    return 1
  fi
}

main() {
  local reason

  if reason="$(memory_reason)"; then
    restart_service "$reason"
    exit 0
  fi

  if reason="$(api_reason)"; then
    restart_service "$reason"
    exit 0
  fi

  log_line "INFO" "no action required"
}

main "$@"
