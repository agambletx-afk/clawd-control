#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-openclaw.service}"
WATCHDOG_LOG="${WATCHDOG_LOG:-/var/log/openclaw-watchdog.log}"
COOLDOWN_SECONDS="${COOLDOWN_SECONDS:-300}"
MEMORY_RESTART_PERCENT="${MEMORY_RESTART_PERCENT:-80}"
API_URL="${API_URL:-http://127.0.0.1:3000/}"
API_TIMEOUT_SECONDS="${API_TIMEOUT_SECONDS:-5}"
RESTART_STATE_FILE="${RESTART_STATE_FILE:-/tmp/openclaw-watchdog.last_restart}"
JSON_STATUS_FILE="${JSON_STATUS_FILE:-/tmp/openclaw-api-liveness.json}"

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

write_liveness_json() {
  local now code time_total response_ms api_alive_bool api_status
  local max_bytes current_bytes threshold_bytes
  local rss_mb threshold_mb memorymax_mb memory_status
  local tmp_file

  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  read -r code time_total < <(
    curl -sS -o /dev/null -w '%{http_code} %{time_total}' --max-time "$API_TIMEOUT_SECONDS" "$API_URL" 2>/dev/null || echo "000 0"
  )

  if [[ "$code" == "200" || "$code" == "401" ]]; then
    api_alive_bool=true
    api_status="healthy"
  else
    api_alive_bool=false
    api_status="unhealthy"
  fi

  response_ms="$(awk -v t="$time_total" 'BEGIN { printf "%d", (t * 1000) }')"

  max_bytes="$(get_memory_max_bytes)"
  current_bytes="$(get_memory_current_bytes)"

  threshold_bytes=0
  threshold_mb=0
  rss_mb=0
  memorymax_mb=0
  memory_status="warning"

  if [[ -n "$max_bytes" && -n "$current_bytes" ]]; then
    threshold_bytes=$(( max_bytes * MEMORY_RESTART_PERCENT / 100 ))
    threshold_mb=$(( threshold_bytes / 1024 / 1024 ))
    rss_mb=$(( current_bytes / 1024 / 1024 ))
    memorymax_mb=$(( max_bytes / 1024 / 1024 ))

    if (( current_bytes >= max_bytes )); then
      memory_status="critical"
    elif (( current_bytes >= threshold_bytes )); then
      memory_status="warning"
    else
      memory_status="ok"
    fi
  fi

  tmp_file="${JSON_STATUS_FILE}.tmp.$$"

  jq -n \
    --arg timestamp "$now" \
    --argjson api_alive "$api_alive_bool" \
    --argjson response_ms "$response_ms" \
    --argjson rss_mb "$rss_mb" \
    --argjson threshold_mb "$threshold_mb" \
    --arg memory_status "$memory_status" \
    --arg api_status "$api_status" \
    '{
      timestamp: $timestamp,
      api_alive: $api_alive,
      response_ms: $response_ms,
      memory_status: {
        rss_mb: $rss_mb,
        threshold_mb: $threshold_mb,
        status: $memory_status
      },
      api_liveness: {
        status: $api_status,
        response_ms: $response_ms,
        last_check: $timestamp
      }
    }' >"$tmp_file"

  mv "$tmp_file" "$JSON_STATUS_FILE"

  log_line "INFO" "status json updated (api_alive=${api_alive_bool} response_ms=${response_ms} rss_mb=${rss_mb} threshold_mb=${threshold_mb} memorymax_mb=${memorymax_mb} memory_status=${memory_status} file=${JSON_STATUS_FILE})"
}

main() {
  local reason
  local had_action=0
  local exit_code=0

  if reason="$(memory_reason)"; then
    had_action=1
    if ! restart_service "$reason"; then
      exit_code=1
    fi
  elif reason="$(api_reason)"; then
    had_action=1
    if ! restart_service "$reason"; then
      exit_code=1
    fi
  fi

  if (( had_action == 0 )); then
    log_line "INFO" "no action required"
  fi

  write_liveness_json

  return "$exit_code"
}

main "$@"
