#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-openclaw.service}"
LOG_FILE="${LOG_FILE:-/var/log/openclaw-healthcheck.log}"

log_line() {
  local timestamp
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
  printf '%s [INFO] %s\n' "$timestamp" "$1" >>"$LOG_FILE" 2>/dev/null || printf '%s [INFO] %s\n' "$timestamp" "$1" >&2
}

main_pid="$(systemctl show "$SERVICE_NAME" -p MainPID --value 2>/dev/null || echo 0)"
if [[ -z "$main_pid" || "$main_pid" == "0" || ! -r "/proc/${main_pid}/status" ]]; then
  log_line "service process not available for memory report"
  exit 0
fi

rss_bytes="$(awk '/VmRSS:/ {print $2 * 1024}' "/proc/${main_pid}/status")"
log_line "memory report only: pid=${main_pid} rss=${rss_bytes}B"
