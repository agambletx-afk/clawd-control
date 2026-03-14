#!/usr/bin/env bash

if [[ -z "${HEARTBEAT_ID:-}" ]]; then
  echo "heartbeat-lib.sh: HEARTBEAT_ID is required" >&2
  exit 1
fi

HEARTBEAT_FILE="/tmp/${HEARTBEAT_ID}-heartbeat.json"
_HEARTBEAT_FINISHED=0
_HEARTBEAT_PREVIOUS_EXIT_TRAP=""

_heartbeat_now_iso() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

_heartbeat_started_epoch() {
  if [[ -n "${EPOCHREALTIME:-}" ]]; then
    printf '%s\n' "${EPOCHREALTIME%%.*}"
  else
    date +%s
  fi
}

_heartbeat_write() {
  local status="$1"
  local finished_at="$2"
  local duration_ms="$3"
  local exit_code="$4"
  local tmp_file
  tmp_file="${HEARTBEAT_FILE}.tmp.$$"

  jq -n \
    --arg id "$HEARTBEAT_ID" \
    --arg status "$status" \
    --arg started_at "$HEARTBEAT_STARTED_AT" \
    --argjson finished_at "$finished_at" \
    --argjson duration_ms "$duration_ms" \
    --argjson exit_code "$exit_code" \
    --arg version "2" \
    '{
      id: $id,
      status: $status,
      started_at: $started_at,
      finished_at: $finished_at,
      duration_ms: $duration_ms,
      exit_code: $exit_code,
      version: $version
    }' >"$tmp_file"

  mv "$tmp_file" "$HEARTBEAT_FILE"
}

heartbeat_finish() {
  _HEARTBEAT_FINISHED=1
  local finished_at duration_ms
  finished_at="\"$(_heartbeat_now_iso)\""
  duration_ms="$((SECONDS * 1000))"
  _heartbeat_write "success" "$finished_at" "$duration_ms" "0"
}

_heartbeat_on_exit() {
  local exit_code="$?"
  local previous_trap_cmd

  if [[ "${_HEARTBEAT_FINISHED:-0}" -ne 1 ]]; then
    local finished_at duration_ms status
    finished_at="\"$(_heartbeat_now_iso)\""
    duration_ms="$((SECONDS * 1000))"
    if (( exit_code == 0 )); then
      status="success"
    else
      status="failed"
    fi
    _heartbeat_write "$status" "$finished_at" "$duration_ms" "$exit_code"
  fi

  previous_trap_cmd="${_HEARTBEAT_PREVIOUS_EXIT_TRAP:-}"
  if [[ -n "$previous_trap_cmd" ]]; then
    eval "$previous_trap_cmd"
  fi

  return "$exit_code"
}

_heartbeat_capture_existing_exit_trap() {
  local trap_def
  trap_def="$(trap -p EXIT || true)"
  if [[ "$trap_def" =~ ^trap\ --\ \'(.*)\'\ EXIT$ ]]; then
    _HEARTBEAT_PREVIOUS_EXIT_TRAP="${BASH_REMATCH[1]}"
  else
    _HEARTBEAT_PREVIOUS_EXIT_TRAP=""
  fi
}

HEARTBEAT_STARTED_AT="$(_heartbeat_now_iso)"
_HEARTBEAT_STARTED_EPOCH="$(_heartbeat_started_epoch)"
SECONDS=0

_heartbeat_write "running" "null" "null" "null"
_heartbeat_capture_existing_exit_trap
trap '_heartbeat_on_exit' EXIT
