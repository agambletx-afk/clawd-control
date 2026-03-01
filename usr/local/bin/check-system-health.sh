#!/bin/bash
set -euo pipefail

NOW_EPOCH=$(date -u +%s)

check_service() {
  local name="$1"
  local status
  status=$(systemctl is-active "$name" 2>/dev/null || true)
  if [[ "$status" == "active" ]]; then
    jq -n --arg name "$name" '{name:$name,status:"green",message:"service active"}'
  else
    jq -n --arg name "$name" --arg status "$status" '{name:$name,status:"red",message:("service status: " + ($status|if .=="" then "unknown" else . end))}'
  fi
}

check_heartbeats() {
  local hb_dir="/tmp/jarvis/heartbeats"

  if [[ ! -d "$hb_dir" ]]; then
    jq -n '[{"name":"heartbeats","status":"yellow","message":"no heartbeat files found"}]'
    return
  fi

  shopt -s nullglob
  local files=("$hb_dir"/*.json)
  shopt -u nullglob
  if (( ${#files[@]} == 0 )); then
    jq -n '[{"name":"heartbeats","status":"yellow","message":"no heartbeat files found"}]'
    return
  fi

  local out='[]'
  local file agent timestamp pid agent_status="green" msg="agent heartbeat healthy" age

  for file in "${files[@]}"; do
    agent=$(jq -r '.agent // "unknown"' "$file" 2>/dev/null || echo "unknown")
    timestamp=$(jq -r '.timestamp // empty' "$file" 2>/dev/null || true)
    pid=$(jq -r '.pid // 0' "$file" 2>/dev/null || echo 0)

    agent_status="green"
    msg="agent heartbeat healthy"

    if [[ -n "$timestamp" ]]; then
      local ts_epoch
      ts_epoch=$(date -u -d "$timestamp" +%s 2>/dev/null || echo 0)
      if (( ts_epoch > 0 )); then
        age=$((NOW_EPOCH - ts_epoch))
        if (( age > 1800 )); then
          agent_status="red"
          msg="agent may be dead"
        elif (( age > 600 )); then
          agent_status="yellow"
          msg="agent heartbeat stale"
        fi
      fi
    fi

    if ! kill -0 "$pid" 2>/dev/null; then
      agent_status="red"
      msg="agent PID not found"
    fi

    out=$(jq --arg name "heartbeat:$agent" --arg status "$agent_status" --arg message "$msg" '. + [{name:$name,status:$status,message:$message}]' <<<"$out")
  done

  echo "$out"
}

services=$(jq -n '[]')
for svc in openclaw clawd-control; do
  services=$(jq --argjson item "$(check_service "$svc")" '. + [$item]' <<<"$services")
done

heartbeats=$(check_heartbeats)
checks=$(jq -s 'add' <(echo "$services") <(echo "$heartbeats"))
overall=$(jq -r 'if any(.[]; .status=="red") then "red" elif any(.[]; .status=="yellow") then "yellow" else "green" end' <<<"$checks")

jq -n --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg overall "$overall" --argjson checks "$checks" \
  '{timestamp:$timestamp,overall_status:$overall,checks:$checks}'
