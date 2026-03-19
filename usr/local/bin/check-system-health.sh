#!/bin/bash
set -euo pipefail

HEARTBEAT_ID="system-health"
source /usr/local/bin/heartbeat-lib.sh

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
  # v2 source of truth: watcher-status artifact (heartbeat_v2 checks)
  local watcher_file="/home/openclaw/.openclaw/workspace/watcher-status.json"

  if [[ -f "$watcher_file" ]]; then
    local watcher_json watcher_generated watcher_epoch watcher_age hb2_count stale_count
    watcher_json=$(cat "$watcher_file" 2>/dev/null || true)

    if echo "$watcher_json" | jq -e '.system_crons and (.system_crons|type=="array")' >/dev/null 2>&1; then
      watcher_generated=$(echo "$watcher_json" | jq -r '.generated_at // empty')
      watcher_epoch=$(date -u -d "$watcher_generated" +%s 2>/dev/null || echo 0)
      watcher_age=999999
      if (( watcher_epoch > 0 )); then
        watcher_age=$((NOW_EPOCH - watcher_epoch))
      fi

      hb2_count=$(echo "$watcher_json" | jq '[.system_crons[] | select((.heartbeat_version|tostring)=="2")] | length')
      stale_count=$(echo "$watcher_json" | jq --argjson now "$NOW_EPOCH" '
        [.system_crons[]
          | select((.heartbeat_version|tostring)=="2")
          | .last_seen as $ls
          | (try ($ls | fromdateiso8601) catch 0) as $ts
          | select($ts > 0)
          | select(($now - $ts) > (((.threshold_minutes // 10) * 60) | floor))
        ] | length')

      if (( hb2_count == 0 )); then
        jq -n '[{"name":"heartbeats","status":"yellow","message":"no heartbeat_v2 checks found in watcher-status"}]'
        return
      fi

      if (( watcher_age > 900 )); then
        jq -n --arg age "${watcher_age}" '[{"name":"heartbeats","status":"yellow","message":("watcher-status stale (" + $age + "s old)")}]'
        return
      fi

      if (( stale_count > 0 )); then
        jq -n --arg stale "${stale_count}" '[{"name":"heartbeats","status":"yellow","message":($stale + " heartbeat_v2 checks stale")}]'
        return
      fi

      jq -n --arg count "${hb2_count}" '[{"name":"heartbeats","status":"green","message":("heartbeat_v2 healthy (" + $count + " checks)")}]'
      return
    fi
  fi

  # Legacy fallback: older /tmp/jarvis/heartbeats artifacts
  local hb_dir="/tmp/jarvis/heartbeats"
  if [[ ! -d "$hb_dir" ]]; then
    jq -n '[{"name":"heartbeats","status":"yellow","message":"no heartbeat artifacts found (watcher-status + legacy path missing)"}]'
    return
  fi

  shopt -s nullglob
  local files=("$hb_dir"/*.json)
  shopt -u nullglob
  if (( ${#files[@]} == 0 )); then
    jq -n '[{"name":"heartbeats","status":"yellow","message":"no heartbeat artifacts found (legacy path empty)"}]'
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
heartbeat_finish
