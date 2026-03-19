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
    local watcher_json watcher_generated watcher_epoch watcher_age hb2_count stale_count stale_ids
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
      stale_ids=$(echo "$watcher_json" | jq -r --argjson now "$NOW_EPOCH" '
        [.system_crons[]
          | select((.heartbeat_version|tostring)=="2")
          | .last_seen as $ls
          | (try ($ls | fromdateiso8601) catch 0) as $ts
          | select($ts > 0)
          | select(($now - $ts) > (((.threshold_minutes // 10) * 60) | floor))
          | (.id // "unknown")
        ] | join(",")')

      if (( hb2_count == 0 )); then
        jq -n '[{"name":"heartbeats","status":"yellow","message":"no heartbeat_v2 checks found in watcher-status"}]'
        return
      fi

      if (( watcher_age > 900 )); then
        jq -n --arg age "${watcher_age}" '[{"name":"heartbeats","status":"yellow","message":("watcher-status stale (" + $age + "s old)")}]'
        return
      fi

      if (( stale_count > 0 )); then
        local stale_log_file="/home/openclaw/.openclaw/workspace/heartbeats-stale.log"
        local stale_line
        stale_line="$(date -u +%Y-%m-%dT%H:%M:%SZ) stale_count=${stale_count} ids=${stale_ids:-unknown}"
        {
          echo "$stale_line"
          [[ -f "$stale_log_file" ]] && cat "$stale_log_file"
        } | head -n 500 > "${stale_log_file}.tmp" && mv "${stale_log_file}.tmp" "$stale_log_file"

        jq -n --arg stale "${stale_count}" --arg ids "${stale_ids}" '[{"name":"heartbeats","status":"yellow","message":($stale + " heartbeat_v2 checks stale: " + (if ($ids|length)>0 then $ids else "unknown" end))}]'
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


check_stale_tasks() {
  local db="/home/openclaw/clawd-control/tasks.db"
  if [[ ! -f "$db" ]]; then
    jq -n '[{"name":"task-stall","status":"yellow","message":"tasks.db not found"}]'
    return
  fi

  local stale_minutes=30
  local rows
  rows=$(sqlite3 "$db" "SELECT id, title, assigned_agent, CAST((strftime('%s','now') - strftime('%s',updated_at)) / 60 AS INTEGER) AS mins FROM tasks WHERE status = 'in_progress' AND updated_at < datetime('now', '-${stale_minutes} minutes')" 2>/dev/null || true)

  if [[ -z "$rows" ]]; then
    jq -n '[{"name":"task-stall","status":"green","message":"no stale tasks"}]'
    return
  fi

  local count
  count=$(echo "$rows" | wc -l)
  local status="yellow"
  if (( count >= 3 )); then status="red"; fi

  local detail
  detail=$(echo "$rows" | head -3 | while IFS='|' read -r id title agent mins; do echo "#${id} ${title} (${mins}m)"; done | tr '\n' '; ')

  jq -n --arg status "$status" --arg message "${count} stale task(s): ${detail}" \
    '[{"name":"task-stall","status":$status,"message":$message}]'
}

check_overdue_tasks() {
  local db="/home/openclaw/clawd-control/tasks.db"
  if [[ ! -f "$db" ]]; then
    jq -n '[{"name":"task-overdue","status":"green","message":"tasks.db not found"}]'
    return
  fi

  local rows
  rows=$(sqlite3 "$db" "SELECT id, title, assigned_agent, due_at, CAST((strftime('%s','now') - strftime('%s',due_at)) / 60 AS INTEGER) AS mins_overdue FROM tasks WHERE due_at IS NOT NULL AND datetime(due_at) < datetime('now') AND status NOT IN ('done','archive','failed')" 2>/dev/null || true)

  if [[ -z "$rows" ]]; then
    jq -n '[{"name":"task-overdue","status":"green","message":"no overdue deliverables"}]'
    return
  fi

  local count
  count=$(echo "$rows" | wc -l)

  local detail
  detail=$(echo "$rows" | head -3 | while IFS='|' read -r id title agent due mins; do echo "#${id} ${title} (${mins}m overdue)"; done | tr '\n' '; ')

  jq -n --arg message "${count} overdue deliverable(s): ${detail}" \
    '[{"name":"task-overdue","status":"red","message":$message}]'
}

check_unnotified_tasks() {
  local db="/home/openclaw/clawd-control/tasks.db"
  if [[ ! -f "$db" ]]; then
    jq -n '[{"name":"task-unnotified","status":"green","message":"tasks.db not found"}]'
    return
  fi

  local rows
  rows=$(sqlite3 "$db" "SELECT id, title FROM tasks WHERE status IN ('done','failed') AND requested_via IS NOT NULL AND user_notified_at IS NULL AND updated_at < datetime('now', '-10 minutes')" 2>/dev/null || true)

  if [[ -z "$rows" ]]; then
    jq -n '[{"name":"task-unnotified","status":"green","message":"no unnotified completions"}]'
    return
  fi

  local count
  count=$(echo "$rows" | wc -l)

  local detail
  detail=$(echo "$rows" | head -3 | while IFS='|' read -r id title; do echo "#${id} ${title}"; done | tr '\n' '; ')

  jq -n --arg message "${count} completed but user not notified: ${detail}" \
    '[{"name":"task-unnotified","status":"yellow","message":$message}]'
}

services=$(jq -n '[]')
for svc in openclaw clawd-control; do
  services=$(jq --argjson item "$(check_service "$svc")" '. + [$item]' <<<"$services")
done

heartbeats=$(check_heartbeats)
stale_tasks=$(check_stale_tasks)
overdue_tasks=$(check_overdue_tasks)
unnotified_tasks=$(check_unnotified_tasks)
checks=$(jq -s 'add' <(echo "$services") <(echo "$heartbeats") <(echo "$stale_tasks") <(echo "$overdue_tasks") <(echo "$unnotified_tasks"))
overall=$(jq -r 'if any(.[]; .status=="red") then "red" elif any(.[]; .status=="yellow") then "yellow" else "green" end' <<<"$checks")

jq -n --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg overall "$overall" --argjson checks "$checks" \
  '{timestamp:$timestamp,overall_status:$overall,checks:$checks}'
heartbeat_finish
