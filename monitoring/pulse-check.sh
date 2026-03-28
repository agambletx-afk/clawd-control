#!/bin/bash

set -uo pipefail

WORKSPACE_PATH="/home/openclaw/.openclaw/workspace/"
SESSIONS_PATH="/home/openclaw/.openclaw/sessions/"
HEALTH_URL="http://localhost:18789/health"
SERVICE_NAME="openclaw.service"
STATE_FILE="${WORKSPACE_PATH}.pulse-state.json"
STATUS_FILE="${WORKSPACE_PATH}.pulse-status.json"
KILL_SWITCH_FILE="${WORKSPACE_PATH}.kill-switches.json"
RECOVERY_LOG_FILE="${WORKSPACE_PATH}.recovery-log.jsonl"
PULSE_CONFIG_FILE="${WORKSPACE_PATH}.pulse-config.json"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=monitoring/preflight-checks.sh
source "${SCRIPT_DIR}/preflight-checks.sh"

START_EPOCH="$(date +%s)"
START_ISO="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
CHECK_ID="pulse-$(date -u +"%Y%m%dT%H%M%SZ")-$$"
EXIT_CODE=0
STATUS_COLOR="green"

json_file_update() {
  local file_path="$1"
  local py_expr="$2"
  python3 -c "import json, os, tempfile; p='$file_path'; d=json.load(open(p, 'r', encoding='utf-8')) if os.path.exists(p) else {}; $py_expr; f=tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8', dir=os.path.dirname(p)); json.dump(d, f, indent=2, sort_keys=True); f.write('\\n'); f.close(); os.replace(f.name, p)"
}

ensure_state_file() {
  if [ -f "$STATE_FILE" ]; then
    return
  fi
  json_file_update "$STATE_FILE" "d.update({'consecutive_failures':0,'last_success_at':None,'last_restart_at':None,'last_restart_result':None,'restarts_this_hour':0,'restart_timestamps':[],'kill_switch_reminders':{}})"
}

get_state_field() {
  local key="$1"
  python3 -c "import json; d=json.load(open('$STATE_FILE', 'r', encoding='utf-8')); v=d.get('$key'); print('' if v is None else v)"
}

get_active_kill_switches() {
  python3 -c "import json; d=json.load(open('$KILL_SWITCH_FILE','r',encoding='utf-8')); print(','.join(sorted([k for k,v in d.items() if isinstance(v,dict) and v.get('active')])) )"
}

activate_kill_switch() {
  local switch_name="$1"
  local reason="$2"
  local activated_by="$3"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  python3 -c "import json, os, tempfile; p='$KILL_SWITCH_FILE'; d=json.load(open(p,'r',encoding='utf-8')); s=d.get('$switch_name',{}); s['active']=True; s['reason']='$reason'; s['activated_at']='$ts'; s['activated_by']='$activated_by'; d['$switch_name']=s; f=tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8', dir=os.path.dirname(p)); json.dump(d,f,indent=2,sort_keys=True); f.write('\\n'); f.close(); os.replace(f.name,p)"
}

append_recovery_log() {
  local layer="$1"
  local action="$2"
  local result="$3"
  local activated="$4"
  local escalated="$5"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  python3 -c "import json, os, tempfile; p='$RECOVERY_LOG_FILE'; entry={'timestamp':'$ts','check_id':'$CHECK_ID','layer':'$layer','action':'$action','result':'$result','kill_switches_activated':'$activated','escalated':$escalated}; content='';\
if os.path.exists(p): content=open(p,'r',encoding='utf-8').read();\
f=tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8', dir=os.path.dirname(p));\
f.write(content); f.write(json.dumps(entry, sort_keys=True)+'\\n'); f.close(); os.replace(f.name, p)"
}

send_telegram() {
  local message="$1"
  local token chat_id
  token="$(python3 -c "import json; d=json.load(open('$PULSE_CONFIG_FILE', 'r', encoding='utf-8')); print(d.get('telegram_bot_token',''))")"
  chat_id="$(python3 -c "import json; d=json.load(open('$PULSE_CONFIG_FILE', 'r', encoding='utf-8')); print(d.get('telegram_chat_id',''))")"

  if [ -z "$token" ] || [ -z "$chat_id" ]; then
    append_recovery_log "pulse" "telegram_send" "skipped_missing_credentials" "" "False"
    return
  fi

  curl -sS -X POST "https://api.telegram.org/bot${token}/sendMessage" \
    -d chat_id="$chat_id" \
    -d text="$message" \
    -d parse_mode="HTML" >/dev/null 2>&1 || true
}

http_health_check() {
  local code
  code="$(curl -sS -m 5 -o /dev/null -w "%{http_code}" "$HEALTH_URL" || echo "000")"
  [ "$code" = "200" ]
}

process_health_check() {
  pgrep -f "openclaw" >/dev/null 2>&1
}

port_health_check() {
  ss -tlnp 2>/dev/null | grep -q ":18789"
}

recent_session_write_check() {
  python3 -c "import os, time; root='$SESSIONS_PATH'; now=time.time();\
bad=False\
\
for dp,_,fs in os.walk(root):\
  for n in fs:\
    if n.endswith('.jsonl') and now-os.path.getmtime(os.path.join(dp,n)) < 5: bad=True\
\
raise SystemExit(1 if bad else 0)"
}

refresh_restart_window() {
  local now_epoch
  now_epoch="$(date +%s)"
  python3 -c "import json, os, tempfile, time; p='$STATE_FILE'; d=json.load(open(p,'r',encoding='utf-8')); ts=[int(x) for x in d.get('restart_timestamps',[]) if int(x) >= int($now_epoch)-3600]; d['restart_timestamps']=ts; d['restarts_this_hour']=len(ts); f=tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8', dir=os.path.dirname(p)); json.dump(d,f,indent=2,sort_keys=True); f.write('\\n'); f.close(); os.replace(f.name,p)"
}

record_restart() {
  local result="$1"
  local now_epoch now_iso
  now_epoch="$(date +%s)"
  now_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  python3 -c "import json, os, tempfile; p='$STATE_FILE'; d=json.load(open(p,'r',encoding='utf-8')); ts=[int(x) for x in d.get('restart_timestamps',[]) if int(x) >= int($now_epoch)-3600]; ts.append(int($now_epoch)); d['restart_timestamps']=ts; d['restarts_this_hour']=len(ts); d['last_restart_at']='$now_iso'; d['last_restart_result']='$result'; f=tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8', dir=os.path.dirname(p)); json.dump(d,f,indent=2,sort_keys=True); f.write('\\n'); f.close(); os.replace(f.name,p)"
}

set_consecutive_failures() {
  local value="$1"
  python3 -c "import json, os, tempfile; p='$STATE_FILE'; d=json.load(open(p,'r',encoding='utf-8')); d['consecutive_failures']=int($value); f=tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8', dir=os.path.dirname(p)); json.dump(d,f,indent=2,sort_keys=True); f.write('\\n'); f.close(); os.replace(f.name,p)"
}

set_last_success() {
  local when="$1"
  python3 -c "import json, os, tempfile; p='$STATE_FILE'; d=json.load(open(p,'r',encoding='utf-8')); d['last_success_at']='$when'; f=tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8', dir=os.path.dirname(p)); json.dump(d,f,indent=2,sort_keys=True); f.write('\\n'); f.close(); os.replace(f.name,p)"
}

write_status_contract() {
  local end_iso duration_ms active_kill_switches consecutive_failures last_success_at last_restart_at last_restart_result restarts_this_hour
  end_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  duration_ms="$(( ( $(date +%s) - START_EPOCH ) * 1000 ))"
  active_kill_switches="$(get_active_kill_switches)"
  consecutive_failures="$(get_state_field consecutive_failures)"
  last_success_at="$(get_state_field last_success_at)"
  last_restart_at="$(get_state_field last_restart_at)"
  last_restart_result="$(get_state_field last_restart_result)"
  restarts_this_hour="$(get_state_field restarts_this_hour)"

  STATUS_LAST_SUCCESS_AT="$last_success_at" \
  STATUS_LAST_RESTART_AT="$last_restart_at" \
  STATUS_LAST_RESTART_RESULT="$last_restart_result" \
  STATUS_ACTIVE_KILL_SWITCHES="$active_kill_switches" \
  python3 -c "import json, os, tempfile; p='$STATUS_FILE';\
last_success=os.environ.get('STATUS_LAST_SUCCESS_AT') or None;\
last_restart_at=os.environ.get('STATUS_LAST_RESTART_AT') or None;\
last_restart_result=os.environ.get('STATUS_LAST_RESTART_RESULT') or None;\
active=os.environ.get('STATUS_ACTIVE_KILL_SWITCHES','');\
d={'check_id':'$CHECK_ID','last_started_at':'$START_ISO','last_finished_at':'$end_iso','last_success_at':last_success,'exit_code':int($EXIT_CODE),'duration_ms':int($duration_ms),'status':'$STATUS_COLOR','consecutive_failures':int(${consecutive_failures:-0}),'last_restart_at':last_restart_at,'last_restart_result':last_restart_result,'restarts_this_hour':int(${restarts_this_hour:-0}),'active_kill_switches':[] if active=='' else active.split(',')};\
f=tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8', dir=os.path.dirname(p)); json.dump(d,f,indent=2,sort_keys=True); f.write('\\n'); f.close(); os.replace(f.name,p)"
}

check_kill_switch_staleness() {
  python3 -c "import json, datetime; ks=json.load(open('$KILL_SWITCH_FILE','r',encoding='utf-8')); st=json.load(open('$STATE_FILE','r',encoding='utf-8')); now=datetime.datetime.now(datetime.timezone.utc); reminders=st.get('kill_switch_reminders',{}); changed=False;\
for k,v in ks.items():\
  if not isinstance(v,dict) or not v.get('active') or not v.get('activated_at'): continue\
  activated=datetime.datetime.fromisoformat(str(v.get('activated_at')).replace('Z','+00:00'))\
  if (now-activated).total_seconds() < 43200: continue\
  last=reminders.get(k); send=True\
  if last:\
    last_dt=datetime.datetime.fromisoformat(str(last).replace('Z','+00:00')); send=(now-last_dt).total_seconds()>=43200\
  if send:\
    print(k)\
    reminders[k]=now.isoformat().replace('+00:00','Z'); changed=True\
if changed:\
  st['kill_switch_reminders']=reminders\
  import os,tempfile\
  p='$STATE_FILE'; f=tempfile.NamedTemporaryFile('w',delete=False,encoding='utf-8',dir=os.path.dirname(p)); json.dump(st,f,indent=2,sort_keys=True); f.write('\\n'); f.close(); os.replace(f.name,p)"
}

ensure_state_file
refresh_restart_window

preflight_service_user_check "root" >/dev/null || true

for stale_switch in $(check_kill_switch_staleness); do
  send_telegram "<b>Pulse reminder</b>%0AKill switch <code>${stale_switch}</code> has been active for over 12 hours. Please review and clear manually if appropriate."
done

http_ok=0
proc_ok=0
port_ok=0
failure_reasons=()

if http_health_check; then
  http_ok=1
else
  failure_reasons+=("http_health")
fi
if process_health_check; then
  proc_ok=1
else
  failure_reasons+=("process")
fi
if port_health_check; then
  port_ok=1
else
  failure_reasons+=("port_18789")
fi

if [ "$http_ok" -eq 1 ] && [ "$proc_ok" -eq 1 ] && [ "$port_ok" -eq 1 ]; then
  set_consecutive_failures 0
  set_last_success "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  STATUS_COLOR="green"
  EXIT_CODE=0
  append_recovery_log "pulse" "health_check" "healthy" "" "False"
  write_status_contract
  exit "$EXIT_CODE"
fi

current_failures="$(get_state_field consecutive_failures)"
if [ -z "$current_failures" ]; then
  current_failures=0
fi
current_failures="$((current_failures + 1))"
set_consecutive_failures "$current_failures"

STATUS_COLOR="yellow"
append_recovery_log "pulse" "health_check" "failed:${failure_reasons[*]}" "" "False"

if [ "$current_failures" -lt 3 ]; then
  EXIT_CODE=0
  write_status_contract
  exit "$EXIT_CODE"
fi

STATUS_COLOR="red"
restarts_this_hour="$(get_state_field restarts_this_hour)"
active_switches="$(get_active_kill_switches)"
heartbeat_active=0
if echo "$active_switches" | tr ',' '\n' | grep -q "^heartbeat_injection$"; then
  heartbeat_active=1
fi

action_taken="none"
kill_activated=""
escalated="True"

if [ "$heartbeat_active" -eq 1 ]; then
  action_taken="restart_skipped_kill_switch_active"
elif [ "${restarts_this_hour:-0}" -ge 1 ]; then
  action_taken="restart_skipped_hourly_cap"
  activate_kill_switch "heartbeat_injection" "restart cap reached with persistent gateway failures" "pulse-layer1"
  kill_activated="heartbeat_injection"
else
  if ! recent_session_write_check; then
    action_taken="restart_skipped_recent_session_writes"
  elif ! preflight_disk_space_check >/dev/null; then
    action_taken="restart_skipped_low_disk"
  else
    rm -rf /tmp/jiti/* 2>/dev/null || true
    append_recovery_log "pulse" "restart" "attempting" "" "False"
    if sudo -n systemctl restart "$SERVICE_NAME"; then
      sleep 30
      if http_health_check && journalctl -u "$SERVICE_NAME" --since "-5 min" 2>/dev/null | grep -Eiq "started|listen|gateway"; then
        record_restart "success"
        set_consecutive_failures 0
        set_last_success "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        action_taken="restart_success"
        append_recovery_log "pulse" "restart" "success" "" "True"
        send_telegram "<b>Pulse recovery successful</b>%0AStatus: recovered after ${current_failures} consecutive failures.%0AFailed checks: ${failure_reasons[*]}.%0AAction: restarted ${SERVICE_NAME}.%0AActive kill switches: ${active_switches:-none}.%0AAdam: monitor service logs and verify downstream automations."
        EXIT_CODE=0
        STATUS_COLOR="green"
        write_status_contract
        exit "$EXIT_CODE"
      fi
      record_restart "failed"
      action_taken="restart_failed_postcheck"
    else
      record_restart "failed"
      action_taken="restart_command_failed"
    fi
    activate_kill_switch "heartbeat_injection" "gateway unhealthy after bounded recovery" "pulse-layer1"
    kill_activated="heartbeat_injection"
  fi
fi

append_recovery_log "pulse" "escalation" "$action_taken" "$kill_activated" "$escalated"

active_switches="$(get_active_kill_switches)"
send_telegram "<b>Pulse gateway alert</b>%0AStatus: DOWN (red).%0AFailed checks: ${failure_reasons[*]}.%0AConsecutive failures: ${current_failures}.%0ARecovery action: ${action_taken}.%0AActive kill switches: ${active_switches:-none}.%0AAdam: check openclaw.service, inspect journalctl logs, verify gateway bind on :18789, and manually clear kill switches only after stable recovery."

EXIT_CODE=1
write_status_contract
exit "$EXIT_CODE"
