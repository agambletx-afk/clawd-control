#!/bin/bash

set -uo pipefail
umask 0002

WORKSPACE_PATH="/home/openclaw/.openclaw/workspace"
CHECKS_CONFIG_FILE="${WORKSPACE_PATH}/health-checks.json"
LAST_GOOD_FILE="${WORKSPACE_PATH}/.health-checks-last-good.json"
PULSE_CONFIG_FILE="${WORKSPACE_PATH}/.pulse-config.json"
KILL_SWITCH_FILE="${WORKSPACE_PATH}/.kill-switches.json"
RECOVERY_LOG_FILE="${WORKSPACE_PATH}/.recovery-log.jsonl"
SWEEP_STATUS_FILE="${WORKSPACE_PATH}/sweep-status.json"
HELPER_SCRIPT="${WORKSPACE_PATH}/sweep-helpers.py"

source "${WORKSPACE_PATH}/preflight-checks.sh"

START_EPOCH="$(date +%s)"
START_ISO="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
CHECK_ID="sweep-$(date -u +"%Y%m%dT%H%M%SZ")-$$"
EXIT_CODE=0

RESULTS_FILE="${WORKSPACE_PATH}/.sweep-results.${CHECK_ID}.json"
printf '[]\n' > "$RESULTS_FILE"
FAILURES=()

append_result() {
  local check_name="$1"
  local payload="$2"
  CHECK_NAME="$check_name" PAYLOAD_JSON="$payload" RESULTS_PATH="$RESULTS_FILE" python3 -c "import json, os, tempfile; p=os.environ['RESULTS_PATH']; arr=json.load(open(p,'r',encoding='utf-8')); arr.append({'check':os.environ['CHECK_NAME'],'result':json.loads(os.environ['PAYLOAD_JSON'])}); tmp=tempfile.NamedTemporaryFile('w',delete=False,encoding='utf-8',dir=os.path.dirname(p)); json.dump(arr,tmp,sort_keys=True); tmp.write(chr(10)); tmp.close(); os.replace(tmp.name,p)"
}

append_recovery_log() {
  local action="$1"
  local result="$2"
  python3 "${HELPER_SCRIPT}" append-recovery-log "${CHECK_ID}" "sweep" "$action" "$result"
}

send_telegram() {
  local message="$1"
  local token chat_id
  token="$(python3 -c "import json; d=json.load(open('${PULSE_CONFIG_FILE}','r',encoding='utf-8')); print(d.get('telegram_bot_token',''))" 2>/dev/null || echo "")"
  chat_id="$(python3 -c "import json; d=json.load(open('${PULSE_CONFIG_FILE}','r',encoding='utf-8')); print(d.get('telegram_chat_id',''))" 2>/dev/null || echo "")"
  if [ -z "$token" ] || [ -z "$chat_id" ]; then
    append_recovery_log "telegram_send" "skipped_missing_credentials"
    return 1
  fi
  curl -sS -X POST "https://api.telegram.org/bot${token}/sendMessage" -d chat_id="$chat_id" -d text="$message" -d parse_mode="HTML" >/dev/null 2>&1 || true
  return 0
}

activate_kill_switch() {
  local switch_name="$1"
  local reason="$2"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  SWITCH_NAME="$switch_name" REASON="$reason" TS="$ts" python3 -c "import json, os, tempfile; p='${KILL_SWITCH_FILE}'; d=json.load(open(p,'r',encoding='utf-8')); s=d.get(os.environ['SWITCH_NAME'],{}); s['active']=True; s['reason']=os.environ['REASON']; s['activated_at']=os.environ['TS']; s['activated_by']='sweep-layer3'; d[os.environ['SWITCH_NAME']]=s; f=tempfile.NamedTemporaryFile('w',delete=False,encoding='utf-8',dir=os.path.dirname(p)); json.dump(d,f,indent=2,sort_keys=True); f.write(chr(10)); f.close(); os.replace(f.name,p)"
}

snapshot_config() {
  local tmp_file
  tmp_file="${LAST_GOOD_FILE}.tmp.$$"
  if cp "${CHECKS_CONFIG_FILE}" "$tmp_file" 2>/dev/null && mv "$tmp_file" "${LAST_GOOD_FILE}"; then
    return 0
  fi
  rm -f "$tmp_file"
  return 1
}

check_cron_liveness() {
  python3 "${HELPER_SCRIPT}" cron-liveness
}

run_helper_json() {
  local subcmd="$1"
  python3 "${HELPER_SCRIPT}" "$subcmd"
}

record_result() {
  local check_name="$1"
  local payload="$2"
  local status message
  append_result "$check_name" "$payload"
  status="$(PAYLOAD_JSON="$payload" python3 -c "import json, os; d=json.loads(os.environ['PAYLOAD_JSON']); print(d.get('status','alert'))")"
  message="$(PAYLOAD_JSON="$payload" python3 -c "import json, os; d=json.loads(os.environ['PAYLOAD_JSON']); print(d.get('message',''))")"
  if [ "$status" = "alert" ]; then
    FAILURES+=("${check_name}: ${message}")
    EXIT_CODE=1
  fi
}

write_status_contract() {
  local end_iso duration_ms status failure_count
  end_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  duration_ms="$(( ( $(date +%s) - START_EPOCH ) * 1000 ))"
  failure_count="${#FAILURES[@]}"
  if [ "$failure_count" -gt 0 ]; then
    status="red"
  else
    status="green"
  fi
  RESULTS_PATH="$RESULTS_FILE" STATUS_VAL="$status" python3 -c "import json, os, tempfile; p='${SWEEP_STATUS_FILE}'; results=json.load(open(os.environ['RESULTS_PATH'],'r',encoding='utf-8')); success_at=None if int(${failure_count})>0 else '${end_iso}'; d={'check_id':'${CHECK_ID}','last_started_at':'${START_ISO}','last_finished_at':'${end_iso}','last_success_at':success_at,'exit_code':int(${EXIT_CODE}),'duration_ms':int(${duration_ms}),'status':os.environ['STATUS_VAL'],'results':results}; f=tempfile.NamedTemporaryFile('w',delete=False,encoding='utf-8',dir=os.path.dirname(p)); json.dump(d,f,indent=2,sort_keys=True); f.write(chr(10)); f.close(); os.replace(f.name,p)"
}

# --- Main execution ---

if ! preflight_workspace_writable_check >/dev/null; then
  send_telegram "<b>Layer 3 sweep alert</b>%0AWorkspace is not writable at <code>${WORKSPACE_PATH}</code>. Sweep aborted."
  rm -f "$RESULTS_FILE"
  exit 1
fi

preflight_disk_space_check >/dev/null || append_recovery_log "preflight" "warn_disk_space"
preflight_config_parseable_check >/dev/null || append_recovery_log "preflight" "warn_config_parse"

if ! snapshot_config; then
  append_recovery_log "snapshot" "failed"
fi

# Check A: Cron Liveness
cron_result="$(check_cron_liveness)"
record_result "cron_liveness" "$cron_result"

# Check B: Token Anomaly
token_result="$(run_helper_json token-anomaly)"
record_result "token_anomaly" "$token_result"
if TOKEN_PAYLOAD="$token_result" python3 -c "import json, os, sys; d=json.loads(os.environ['TOKEN_PAYLOAD']); sys.exit(0 if d.get('status')=='alert' else 1)"; then
  reason="$(TOKEN_PAYLOAD="$token_result" python3 -c "import json, os; d=json.loads(os.environ['TOKEN_PAYLOAD']); print(d.get('message','token anomaly detected'))")"
  activate_kill_switch "heartbeat_injection" "$reason"
fi

# Check C: Outbound Rate
outbound_result='{"status":"ok","message":"outbound rate check disabled (getUpdates 409 conflict)","message_count":0}'  # TODO: re-enable with in-gateway ledger
record_result "outbound_rate" "$outbound_result"
if OUT_PAYLOAD="$outbound_result" python3 -c "import json, os, sys; d=json.loads(os.environ['OUT_PAYLOAD']); sys.exit(0 if d.get('status')=='alert' else 1)"; then
  reason="$(OUT_PAYLOAD="$outbound_result" python3 -c "import json, os; d=json.loads(os.environ['OUT_PAYLOAD']); print(d.get('message','outbound spike detected'))")"
  activate_kill_switch "outbound_telegram" "$reason"
fi

# Check D: File Hashes
hash_result="$(run_helper_json file-hashes)"
record_result "critical_file_hashes" "$hash_result"

# Check E: File Backups
backup_result="$(run_helper_json backup-critical-files)"
record_result "critical_file_backups" "$backup_result"

# Write status and alert
write_status_contract
rm -f "$RESULTS_FILE"

if [ "${#FAILURES[@]}" -gt 0 ]; then
  summary="$(printf '%s; ' "${FAILURES[@]}")"
  send_telegram "<b>Layer 3 sweep alert</b>%0AStatus: FAIL%0ACheck ID: <code>${CHECK_ID}</code>%0AFailures: ${summary}%0AAction: review sweep-status.json and recovery log."
  append_recovery_log "sweep" "alert_sent"
fi

exit "${EXIT_CODE}"
chown openclaw:openclaw "${SWEEP_STATUS_FILE}" 2>/dev/null || true
