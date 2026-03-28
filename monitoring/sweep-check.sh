#!/bin/bash

set -uo pipefail

WORKSPACE_PATH="/home/openclaw/.openclaw/workspace"
CHECKS_CONFIG_FILE="${WORKSPACE_PATH}"/health-checks.json
LAST_GOOD_FILE="${WORKSPACE_PATH}"/.health-checks-last-good.json
PULSE_CONFIG_FILE="${WORKSPACE_PATH}"/.pulse-config.json
KILL_SWITCH_FILE="${WORKSPACE_PATH}"/.kill-switches.json
RECOVERY_LOG_FILE="${WORKSPACE_PATH}"/.recovery-log.jsonl
SWEEP_STATUS_FILE="${WORKSPACE_PATH}"/sweep-status.json
HELPER_SCRIPT="${WORKSPACE_PATH}"/sweep-helpers.py

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=monitoring/preflight-checks.sh
source "${SCRIPT_DIR}/preflight-checks.sh"

START_EPOCH="$(date +%s)"
START_ISO="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
CHECK_ID="sweep-$(date -u +"%Y%m%dT%H%M%SZ")-$$"
EXIT_CODE=0

RESULTS_FILE="${WORKSPACE_PATH}"/.sweep-results.${CHECK_ID}.json
printf '[]\n' > "$RESULTS_FILE"
FAILURES=()

append_result() {
  local check_name="$1"
  local payload="$2"
  CHECK_NAME="$check_name" PAYLOAD_JSON="$payload" RESULTS_PATH="$RESULTS_FILE" python3 -c "import json, os, tempfile; p=os.environ['RESULTS_PATH']; arr=json.load(open(p,'r',encoding='utf-8')); arr.append({'check':os.environ['CHECK_NAME'],'result':json.loads(os.environ['PAYLOAD_JSON'])}); tmp=tempfile.NamedTemporaryFile('w',delete=False,encoding='utf-8',dir=os.path.dirname(p)); json.dump(arr,tmp,sort_keys=True); tmp.write('\\n'); tmp.close(); os.replace(tmp.name,p)"
}

append_recovery_log() {
  local action="$1"
  local result="$2"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  python3 -c "import json, os, tempfile; p='${RECOVERY_LOG_FILE}'; entry={'timestamp':'${ts}','check_id':'${CHECK_ID}','layer':'sweep','action':'${action}','result':'${result}'}; content='';\
if os.path.exists(p): content=open(p,'r',encoding='utf-8').read();\
f=tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8', dir=os.path.dirname(p)); f.write(content); f.write(json.dumps(entry, sort_keys=True)+'\\n'); f.close(); os.replace(f.name, p)"
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
  SWITCH_NAME="$switch_name" REASON="$reason" TS="$ts" python3 -c "import json, os, tempfile; p='${KILL_SWITCH_FILE}'; d=json.load(open(p,'r',encoding='utf-8')); s=d.get(os.environ['SWITCH_NAME'],{}); s['active']=True; s['reason']=os.environ['REASON']; s['activated_at']=os.environ['TS']; s['activated_by']='sweep-layer3'; d[os.environ['SWITCH_NAME']]=s; f=tempfile.NamedTemporaryFile('w',delete=False,encoding='utf-8',dir=os.path.dirname(p)); json.dump(d,f,indent=2,sort_keys=True); f.write('\\n'); f.close(); os.replace(f.name,p)"
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
  python3 -c "import json, os, datetime; cfg_path='${CHECKS_CONFIG_FILE}'; now=datetime.datetime.now(datetime.timezone.utc); defaults=[{'name':'watcher-status.json','path':'/home/openclaw/.openclaw/workspace' + '/watcher-status.json','fields':['generated_at'],'max_stale_minutes':90},{'name':'cost-sentinel-status.json','path':'/home/openclaw/.openclaw/workspace' + '/cost-sentinel-status.json','fields':['generated_at','last_success_at'],'max_stale_minutes':180},{'name':'cortex-sentinel-status.json','path':'/home/openclaw/.openclaw/workspace' + '/cortex-sentinel-status.json','fields':['generated_at','last_success_at'],'max_stale_minutes':180},{'name':'.pulse-state.json','path':'/home/openclaw/.openclaw/workspace' + '/.pulse-state.json','fields':['last_success_at'],'max_stale_minutes':10}]; checks=defaults;\
try:\
 data=json.load(open(cfg_path,'r',encoding='utf-8')); custom=((data.get('sweep_runner') or {}).get('cron_liveness') or None);\
 if isinstance(custom,list) and custom: checks=custom\
except Exception:\
 pass\
failures=[]; details=[]\
for chk in checks:\
 path=chk.get('path'); name=chk.get('name',path); fields=chk.get('fields',[]); limit=int(chk.get('max_stale_minutes',0));\
 if not path or not fields or limit<=0: failures.append(f'{name}:invalid-config'); continue\
 if not os.path.exists(path): failures.append(f'{name}:missing-file'); continue\
 try: payload=json.load(open(path,'r',encoding='utf-8'))\
 except Exception as exc: failures.append(f'{name}:parse-error:{exc}'); continue\
 stamp=None\
 for field in fields:\
  value=payload.get(field) if isinstance(payload,dict) else None\
  if value:\
   try: stamp=datetime.datetime.fromisoformat(str(value).replace('Z','+00:00')); break\
   except ValueError: pass\
 if stamp is None: failures.append(f'{name}:missing-timestamp'); continue\
 stale=(now-stamp).total_seconds()/60.0; details.append({'name':name,'stale_minutes':round(stale,2),'max_stale_minutes':limit});\
 if stale>limit: failures.append(f'{name}:stale:{int(stale)}m>{limit}m')\
status='alert' if failures else 'ok'; msg='cron liveness stale: ' + '; '.join(failures) if failures else 'cron liveness healthy'; print(json.dumps({'status':status,'message':msg,'failures':failures,'details':details}, sort_keys=True))"
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
  RESULTS_PATH="$RESULTS_FILE" python3 -c "import json, os, tempfile; p='${SWEEP_STATUS_FILE}'; results=json.load(open(os.environ['RESULTS_PATH'],'r',encoding='utf-8')); d={'check_id':'${CHECK_ID}','last_started_at':'${START_ISO}','last_finished_at':'${end_iso}','last_success_at':None if ${failure_count}>0 else '${end_iso}','exit_code':int(${EXIT_CODE}),'duration_ms':int(${duration_ms}),'status':'${status}','results':results}; f=tempfile.NamedTemporaryFile('w',delete=False,encoding='utf-8',dir=os.path.dirname(p)); json.dump(d,f,indent=2,sort_keys=True); f.write('\\n'); f.close(); os.replace(f.name,p)"
}

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

cron_result="$(check_cron_liveness)"
record_result "cron_liveness" "$cron_result"

token_result="$(run_helper_json token-anomaly)"
record_result "token_anomaly" "$token_result"
if TOKEN_PAYLOAD="$token_result" python3 -c "import json, os, sys; d=json.loads(os.environ['TOKEN_PAYLOAD']); sys.exit(0 if d.get('status')=='alert' else 1)"; then
  reason="$(TOKEN_PAYLOAD="$token_result" python3 -c "import json, os; d=json.loads(os.environ['TOKEN_PAYLOAD']); print(d.get('message','token anomaly detected'))")"
  activate_kill_switch "heartbeat_injection" "$reason"
fi

outbound_result="$(run_helper_json outbound-rate)"
record_result "outbound_rate" "$outbound_result"
if OUT_PAYLOAD="$outbound_result" python3 -c "import json, os, sys; d=json.loads(os.environ['OUT_PAYLOAD']); sys.exit(0 if d.get('status')=='alert' else 1)"; then
  reason="$(OUT_PAYLOAD="$outbound_result" python3 -c "import json, os; d=json.loads(os.environ['OUT_PAYLOAD']); print(d.get('message','outbound spike detected'))")"
  activate_kill_switch "outbound_telegram" "$reason"
fi

hash_result="$(run_helper_json file-hashes)"
record_result "critical_file_hashes" "$hash_result"

backup_result="$(run_helper_json backup-critical-files)"
record_result "critical_file_backups" "$backup_result"

write_status_contract
rm -f "$RESULTS_FILE"

if [ "${#FAILURES[@]}" -gt 0 ]; then
  summary="$(printf '%s; ' "${FAILURES[@]}")"
  send_telegram "<b>Layer 3 sweep alert</b>%0AStatus: FAIL%0ACheck ID: <code>${CHECK_ID}</code>%0AFailures: ${summary}%0AAction: review sweep-status.json and recovery log."
  append_recovery_log "sweep" "alert_sent"
else
  append_recovery_log "sweep" "ok"
fi

exit "${EXIT_CODE}"
