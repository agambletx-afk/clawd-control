#!/bin/bash

set -uo pipefail

WORKSPACE_PATH="/home/openclaw/.openclaw/workspace"
PULSE_CONFIG_FILE="${WORKSPACE_PATH}/.pulse-config.json"
AUDIT_STATUS_FILE="${WORKSPACE_PATH}/audit-status.json"
HELPER_SCRIPT="${WORKSPACE_PATH}/audit-helpers.py"

source "${WORKSPACE_PATH}/preflight-checks.sh"

START_EPOCH="$(date +%s)"
START_ISO="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
CHECK_ID="audit-$(date -u +"%Y%m%dT%H%M%SZ")-$$"
EXIT_CODE=0

RESULTS_FILE="${WORKSPACE_PATH}/.audit-results.${CHECK_ID}.json"
printf '[]\n' > "$RESULTS_FILE"
FAILURES=()

append_result() {
  local check_name="$1"
  local payload_file="$2"
  python3 -c "
import json, os, tempfile
p = '${RESULTS_FILE}'
arr = json.load(open(p, 'r', encoding='utf-8'))
result = json.load(open('${payload_file}', 'r', encoding='utf-8'))
arr.append({'check': '${check_name}', 'result': result})
tmp = tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8', dir=os.path.dirname(p))
json.dump(arr, tmp, sort_keys=True)
tmp.write(chr(10))
tmp.close()
os.replace(tmp.name, p)
"
}

record_result() {
  local check_name="$1"
  local payload_file="$2"
  local status message
  append_result "$check_name" "$payload_file"
  status="$(python3 -c "import json; d=json.load(open('${payload_file}')); print(d.get('status','alert'))")"
  message="$(python3 -c "import json; d=json.load(open('${payload_file}')); print(d.get('message','alert'))")"
  if [ "$status" = "alert" ]; then
    FAILURES+=("${check_name}: ${message}")
    EXIT_CODE=1
  fi
}

send_telegram() {
  local message="$1"
  local token chat_id
  token="$(python3 -c "import json; d=json.load(open('${PULSE_CONFIG_FILE}','r',encoding='utf-8')); print(d.get('telegram_bot_token',''))" 2>/dev/null || echo "")"
  chat_id="$(python3 -c "import json; d=json.load(open('${PULSE_CONFIG_FILE}','r',encoding='utf-8')); print(d.get('telegram_chat_id',''))" 2>/dev/null || echo "")"
  if [ -z "$token" ] || [ -z "$chat_id" ]; then
    return 1
  fi
  curl -sS -X POST "https://api.telegram.org/bot${token}/sendMessage" -d chat_id="$chat_id" -d text="$message" -d parse_mode="HTML" >/dev/null 2>&1 || true
  return 0
}

write_status_contract() {
  local end_iso duration_ms status
  end_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  duration_ms="$(( ( $(date +%s) - START_EPOCH ) * 1000 ))"
  status="green"
  if [ "${#FAILURES[@]}" -gt 0 ]; then
    status="red"
  fi
  python3 -c "
import json, os, tempfile
p = '${AUDIT_STATUS_FILE}'
results = json.load(open('${RESULTS_FILE}', 'r', encoding='utf-8'))
success_at = None if int(${EXIT_CODE}) != 0 else '${end_iso}'
d = {
    'check_id': '${CHECK_ID}',
    'last_started_at': '${START_ISO}',
    'last_finished_at': '${end_iso}',
    'last_success_at': success_at,
    'exit_code': int(${EXIT_CODE}),
    'duration_ms': int(${duration_ms}),
    'status': '${status}',
    'results': results,
}
f = tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8', dir=os.path.dirname(p))
json.dump(d, f, indent=2, sort_keys=True)
f.write(chr(10))
f.close()
os.replace(f.name, p)
"
}

run_check() {
  local check_name="$1"
  local subcommand="$2"
  local payload_file="${WORKSPACE_PATH}/.audit-payload.${CHECK_ID}.${check_name}.json"
  python3 "${HELPER_SCRIPT}" "$subcommand" > "$payload_file"
  record_result "$check_name" "$payload_file"
  rm -f "$payload_file"
}

# --- Main execution ---

if ! preflight_workspace_writable_check >/dev/null; then
  send_telegram "<b>Layer 4 audit alert</b>%0AWorkspace is not writable at <code>${WORKSPACE_PATH}</code>. Audit aborted."
  rm -f "$RESULTS_FILE"
  exit 1
fi

preflight_disk_space_check >/dev/null || true
preflight_config_parseable_check >/dev/null || true

run_check "runtime_repo_drift" "drift-detection"
run_check "storage_health" "storage-health"
run_check "monitor_the_monitors" "monitor-the-monitors"
run_check "critical_backup_rotation" "backup-rotation"

write_status_contract

if [ "${#FAILURES[@]}" -eq 0 ]; then
  send_telegram "<b>Layer 4 daily audit</b>%0AStatus: OK%0ACheck ID: <code>${CHECK_ID}</code>%0ADaily audit: all clear."
else
  summary="$(printf '%s; ' "${FAILURES[@]}")"
  send_telegram "<b>Layer 4 daily audit</b>%0AStatus: ALERT%0ACheck ID: <code>${CHECK_ID}</code>%0AIssues: ${summary}%0AAction: review <code>audit-status.json</code>."
fi

rm -f "$RESULTS_FILE"
exit "$EXIT_CODE"
