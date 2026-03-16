#!/usr/bin/env bash
set -euo pipefail

HEARTBEAT_ID="proxy-sentinel"
source /usr/local/bin/heartbeat-lib.sh

WORKSPACE="${HOME:-/home/openclaw}/.openclaw/workspace"
STATUS_FILE="${WORKSPACE}/proxy-sentinel-status.json"
TMP_FILE="${WORKSPACE}/.proxy-sentinel-status.tmp"
TG_SCRIPT="/usr/local/bin/send-to-telegram.sh"
API_URL="https://gw.dataimpulse.com:777/api/stats"
TOTAL_BYTES="26843545600"
DRY_RUN="false"
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN="true"

mkdir -p "$WORKSPACE"

if [[ -z "${PROXY_USERNAME:-}" || -z "${PROXY_PASSWORD:-}" ]]; then
  jq -n --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" '{timestamp:$ts,checks:{balance:{status:"error",detail:"Proxy credentials not configured",threshold:"<1GB warn, <0.25GB critical"}},overall:"error",alerts_sent:false}' > "$TMP_FILE"
  mv -f "$TMP_FILE" "$STATUS_FILE"
  heartbeat_finish
  exit 0
fi

resp="$(curl -sS --max-time 10 -u "${PROXY_USERNAME}:${PROXY_PASSWORD}" "$API_URL" || true)"
traffic_left="$(echo "$resp" | jq -r '.traffic_left // empty' 2>/dev/null || true)"
traffic_used="$(echo "$resp" | jq -r '.traffic_used // 0' 2>/dev/null || echo 0)"

if [[ -z "$traffic_left" ]]; then
  jq -n --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" --arg detail "API unreachable or invalid payload" '{timestamp:$ts,checks:{balance:{status:"error",detail:$detail,threshold:"<1GB warn, <0.25GB critical"}},overall:"error",alerts_sent:false}' > "$TMP_FILE"
  mv -f "$TMP_FILE" "$STATUS_FILE"
  heartbeat_finish
  exit 0
fi

remaining_gb="$(echo "scale=4; $traffic_left/1073741824" | bc -l)"
used_pct="$(echo "scale=2; ($traffic_used/$TOTAL_BYTES)*100" | bc -l)"
status="ok"
if awk -v v="$remaining_gb" 'BEGIN{exit !(v<0.25)}'; then
  status="critical"
elif awk -v v="$remaining_gb" 'BEGIN{exit !(v<1.0)}'; then
  status="warn"
fi

detail="${remaining_gb} GB remaining (${used_pct}% used)"
alerts_sent="false"

if [[ "$status" != "ok" && "$DRY_RUN" != "true" && -x "$TG_SCRIPT" ]]; then
  msg="⚠️ Proxy Sentinel ${status^^}: ${detail}"
  "$TG_SCRIPT" "$msg" >/dev/null 2>&1 || true
  alerts_sent="true"
fi

jq -n \
  --arg ts "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg status "$status" \
  --arg detail "$detail" \
  --arg alerts "$alerts_sent" \
  '{timestamp:$ts,checks:{balance:{status:$status,detail:$detail,threshold:"<1GB warn, <0.25GB critical"}},overall:$status,alerts_sent:($alerts=="true")}' > "$TMP_FILE"

mv -f "$TMP_FILE" "$STATUS_FILE"
heartbeat_finish
