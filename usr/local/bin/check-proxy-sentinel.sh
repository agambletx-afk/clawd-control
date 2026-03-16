#!/usr/bin/env bash
set -euo pipefail

HEARTBEAT_ID="proxy-sentinel"
source /usr/local/bin/heartbeat-lib.sh

WORKSPACE="${HOME:-/home/openclaw}/.openclaw/workspace"
STATUS_FILE="${WORKSPACE}/proxy-sentinel-status.json"
TMP_FILE="${WORKSPACE}/.proxy-sentinel-status.tmp"
TG_SCRIPT="/usr/local/bin/send-to-telegram.sh"
API_URL="https://gw.dataimpulse.com:777/api/stats"
HISTORY_API_URL="https://gw.dataimpulse.com:777/api/stats_with_history"
TOTAL_BYTES="26843545600"
VPS_IP="161.35.136.216"
DAILY_SPIKE_WARN="0.5"
DAILY_SPIKE_CRIT="2.0"
SUCCESS_RATE_WARN="90"
SUCCESS_RATE_CRIT="75"
DRY_RUN="false"
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN="true"

mkdir -p "$WORKSPACE"

CHECKS_JSON=""
ALERTS_SENT="false"
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

add_check() {
  local name="$1" status="$2" detail="$3" threshold="$4"
  local entry
  entry=$(jq -n \
    --arg name "$name" \
    --arg status "$status" \
    --arg detail "$detail" \
    --arg threshold "$threshold" \
    '{($name): {status: $status, detail: $detail, threshold: $threshold}}')
  if [[ -z "$CHECKS_JSON" ]]; then
    CHECKS_JSON="$entry"
  else
    CHECKS_JSON=$(echo "$CHECKS_JSON $entry" | jq -s 'add')
  fi
}

is_gte() {
  awk -v a="$1" -v b="$2" 'BEGIN { exit (a+0 >= b+0 ? 0 : 1) }'
}

is_lt() {
  awk -v a="$1" -v b="$2" 'BEGIN { exit (a+0 < b+0 ? 0 : 1) }'
}

PROXY_CONFIGURED="true"
if [[ -z "${PROXY_USERNAME:-}" || -z "${PROXY_PASSWORD:-}" ]]; then
  PROXY_CONFIGURED="false"
fi

STATS_RESP=""
STATS_OK="false"
if [[ "$PROXY_CONFIGURED" == "true" ]]; then
  STATS_RESP="$(curl -sS --max-time 10 -u "${PROXY_USERNAME}:${PROXY_PASSWORD}" "$API_URL" || true)"
  if echo "$STATS_RESP" | jq -e '.status == "ok"' >/dev/null 2>&1; then
    STATS_OK="true"
  fi
fi

HISTORY_FROM="$(date -u +%Y-%m-%dT00:00:00Z)"
HISTORY_TO="$(date -u +%Y-%m-%dT23:59:59Z)"
HISTORY_RESP=""
HISTORY_OK="false"
if [[ "$PROXY_CONFIGURED" == "true" ]]; then
  HISTORY_RESP="$(curl -sS --max-time 10 -u "${PROXY_USERNAME}:${PROXY_PASSWORD}" "${HISTORY_API_URL}?group_type=day&from=${HISTORY_FROM}&to=${HISTORY_TO}" || true)"
  if echo "$HISTORY_RESP" | jq -e '.status == "ok" and (.traffic_history | type == "array")' >/dev/null 2>&1; then
    HISTORY_OK="true"
  fi
fi

# Check 1: Balance
BALANCE_STATUS="ok"
BALANCE_DETAIL=""
if [[ "$PROXY_CONFIGURED" != "true" ]]; then
  BALANCE_STATUS="error"
  BALANCE_DETAIL="Proxy credentials not configured"
else
  TRAFFIC_LEFT="$(echo "$STATS_RESP" | jq -r '.traffic_left // empty' 2>/dev/null || true)"
  TRAFFIC_USED="$(echo "$STATS_RESP" | jq -r '.traffic_used // 0' 2>/dev/null || echo 0)"
  if [[ "$STATS_OK" != "true" || -z "$TRAFFIC_LEFT" ]]; then
    BALANCE_STATUS="error"
    BALANCE_DETAIL="API unreachable or invalid payload"
  else
    REMAINING_GB="$(echo "scale=4; $TRAFFIC_LEFT/1073741824" | bc -l)"
    USED_PCT="$(echo "scale=2; ($TRAFFIC_USED/$TOTAL_BYTES)*100" | bc -l)"
    BALANCE_STATUS="ok"
    if is_lt "$REMAINING_GB" "0.25"; then
      BALANCE_STATUS="critical"
    elif is_lt "$REMAINING_GB" "1.0"; then
      BALANCE_STATUS="warn"
    fi
    BALANCE_DETAIL="${REMAINING_GB} GB remaining (${USED_PCT}% used)"
  fi
fi
add_check "balance" "$BALANCE_STATUS" "$BALANCE_DETAIL" "<1GB warn, <0.25GB critical"

# Check 2: Exit IP verification
EXIT_STATUS="warn"
EXIT_DETAIL="Proxy unreachable — could not verify exit IP"
if [[ "$PROXY_CONFIGURED" == "true" ]]; then
  set +e
  EXIT_IP="$(curl -s --max-time 10 -x "http://${PROXY_USERNAME}:${PROXY_PASSWORD}@gw.dataimpulse.com:823" https://api.ipify.org)"
  EXIT_RC=$?
  set -e

  if [[ "$EXIT_RC" -ne 0 ]]; then
    EXIT_STATUS="warn"
    EXIT_DETAIL="Proxy unreachable — could not verify exit IP"
  elif [[ -z "$EXIT_IP" || "$EXIT_IP" == "$VPS_IP" ]]; then
    EXIT_STATUS="critical"
    EXIT_DETAIL="Proxy not active — traffic using VPS IP (${VPS_IP})"
  else
    EXIT_STATUS="ok"
    EXIT_DETAIL="Exit IP: ${EXIT_IP} (residential)"
  fi
else
  EXIT_STATUS="warn"
  EXIT_DETAIL="Proxy credentials not configured — could not verify exit IP"
fi
add_check "proxy_exit_ip" "$EXIT_STATUS" "$EXIT_DETAIL" "must differ from ${VPS_IP}"

# Check 3: Daily spike detection
SPIKE_STATUS="warn"
SPIKE_DETAIL="Could not fetch daily traffic"
if [[ "$HISTORY_OK" == "true" ]]; then
  TOTAL_TRAFFIC_BYTES="$(echo "$HISTORY_RESP" | jq -r '[.traffic_history[]?.total_traffic // 0] | add // 0' 2>/dev/null || echo 0)"
  TODAY_GB="$(echo "scale=4; $TOTAL_TRAFFIC_BYTES/1073741824" | bc -l)"
  SPIKE_STATUS="ok"
  if is_gte "$TODAY_GB" "$DAILY_SPIKE_CRIT"; then
    SPIKE_STATUS="critical"
  elif is_gte "$TODAY_GB" "$DAILY_SPIKE_WARN"; then
    SPIKE_STATUS="warn"
  fi
  TODAY_GB_FMT="$(awk -v v="$TODAY_GB" 'BEGIN { printf "%.2f", v }')"
  SPIKE_DETAIL="Today: ${TODAY_GB_FMT} GB (warn: ${DAILY_SPIKE_WARN} GB, crit: ${DAILY_SPIKE_CRIT} GB)"
fi
add_check "daily_spike" "$SPIKE_STATUS" "$SPIKE_DETAIL" ">${DAILY_SPIKE_WARN}GB warn, >${DAILY_SPIKE_CRIT}GB critical"

# Check 4: API reachability (reuses /api/stats call)
API_STATUS="warn"
API_DETAIL="DataImpulse API unreachable — monitoring degraded"
if [[ "$STATS_OK" == "true" ]]; then
  API_STATUS="ok"
  API_DETAIL="DataImpulse API reachable"
fi
add_check "api_reachable" "$API_STATUS" "$API_DETAIL" "API status must be ok"

# Check 5: Success rate
SUCCESS_STATUS="warn"
SUCCESS_DETAIL="Could not fetch request success rate"
if [[ "$HISTORY_OK" == "true" ]]; then
  REQUESTS_COUNT="$(echo "$HISTORY_RESP" | jq -r '[.traffic_history[]?.requests_count // 0] | add // 0' 2>/dev/null || echo 0)"
  ERRORS_COUNT="$(echo "$HISTORY_RESP" | jq -r '[.traffic_history[]?.errors // 0] | add // 0' 2>/dev/null || echo 0)"

  if [[ "$REQUESTS_COUNT" -eq 0 ]]; then
    SUCCESS_STATUS="ok"
    SUCCESS_DETAIL="No requests in last 24h"
  else
    SUCCESS_PCT="$(awk -v req="$REQUESTS_COUNT" -v err="$ERRORS_COUNT" 'BEGIN { printf "%.1f", ((req-err)/req)*100 }')"
    SUCCESS_STATUS="ok"
    if is_lt "$SUCCESS_PCT" "$SUCCESS_RATE_CRIT"; then
      SUCCESS_STATUS="critical"
    elif is_lt "$SUCCESS_PCT" "$SUCCESS_RATE_WARN"; then
      SUCCESS_STATUS="warn"
    fi
    SUCCESS_DETAIL="${SUCCESS_PCT}% success (${REQUESTS_COUNT} requests, ${ERRORS_COUNT} errors)"
  fi
fi
add_check "success_rate" "$SUCCESS_STATUS" "$SUCCESS_DETAIL" "<${SUCCESS_RATE_WARN}% warn, <${SUCCESS_RATE_CRIT}% critical"

OVERALL="$(echo "$CHECKS_JSON" | jq -r '
  [to_entries[].value.status] as $s
  | if ($s | index("error")) then "error"
    elif ($s | index("critical")) then "critical"
    elif ($s | index("warn")) then "warn"
    else "ok" end
')"

if [[ "$OVERALL" != "ok" && "$DRY_RUN" != "true" && -x "$TG_SCRIPT" ]]; then
  ANOMALY_COUNT="$(echo "$CHECKS_JSON" | jq '[to_entries[] | select(.value.status == "warn" or .value.status == "critical" or .value.status == "error")] | length')"
  BALANCE_LINE="$(echo "$CHECKS_JSON" | jq -r '.balance | "- Balance: [\(.status)] (\(.detail))"')"
  EXIT_LINE="$(echo "$CHECKS_JSON" | jq -r '.proxy_exit_ip | "- Exit IP: [\(.status)] (\(.detail))"')"
  SPIKE_LINE="$(echo "$CHECKS_JSON" | jq -r '.daily_spike | "- Daily spike: [\(.status)] (\(.detail))"')"
  API_LINE="$(echo "$CHECKS_JSON" | jq -r '.api_reachable | "- API: [\(.status)]"')"
  SUCCESS_LINE="$(echo "$CHECKS_JSON" | jq -r '.success_rate | "- Success rate: [\(.status)] (\(.detail))"')"

  msg=$(cat <<MSG
🌐 Proxy Sentinel: ${ANOMALY_COUNT} anomaly(s) detected
${BALANCE_LINE}
${EXIT_LINE}
${SPIKE_LINE}
${API_LINE}
${SUCCESS_LINE}
MSG
)
  "$TG_SCRIPT" "$msg" >/dev/null 2>&1 || true
  ALERTS_SENT="true"
fi

jq -n \
  --arg ts "$TIMESTAMP" \
  --argjson checks "$CHECKS_JSON" \
  --arg overall "$OVERALL" \
  --arg alerts "$ALERTS_SENT" \
  '{timestamp:$ts,checks:$checks,overall:$overall,alerts_sent:($alerts=="true")}' > "$TMP_FILE"

mv -f "$TMP_FILE" "$STATUS_FILE"
heartbeat_finish
