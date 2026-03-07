#!/bin/bash
set -euo pipefail

API_URL="http://localhost:3100/api/tasks/stale"
COOLDOWN_FILE="/home/openclaw/logs/delegation-sweep-cooldown.json"
LOG_FILE="/home/openclaw/logs/delegation-sweep.log"
COOLDOWN_SECONDS=$((6 * 3600))
NOW_EPOCH=$(date -u +%s)
NOW_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

mkdir -p "$(dirname "$COOLDOWN_FILE")"
mkdir -p "$(dirname "$LOG_FILE")"

if [[ ! -f "$COOLDOWN_FILE" ]]; then
  echo '{}' > "$COOLDOWN_FILE"
fi

if ! jq -e 'type == "object"' "$COOLDOWN_FILE" >/dev/null 2>&1; then
  echo '{}' > "$COOLDOWN_FILE"
fi

API_RESPONSE=$(curl -fsS --max-time 4 --connect-timeout 2 "$API_URL") || {
  echo "stale delegation sweep: api request failed" >&2
  exit 1
}

if ! jq -e '.stale and (.stale | type == "array")' >/dev/null 2>&1 <<<"$API_RESPONSE"; then
  echo "stale delegation sweep: invalid API response" >&2
  exit 1
fi

COOLDOWN_DATA=$(cat "$COOLDOWN_FILE")
ACTIONABLE='[]'
SKIPPED='[]'
UPDATED_COOLDOWN="$COOLDOWN_DATA"

while IFS= read -r task; do
  TASK_ID=$(jq -r '.id' <<<"$task")
  AGENT=$(jq -r '.assignedTo // "unassigned"' <<<"$task")
  HOURS=$(jq -r '.hoursSinceUpdate // 0' <<<"$task")
  SEVERITY=$(jq -r '.severity // "soft"' <<<"$task")

  LAST_NUDGE=$(jq -r --arg id "$TASK_ID" '.[$id].last_nudge_epoch // 0' <<<"$COOLDOWN_DATA")
  if [[ "$LAST_NUDGE" =~ ^[0-9]+$ ]] && (( LAST_NUDGE > 0 )) && (( NOW_EPOCH - LAST_NUDGE < COOLDOWN_SECONDS )); then
    REMAINING=$((COOLDOWN_SECONDS - (NOW_EPOCH - LAST_NUDGE)))
    SKIPPED=$(jq --argjson task "$task" --arg reason "cooldown_active" --argjson remaining "$REMAINING" \
      '. + [{task:$task,reason:$reason,cooldownRemainingSeconds:$remaining}]' <<<"$SKIPPED")
    continue
  fi

  ACTION=$([[ "$SEVERITY" == "hard" ]] && echo "NUDGE_HARD" || echo "NUDGE_SOFT")
  echo "[$NOW_ISO] [$TASK_ID] [$AGENT] [$HOURS] [$ACTION]" >> "$LOG_FILE"

  UPDATED_COOLDOWN=$(jq --arg id "$TASK_ID" --arg agent "$AGENT" --arg iso "$NOW_ISO" --argjson now "$NOW_EPOCH" \
    '.[$id] = {agent:$agent,last_nudge_at:$iso,last_nudge_epoch:$now}' <<<"$UPDATED_COOLDOWN")

  ACTIONABLE=$(jq --argjson task "$task" --arg action "$ACTION" --argjson now "$NOW_EPOCH" \
    '. + [{task:$task,triage:{action:$action,sweptAtEpoch:$now}}]' <<<"$ACTIONABLE")
done < <(jq -c '.stale[]' <<<"$API_RESPONSE")

echo "$UPDATED_COOLDOWN" > "$COOLDOWN_FILE"

SUMMARY=$(jq -n --argjson actionable "$ACTIONABLE" --argjson skipped "$SKIPPED" '
  {
    actionable: ($actionable | length),
    skipped: ($skipped | length),
    totalStale: (($actionable | length) + ($skipped | length)),
    softActionable: ($actionable | map(select(.task.severity == "soft")) | length),
    hardActionable: ($actionable | map(select(.task.severity == "hard")) | length)
  }
')

REPORT=$(jq -n \
  --arg generatedAt "$NOW_ISO" \
  --argjson stale "$ACTIONABLE" \
  --argjson skipped "$SKIPPED" \
  --argjson summary "$SUMMARY" \
  '{generatedAt:$generatedAt,stale:$stale,skipped:$skipped,summary:$summary}')

echo "$REPORT"

ACTIONABLE_COUNT=$(jq -r '.summary.actionable' <<<"$REPORT")
if [[ "$ACTIONABLE_COUNT" == "0" ]]; then
  echo "HEARTBEAT_OK"
fi

exit 0
