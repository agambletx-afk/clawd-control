#!/usr/bin/env bash
# =============================================================================
# Cost Sentinel - Zero-token cost anomaly detection
# =============================================================================
# Location: /usr/local/bin/check-cost-sentinel.sh
# Schedule: 0 6 * * * openclaw (daily at 06:00 UTC / midnight CST)
# Output:   ~/.openclaw/workspace/cost-sentinel-status.json
# Alerts:   Telegram on threshold breach
# Version:  1.0
# Date:     2026-03-08
# Brief:    BRIEF-CST-Cost-Sentinel.md
# =============================================================================
# Dependencies: curl, jq, bc (all pre-installed on VPS)
# Runs as: openclaw user
# Token cost: Zero. Pure bash + jq. No LLM calls.
# =============================================================================

set -euo pipefail

HEARTBEAT_ID="cost-sentinel"
source /usr/local/bin/heartbeat-lib.sh

# ---------------------------------------------------------------------------
# Thresholds - tune after 2 weeks of data
# ---------------------------------------------------------------------------
AGENT_CONCENTRATION_WARN=70    # percent
AGENT_CONCENTRATION_CRIT=85    # percent
DAILY_BUDGET_WARN=1.00         # dollars
DAILY_BUDGET_CRIT=2.00         # dollars
SESSION_VOLUME_WARN=30         # sessions per agent per day
SESSION_VOLUME_CRIT=50         # sessions per agent per day
WEEKLY_TREND_MULTIPLIER=2.0    # x daily average
ALERT_COOLDOWN_HOURS=24        # hours between repeat alerts

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
WORKSPACE="${HOME}/.openclaw/workspace"
STATUS_FILE="${WORKSPACE}/cost-sentinel-status.json"
STATUS_TMP="${WORKSPACE}/.cost-sentinel-status.tmp"
LAST_ALERT_FILE="${WORKSPACE}/cost-sentinel-last-alert.json"
ENV_FILE="/opt/openclaw.env"

# ---------------------------------------------------------------------------
# Telegram credentials (env vars > openclaw.env > skip)
# ---------------------------------------------------------------------------
if [[ -f "${ENV_FILE}" ]]; then
    # shellcheck source=/dev/null
    set +u; source "${ENV_FILE}"; set -u
fi
TG_TOKEN="${COST_SENTINEL_TG_TOKEN:-${TELEGRAM_BOT_TOKEN:-}}"
TG_CHAT="${COST_SENTINEL_TG_CHAT:-${TELEGRAM_CHAT_ID:-}}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
ALERTS=()
CHECKS_JSON=""

log_err() { echo "[cost-sentinel] $*" >&2; }

# Append a check result to CHECKS_JSON
# Usage: add_check "name" "status" "detail" "threshold"
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

# Float comparison: returns 0 if $1 > $2
float_gt() {
    echo "$1 > $2" | bc -l | grep -q '^1'
}

# Float comparison: returns 0 if $1 >= $2
float_gte() {
    echo "$1 >= $2" | bc -l | grep -q '^1'
}

# ---------------------------------------------------------------------------
# Ensure workspace exists
# ---------------------------------------------------------------------------
mkdir -p "${WORKSPACE}"

# ---------------------------------------------------------------------------
# Fetch analytics data
# ---------------------------------------------------------------------------
DAILY_DATA=""
WEEKLY_DATA=""
API_BASE="http://localhost:3100/api/analytics"

DAILY_DATA=$(curl -sf --max-time 15 "${API_BASE}?range=1" 2>/dev/null) || true
WEEKLY_DATA=$(curl -sf --max-time 15 "${API_BASE}?range=7" 2>/dev/null) || true

if [[ -z "$DAILY_DATA" ]]; then
    add_check "api_status" "red" "Analytics API unreachable (daily)" "reachable"
    # Write status and exit - can't run checks without data
    jq -n \
        --arg ts "$TIMESTAMP" \
        --argjson checks "$CHECKS_JSON" \
        '{timestamp: $ts, checks: $checks, overall: "red", alerts_sent: false, error: "api_unreachable"}' \
        > "$STATUS_TMP"
    mv -f "$STATUS_TMP" "$STATUS_FILE"
    log_err "Analytics API unreachable. Status written. Exiting."
    exit 0
fi

# ---------------------------------------------------------------------------
# Check 1: Agent Spend Concentration
# ---------------------------------------------------------------------------
TOTAL_COST=$(echo "$DAILY_DATA" | jq -r '.totalCost // 0')
BY_AGENT=$(echo "$DAILY_DATA" | jq -c '.byAgent // []')
AGENT_COUNT=$(echo "$BY_AGENT" | jq 'length')

CHECK1_STATUS="ok"
CHECK1_DETAIL="No single agent dominates spend"
CHECK1_THRESHOLD="${AGENT_CONCENTRATION_WARN}%"

if [[ "$AGENT_COUNT" -gt 0 ]] && float_gt "$TOTAL_COST" "0"; then
    TOP_AGENT_ID=$(echo "$BY_AGENT" | jq -r '.[0].agentId // "unknown"')
    TOP_AGENT_COST=$(echo "$BY_AGENT" | jq -r '.[0].cost // 0')
    # Calculate percentage: (agent_cost / total_cost) * 100
    AGENT_PCT=$(echo "scale=1; ($TOP_AGENT_COST / $TOTAL_COST) * 100" | bc)

    if float_gte "$AGENT_PCT" "$AGENT_CONCENTRATION_CRIT"; then
        CHECK1_STATUS="critical"
        CHECK1_DETAIL="${TOP_AGENT_ID}: ${AGENT_PCT}% of total spend (\$${TOP_AGENT_COST} / \$${TOTAL_COST})"
        ALERTS+=("🔴 Agent Concentration: ${TOP_AGENT_ID} at ${AGENT_PCT}% of spend (\$${TOP_AGENT_COST})")
    elif float_gte "$AGENT_PCT" "$AGENT_CONCENTRATION_WARN"; then
        CHECK1_STATUS="warn"
        CHECK1_DETAIL="${TOP_AGENT_ID}: ${AGENT_PCT}% of total spend (\$${TOP_AGENT_COST} / \$${TOTAL_COST})"
        ALERTS+=("🟡 Agent Concentration: ${TOP_AGENT_ID} at ${AGENT_PCT}% of spend (\$${TOP_AGENT_COST})")
    else
        CHECK1_DETAIL="${TOP_AGENT_ID}: ${AGENT_PCT}% of total spend"
    fi
fi

add_check "agent_concentration" "$CHECK1_STATUS" "$CHECK1_DETAIL" "$CHECK1_THRESHOLD"

# ---------------------------------------------------------------------------
# Check 2: Daily Budget Threshold
# ---------------------------------------------------------------------------
CHECK2_STATUS="ok"
CHECK2_DETAIL="\$${TOTAL_COST} daily spend"
CHECK2_THRESHOLD="\$${DAILY_BUDGET_WARN}"

if float_gte "$TOTAL_COST" "$DAILY_BUDGET_CRIT"; then
    CHECK2_STATUS="critical"
    CHECK2_DETAIL="\$${TOTAL_COST} daily spend exceeds \$${DAILY_BUDGET_CRIT} critical threshold"
    ALERTS+=("🔴 Daily Budget: \$${TOTAL_COST} exceeds \$${DAILY_BUDGET_CRIT} critical threshold")
elif float_gte "$TOTAL_COST" "$DAILY_BUDGET_WARN"; then
    CHECK2_STATUS="warn"
    CHECK2_DETAIL="\$${TOTAL_COST} daily spend exceeds \$${DAILY_BUDGET_WARN} warn threshold"
    ALERTS+=("🟡 Daily Budget: \$${TOTAL_COST} exceeds \$${DAILY_BUDGET_WARN} warn threshold")
fi

add_check "daily_budget" "$CHECK2_STATUS" "$CHECK2_DETAIL" "$CHECK2_THRESHOLD"

# ---------------------------------------------------------------------------
# Check 3: Cron Error Loop Detection
# ---------------------------------------------------------------------------
CHECK3_STATUS="ok"
CHECK3_DETAIL="No cron error loops detected"
CHECK3_THRESHOLD="> 0 errors on enabled job"

# openclaw cron list requires gateway RPC - may fail if gateway is down
CRON_JSON=""
if [[ "$(whoami)" == "openclaw" ]]; then
    CRON_JSON=$(timeout 15 openclaw cron list --all --json 2>/dev/null | grep -v '^\[') || true
else
    CRON_JSON=$(timeout 15 sudo -u openclaw openclaw cron list --all --json 2>/dev/null | grep -v '^\[') || true
fi

if [[ -n "$CRON_JSON" ]]; then
    # Parse each job looking for enabled jobs with consecutive errors
    ERROR_JOBS=$(echo "$CRON_JSON" | jq -c '[.[] | select(.enabled == true and (.consecutiveErrors // 0) > 0)]' 2>/dev/null) || true

    if [[ -n "$ERROR_JOBS" ]]; then
        ERROR_COUNT=$(echo "$ERROR_JOBS" | jq 'length')
        if [[ "$ERROR_COUNT" -gt 0 ]]; then
            CHECK3_STATUS="critical"
            # Build detail string from all erroring jobs
            DETAIL_PARTS=""
            for i in $(seq 0 $((ERROR_COUNT - 1))); do
                JOB_NAME=$(echo "$ERROR_JOBS" | jq -r ".[$i].name // .[$i].id // \"unknown\"")
                JOB_ERRORS=$(echo "$ERROR_JOBS" | jq -r ".[$i].consecutiveErrors // 0")
                if [[ -n "$DETAIL_PARTS" ]]; then
                    DETAIL_PARTS="${DETAIL_PARTS}; "
                fi
                DETAIL_PARTS="${DETAIL_PARTS}${JOB_NAME}: ${JOB_ERRORS} consecutive errors, still enabled"
                ALERTS+=("🔴 Cron Error Loop: ${JOB_NAME} has ${JOB_ERRORS} consecutive errors")
            done
            CHECK3_DETAIL="$DETAIL_PARTS"
        fi
    fi
else
    CHECK3_STATUS="skip"
    CHECK3_DETAIL="Could not query openclaw cron list (gateway may be down)"
fi

add_check "cron_error_loop" "$CHECK3_STATUS" "$CHECK3_DETAIL" "$CHECK3_THRESHOLD"

# ---------------------------------------------------------------------------
# Check 4: Session Volume Anomaly
# ---------------------------------------------------------------------------
CHECK4_STATUS="ok"
CHECK4_DETAIL="Session volumes normal"
CHECK4_THRESHOLD="${SESSION_VOLUME_WARN}"

# The analytics API gives totalSessions but not per-agent session counts
# directly. We need to count from topSessions or use byAgent if it has
# session counts. Fall back to totalSessions as a whole.
# byAgent has {agentId, cost, tokens} - no session count.
# topSessions has per-session data we can group.
# Alternative: use totalSessions as a proxy per agent.
# The brief says "if any single agent has more than 30 sessions in one day"
# We can approximate by grouping topSessions by agentId, but topSessions
# may be truncated. Use totalSessions as a simpler check.

TOTAL_SESSIONS=$(echo "$DAILY_DATA" | jq -r '.totalSessions // 0')
TOP_SESSIONS=$(echo "$DAILY_DATA" | jq -c '.topSessions // []')

# Group sessions by agent from topSessions
AGENT_SESSION_COUNTS=$(echo "$TOP_SESSIONS" | jq -c '
    group_by(.agentId)
    | map({agentId: .[0].agentId, count: length})
    | sort_by(-.count)
' 2>/dev/null) || AGENT_SESSION_COUNTS="[]"

HIGHEST_AGENT=$(echo "$AGENT_SESSION_COUNTS" | jq -r '.[0].agentId // "none"' 2>/dev/null) || HIGHEST_AGENT="none"
HIGHEST_COUNT=$(echo "$AGENT_SESSION_COUNTS" | jq -r '.[0].count // 0' 2>/dev/null) || HIGHEST_COUNT=0

if [[ "$HIGHEST_COUNT" -ge "$SESSION_VOLUME_CRIT" ]]; then
    CHECK4_STATUS="critical"
    CHECK4_DETAIL="${HIGHEST_AGENT}: ${HIGHEST_COUNT} sessions/day exceeds ${SESSION_VOLUME_CRIT} critical threshold"
    ALERTS+=("🔴 Session Volume: ${HIGHEST_AGENT} at ${HIGHEST_COUNT} sessions/day")
elif [[ "$HIGHEST_COUNT" -ge "$SESSION_VOLUME_WARN" ]]; then
    CHECK4_STATUS="warn"
    CHECK4_DETAIL="${HIGHEST_AGENT}: ${HIGHEST_COUNT} sessions/day exceeds ${SESSION_VOLUME_WARN} warn threshold"
    ALERTS+=("🟡 Session Volume: ${HIGHEST_AGENT} at ${HIGHEST_COUNT} sessions/day")
else
    CHECK4_DETAIL="Highest: ${HIGHEST_AGENT} at ${HIGHEST_COUNT} sessions/day (total: ${TOTAL_SESSIONS})"
fi

add_check "session_volume" "$CHECK4_STATUS" "$CHECK4_DETAIL" "$CHECK4_THRESHOLD"

# ---------------------------------------------------------------------------
# Check 5: Weekly Spend Trend
# ---------------------------------------------------------------------------
CHECK5_STATUS="ok"
CHECK5_DETAIL="No weekly data available"
CHECK5_THRESHOLD="${WEEKLY_TREND_MULTIPLIER}x"

if [[ -n "$WEEKLY_DATA" ]]; then
    OVER_TIME=$(echo "$WEEKLY_DATA" | jq -c '.overTime // []')
    DAY_COUNT=$(echo "$OVER_TIME" | jq 'length')

    if [[ "$DAY_COUNT" -ge 2 ]]; then
        # Most recent day's cost
        LATEST_COST=$(echo "$OVER_TIME" | jq -r '.[-1].cost // 0')
        # Average of all days
        AVG_COST=$(echo "$OVER_TIME" | jq -r '[.[].cost] | add / length')

        if float_gt "$AVG_COST" "0"; then
            RATIO=$(echo "scale=2; $LATEST_COST / $AVG_COST" | bc)
            CHECK5_DETAIL="today \$${LATEST_COST} vs 7-day avg \$${AVG_COST} (${RATIO}x)"

            if float_gte "$RATIO" "$WEEKLY_TREND_MULTIPLIER"; then
                CHECK5_STATUS="warn"
                ALERTS+=("🟡 Weekly Trend: today \$${LATEST_COST} is ${RATIO}x the 7-day avg \$${AVG_COST}")
            fi
        else
            CHECK5_DETAIL="7-day average is \$0 (no prior spend)"
        fi
    elif [[ "$DAY_COUNT" -eq 1 ]]; then
        LATEST_COST=$(echo "$OVER_TIME" | jq -r '.[0].cost // 0')
        CHECK5_DETAIL="Only 1 day of data (\$${LATEST_COST}). Need 2+ days for trend."
    fi
fi

add_check "weekly_trend" "$CHECK5_STATUS" "$CHECK5_DETAIL" "$CHECK5_THRESHOLD"

# ---------------------------------------------------------------------------
# Determine overall status
# ---------------------------------------------------------------------------
OVERALL="ok"
if echo "$CHECKS_JSON" | jq -e '[.[].status] | any(. == "critical")' > /dev/null 2>&1; then
    OVERALL="critical"
elif echo "$CHECKS_JSON" | jq -e '[.[].status] | any(. == "warn")' > /dev/null 2>&1; then
    OVERALL="warn"
fi

# ---------------------------------------------------------------------------
# Alert cooldown logic
# ---------------------------------------------------------------------------
SHOULD_ALERT=false
ALERTS_SENT=false

if [[ ${#ALERTS[@]} -gt 0 ]]; then
    SHOULD_ALERT=true

    # Check cooldown
    if [[ -f "$LAST_ALERT_FILE" ]]; then
        LAST_ALERT_TS=$(jq -r '.timestamp // ""' "$LAST_ALERT_FILE" 2>/dev/null) || LAST_ALERT_TS=""
        LAST_CHECKS=$(jq -r '.check_statuses // ""' "$LAST_ALERT_FILE" 2>/dev/null) || LAST_CHECKS=""

        if [[ -n "$LAST_ALERT_TS" ]]; then
            LAST_EPOCH=$(date -d "$LAST_ALERT_TS" +%s 2>/dev/null) || LAST_EPOCH=0
            NOW_EPOCH=$(date +%s)
            ELAPSED_HOURS=$(( (NOW_EPOCH - LAST_EPOCH) / 3600 ))

            if [[ "$ELAPSED_HOURS" -lt "$ALERT_COOLDOWN_HOURS" ]]; then
                # Within cooldown window. Only alert if new checks entered warn/critical.
                CURRENT_CHECKS=$(echo "$CHECKS_JSON" | jq -c '[to_entries[] | select(.value.status == "warn" or .value.status == "critical") | .key] | sort')

                if [[ "$CURRENT_CHECKS" == "$LAST_CHECKS" ]]; then
                    SHOULD_ALERT=false
                fi
                # If different checks are alerting, send anyway (new problem)
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Send Telegram alert
# ---------------------------------------------------------------------------
if [[ "$SHOULD_ALERT" == true ]] && [[ -n "$TG_TOKEN" ]] && [[ -n "$TG_CHAT" ]]; then
    ALERT_MSG="⚠️ COST SENTINEL ALERT"$'\n'$'\n'

    for alert_line in "${ALERTS[@]}"; do
        ALERT_MSG+="${alert_line}"$'\n'
    done

    ALERT_MSG+=$'\n'"Action needed. Check Cost Analytics tab or run:"$'\n'
    ALERT_MSG+='curl -s "http://localhost:3100/api/analytics?range=1" | jq .byAgent'

    # URL-encode not needed for Telegram sendMessage with JSON body
    HTTP_CODE=$(curl -sf --max-time 10 -o /dev/null -w "%{http_code}" \
        -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
        -H "Content-Type: application/json" \
        -d "$(jq -n --arg chat "$TG_CHAT" --arg text "$ALERT_MSG" '{chat_id: $chat, text: $text, parse_mode: "Markdown", disable_web_page_preview: true}')" \
        2>/dev/null) || HTTP_CODE="000"

    if [[ "$HTTP_CODE" == "200" ]]; then
        ALERTS_SENT=true
        # Write cooldown file
        CURRENT_CHECKS=$(echo "$CHECKS_JSON" | jq -c '[to_entries[] | select(.value.status == "warn" or .value.status == "critical") | .key] | sort')
        jq -n \
            --arg ts "$TIMESTAMP" \
            --argjson checks "$CURRENT_CHECKS" \
            '{timestamp: $ts, check_statuses: $checks}' \
            > "$LAST_ALERT_FILE"
    else
        log_err "Telegram send failed (HTTP ${HTTP_CODE})"
    fi
elif [[ "$SHOULD_ALERT" == true ]] && { [[ -z "$TG_TOKEN" ]] || [[ -z "$TG_CHAT" ]]; }; then
    log_err "Telegram credentials not configured. Alert skipped. Set TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID in ${ENV_FILE}"
fi

# ---------------------------------------------------------------------------
# Write status JSON (atomic)
# ---------------------------------------------------------------------------
jq -n \
    --arg ts "$TIMESTAMP" \
    --argjson checks "$CHECKS_JSON" \
    --arg overall "$OVERALL" \
    --argjson alerts_sent "$ALERTS_SENT" \
    '{timestamp: $ts, checks: $checks, overall: $overall, alerts_sent: $alerts_sent}' \
    > "$STATUS_TMP"

mv -f "$STATUS_TMP" "$STATUS_FILE"

heartbeat_finish
exit 0
