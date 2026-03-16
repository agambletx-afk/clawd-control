#!/usr/bin/env bash
# =============================================================================
# CORTEX Routing Health Sentinel - Routing anomaly detection
# =============================================================================
# Location: /usr/local/bin/check-cortex-sentinel.sh
# Schedule: 0 7 * * * openclaw (daily at 07:00 UTC / 01:00 Dallas)
# Output:   /home/openclaw/.openclaw/workspace/cortex-sentinel-status.json
# Alerts:   Telegram on threshold breach
# Version:  1.0
# Date:     2026-03-16
# Brief:    CORTEX Routing Health Sentinel
# =============================================================================
# Dependencies: bash, jq, awk, bc (all pre-installed on VPS)
# Runs as: openclaw user
# Token cost: Zero. Pure bash + jq/awk/bc. No LLM calls.
# =============================================================================

set -euo pipefail

HEARTBEAT_ID="cortex-sentinel"
source /usr/local/bin/heartbeat-lib.sh

# ---------------------------------------------------------------------------
# Thresholds - tunable
# ---------------------------------------------------------------------------
SAMPLE_SIZE=50
MIN_SAMPLE_SIZE=10
WORKTYPE_CONCENTRATION_WARN=75
WORKTYPE_CONCENTRATION_CRIT=90
EVIDENCE_INVARIANCE_WARN=60
EVIDENCE_INVARIANCE_CRIT=80
SCORE_CLUSTER_WARN=0.05
SCORE_CLUSTER_CRIT=0.02
RULE_FIRE_WARN_PCT=10
MODEL_CONCENTRATION_WARN=80
MODEL_CONCENTRATION_CRIT=95

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
LOG_FILE="/home/openclaw/.openclaw/logs/cortex.log"
WORKSPACE="/home/openclaw/.openclaw/workspace"
STATUS_FILE="${WORKSPACE}/cortex-sentinel-status.json"
STATUS_TMP="${WORKSPACE}/.cortex-sentinel-status.tmp"
TG_SCRIPT="/usr/local/bin/send-to-telegram.sh"

DRY_RUN="false"
if [[ "${1:-}" == "--dry-run" ]]; then
    DRY_RUN="true"
fi

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
CHECKS_JSON=""
ALERTS_SENT="false"

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

pct_of_total() {
    local n="$1" d="$2"
    if [[ "$d" -eq 0 ]]; then
        echo "0"
    else
        awk -v n="$n" -v d="$d" 'BEGIN { printf "%.1f", (n/d)*100 }'
    fi
}

is_gte() {
    awk -v a="$1" -v b="$2" 'BEGIN { exit (a+0 >= b+0 ? 0 : 1) }'
}

is_lt() {
    awk -v a="$1" -v b="$2" 'BEGIN { exit (a+0 < b+0 ? 0 : 1) }'
}

mkdir -p "$WORKSPACE"

QUALIFIED_LINES=""
if [[ -f "$LOG_FILE" ]]; then
    QUALIFIED_LINES=$(tac "$LOG_FILE" | jq -Rrc '
        fromjson? |
        select(.status == "selected" or .status == "exhausted") |
        select(
            ((.sessionId // "") | contains(":cron:")) | not
        ) |
        select(
            (
                ((.policyInput.evidence.tokenBucket // "") == "short") and
                ((.policyInput.evidence.explicitDeliverableCount // 0) == 1) and
                ((.policyInput.workType // "") == "conversation") and
                ((.score // 1) < 0.06)
            ) | not
        ) |
        @base64
    ' | head -n "$SAMPLE_SIZE") || true
fi

SAMPLE_COUNT=$(printf '%s\n' "$QUALIFIED_LINES" | sed '/^$/d' | wc -l | tr -d ' ')

if [[ "$SAMPLE_COUNT" -lt "$MIN_SAMPLE_SIZE" ]]; then
    add_check "worktype_concentration" "insufficient_data" "Only ${SAMPLE_COUNT} qualifying routing decisions; need at least ${MIN_SAMPLE_SIZE}" ">= ${MIN_SAMPLE_SIZE} decisions"
    add_check "evidence_invariance" "insufficient_data" "Only ${SAMPLE_COUNT} qualifying routing decisions; need at least ${MIN_SAMPLE_SIZE}" ">= ${MIN_SAMPLE_SIZE} decisions"
    add_check "score_clustering" "insufficient_data" "Only ${SAMPLE_COUNT} qualifying routing decisions; need at least ${MIN_SAMPLE_SIZE}" ">= ${MIN_SAMPLE_SIZE} decisions"
    add_check "rule_silence" "insufficient_data" "Only ${SAMPLE_COUNT} qualifying routing decisions; need at least ${MIN_SAMPLE_SIZE}" ">= ${MIN_SAMPLE_SIZE} decisions"
    add_check "model_concentration" "insufficient_data" "Only ${SAMPLE_COUNT} qualifying routing decisions; need at least ${MIN_SAMPLE_SIZE}" ">= ${MIN_SAMPLE_SIZE} decisions"

    jq -n \
        --arg ts "$TIMESTAMP" \
        --argjson checks "$CHECKS_JSON" \
        --arg alerts "$ALERTS_SENT" \
        '{timestamp: $ts, checks: $checks, overall: "insufficient_data", alerts_sent: ($alerts == "true")}' \
        > "$STATUS_TMP"
    mv -f "$STATUS_TMP" "$STATUS_FILE"
    heartbeat_finish
    exit 0
fi

SAMPLE_JSON=$(printf '%s\n' "$QUALIFIED_LINES" | sed '/^$/d' | while read -r line; do
    printf '%s' "$line" | base64 -d
    printf '\n'
done | jq -s '.')

# ---------------------------------------------------------------------------
# Check 1: WorkType concentration
# ---------------------------------------------------------------------------
WT_TOP=$(echo "$SAMPLE_JSON" | jq -r '
    sort_by(.policyInput.workType // "unknown")
    | group_by(.policyInput.workType // "unknown")
    | map({k: (.[0].policyInput.workType // "unknown"), c: length})
    | sort_by(-.c)
    | .[0]
')
WT_NAME=$(echo "$WT_TOP" | jq -r '.k')
WT_COUNT=$(echo "$WT_TOP" | jq -r '.c')
WT_PCT=$(pct_of_total "$WT_COUNT" "$SAMPLE_COUNT")
WT_STATUS="ok"
if is_gte "$WT_PCT" "$WORKTYPE_CONCENTRATION_CRIT"; then
    WT_STATUS="critical"
elif is_gte "$WT_PCT" "$WORKTYPE_CONCENTRATION_WARN"; then
    WT_STATUS="warn"
fi
add_check "worktype_concentration" "$WT_STATUS" "${WT_NAME}: ${WT_PCT}% of ${SAMPLE_COUNT} decisions" ">${WORKTYPE_CONCENTRATION_WARN}% warn, >${WORKTYPE_CONCENTRATION_CRIT}% critical"

# ---------------------------------------------------------------------------
# Check 2: Evidence flag invariance
# ---------------------------------------------------------------------------
EVIDENCE_JSON=$(echo "$SAMPLE_JSON" | jq -r '
    def pct(flag): (([.[] | select(.policyInput.evidence[flag] == true)] | length) / (length) * 100);
    {
      codeBlockPresent: pct("codeBlockPresent"),
      freshnessRequired: pct("freshnessRequired"),
      citationRequested: pct("citationRequested"),
      validationRequested: pct("validationRequested"),
      multimodalRequired: pct("multimodalRequired")
    }
')
EVI_WORST=$(echo "$EVIDENCE_JSON" | jq -r 'to_entries | max_by(.value)')
EVI_FLAG=$(echo "$EVI_WORST" | jq -r '.key')
EVI_PCT=$(echo "$EVI_WORST" | jq -r '.value')
EVI_PCT_FMT=$(awk -v v="$EVI_PCT" 'BEGIN { printf "%.1f", v }')
EVI_STATUS="ok"
if is_gte "$EVI_PCT_FMT" "$EVIDENCE_INVARIANCE_CRIT"; then
    EVI_STATUS="critical"
elif is_gte "$EVI_PCT_FMT" "$EVIDENCE_INVARIANCE_WARN"; then
    EVI_STATUS="warn"
fi
EVI_DETAIL=$(echo "$EVIDENCE_JSON" | jq -r '
    to_entries
    | sort_by(-.value)
    | .[0:2]
    | map("\(.key): \(.value|floor)% true")
    | join(", ")
')
add_check "evidence_invariance" "$EVI_STATUS" "$EVI_DETAIL" ">${EVIDENCE_INVARIANCE_WARN}% warn, >${EVIDENCE_INVARIANCE_CRIT}% critical"

# ---------------------------------------------------------------------------
# Check 3: Score clustering (stddev)
# ---------------------------------------------------------------------------
SCORE_STATS=$(echo "$SAMPLE_JSON" | jq -r '[.[].score // 0] | @tsv' | awk '
    {
      n=0; sum=0;
      for (i=1; i<=NF; i++) { x=$i+0; a[n]=x; sum+=x; n++ }
      if (n==0) { printf "0 0\n"; exit }
      mean=sum/n;
      ssd=0;
      for (i=0; i<n; i++) { d=a[i]-mean; ssd += d*d }
      stddev=sqrt(ssd/n);
      printf "%.6f %.6f\n", stddev, mean
    }
')
STDDEV=$(echo "$SCORE_STATS" | awk '{print $1}')
MEAN=$(echo "$SCORE_STATS" | awk '{print $2}')
SCORE_STATUS="ok"
if is_lt "$STDDEV" "$SCORE_CLUSTER_CRIT"; then
    SCORE_STATUS="critical"
elif is_lt "$STDDEV" "$SCORE_CLUSTER_WARN"; then
    SCORE_STATUS="warn"
fi
add_check "score_clustering" "$SCORE_STATUS" "stddev=${STDDEV} across ${SAMPLE_COUNT} decisions (mean=${MEAN})" "<${SCORE_CLUSTER_WARN} warn, <${SCORE_CLUSTER_CRIT} critical"

# ---------------------------------------------------------------------------
# Check 4: Rule silence
# ---------------------------------------------------------------------------
RULE_FIRED_COUNT=$(echo "$SAMPLE_JSON" | jq '[.[] | select((.firedRules // []) | length > 0)] | length')
RULE_PCT=$(pct_of_total "$RULE_FIRED_COUNT" "$SAMPLE_COUNT")
RULE_STATUS="ok"
if [[ "$RULE_FIRED_COUNT" -eq 0 ]]; then
    RULE_STATUS="critical"
elif is_lt "$RULE_PCT" "$RULE_FIRE_WARN_PCT"; then
    RULE_STATUS="warn"
fi
add_check "rule_silence" "$RULE_STATUS" "${RULE_FIRED_COUNT}/${SAMPLE_COUNT} decisions had rules fire" "0 critical, <${RULE_FIRE_WARN_PCT}% warn"

# ---------------------------------------------------------------------------
# Check 5: Model concentration
# ---------------------------------------------------------------------------
MODEL_TOP=$(echo "$SAMPLE_JSON" | jq -r '
    sort_by(.modelSelected // "unknown")
    | group_by(.modelSelected // "unknown")
    | map({k: (.[0].modelSelected // "unknown"), c: length})
    | sort_by(-.c)
    | .[0]
')
MODEL_NAME=$(echo "$MODEL_TOP" | jq -r '.k')
MODEL_COUNT=$(echo "$MODEL_TOP" | jq -r '.c')
MODEL_PCT=$(pct_of_total "$MODEL_COUNT" "$SAMPLE_COUNT")
MODEL_STATUS="ok"
if is_gte "$MODEL_PCT" "$MODEL_CONCENTRATION_CRIT"; then
    MODEL_STATUS="critical"
elif is_gte "$MODEL_PCT" "$MODEL_CONCENTRATION_WARN"; then
    MODEL_STATUS="warn"
fi
add_check "model_concentration" "$MODEL_STATUS" "${MODEL_NAME}: ${MODEL_PCT}% of ${SAMPLE_COUNT} decisions" ">${MODEL_CONCENTRATION_WARN}% warn, >${MODEL_CONCENTRATION_CRIT}% critical"

OVERALL=$(echo "$CHECKS_JSON" | jq -r '
    [to_entries[].value.status] as $s
    | if ($s | index("critical")) then "critical"
      elif ($s | index("warn")) then "warn"
      else "ok" end
')

if [[ "$OVERALL" == "warn" || "$OVERALL" == "critical" ]]; then
    if [[ "$DRY_RUN" != "true" && -x "$TG_SCRIPT" ]]; then
        ANOMALY_COUNT=$(echo "$CHECKS_JSON" | jq '[to_entries[] | select(.value.status == "warn" or .value.status == "critical")] | length')
        WT_LINE=$(echo "$CHECKS_JSON" | jq -r '.worktype_concentration | "- WorkType concentration: \(.status) (\(.detail | split(": ")[0]): \(.detail | capture("(?<pct>[0-9.]+)%").pct)%)"')
        EV_LINE=$(echo "$CHECKS_JSON" | jq -r '.evidence_invariance | "- Evidence invariance: \(.status) (\(.detail | split(", ")[0]))"')
        SC_LINE=$(echo "$CHECKS_JSON" | jq -r '.score_clustering | "- Score clustering: \(.status) (\(.detail | capture("stddev=(?<sd>[0-9.]+)").sd as $sd | "stddev: \($sd)"))"')
        RS_LINE=$(echo "$CHECKS_JSON" | jq -r '.rule_silence | "- Rule silence: \(.status) (\(.detail | split(" decisions")[0]))"')
        MC_LINE=$(echo "$CHECKS_JSON" | jq -r '.model_concentration | "- Model concentration: \(.status) (\(.detail | split(": ")[0]): \(.detail | capture("(?<pct>[0-9.]+)%").pct)%)"')

        MESSAGE=$(cat <<MSG
⚡ CORTEX Sentinel: ${ANOMALY_COUNT} anomaly(s) detected
${WT_LINE}
${EV_LINE}
${SC_LINE}
${RS_LINE}
${MC_LINE}
MSG
)
        "$TG_SCRIPT" "$MESSAGE" >/dev/null 2>&1 || true
        ALERTS_SENT="true"
    fi
fi

jq -n \
    --arg ts "$TIMESTAMP" \
    --argjson checks "$CHECKS_JSON" \
    --arg overall "$OVERALL" \
    --arg alerts "$ALERTS_SENT" \
    '{timestamp: $ts, checks: $checks, overall: $overall, alerts_sent: ($alerts == "true")}' \
    > "$STATUS_TMP"
mv -f "$STATUS_TMP" "$STATUS_FILE"

heartbeat_finish
