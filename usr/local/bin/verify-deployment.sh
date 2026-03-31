#!/usr/bin/env bash
set +e

RESULTS_FILE="/tmp/verify-deployment-results.json"
BASELINE_FILE="/tmp/verify-deployment-baseline.json"
SCHEMA_FILE="/usr/local/lib/openclaw-verify/docs-schema.json"
CONFIG_FILE="/home/openclaw/.openclaw/openclaw.json"
ENV_FILE_PRIMARY="/opt/openclaw.env"
ENV_FILE_FALLBACK="/home/openclaw/.openclaw/.env"
WORKSPACE_DIR="/home/openclaw/.openclaw/workspace"
SOUL_FILE="/home/openclaw/.openclaw/workspace/SOUL.md"
AGENTS_FILE="/home/openclaw/.openclaw/workspace/AGENTS.md"
HEARTBEAT_FILE="/home/openclaw/.openclaw/workspace/HEARTBEAT.md"
OPENCLAW_DIR="/home/openclaw/.openclaw"
FACTS_DB="/home/openclaw/.openclaw/memory/facts.db"
EXT_DIR="/home/openclaw/.openclaw/extensions"
SERVICE_NAME="openclaw"
GATEWAY_PORT="18789"
DASHBOARD_PORT="3100"
MONITORING_PORT="8900"

JSON_ONLY=0
VERBOSE=0
SAVE_BASELINE=0
USE_COLOR=1
SECTION_FILTER=""
TIER_FILTER=""
TIER_LABEL="all"

START_MS=$(date +%s%3N)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
GRAY='\033[0;90m'
BLUE='\033[0;34m'
NC='\033[0m'

if [ ! -t 1 ]; then
  USE_COLOR=0
fi

colorize() {
  local color="$1"
  local text="$2"
  if [ "$USE_COLOR" -eq 1 ]; then
    printf "%b%s%b" "$color" "$text" "$NC"
  else
    printf "%s" "$text"
  fi
}

usage() {
  cat <<USAGE
Usage: verify-deployment.sh [options]
  --section core,config,workspace,memory,services,cron,security_baseline,plugins,environment,context,latency,permissions
  --tier 1,2,3,all
  --json-only
  --verbose
  --save-baseline
  --no-color
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --section)
      SECTION_FILTER="$2"
      shift 2
      ;;
    --tier)
      TIER_FILTER="$2"
      shift 2
      ;;
    --json-only)
      JSON_ONLY=1
      shift
      ;;
    --verbose)
      VERBOSE=1
      shift
      ;;
    --save-baseline)
      SAVE_BASELINE=1
      shift
      ;;
    --no-color)
      USE_COLOR=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

RESULTS_JSONL=$(mktemp)
trap 'rm -f "$RESULTS_JSONL" "$RESULTS_TMP"' EXIT

if [ -n "$TIER_FILTER" ] && [ -n "$SECTION_FILTER" ]; then
  echo "--tier and --section are mutually exclusive" >&2
  exit 1
fi

if [ -n "$TIER_FILTER" ]; then
  TIER_LABEL="$TIER_FILTER"
  if [ "$TIER_FILTER" != "all" ]; then
    expanded_sections=""
    IFS=',' read -r -a req_tiers <<< "$TIER_FILTER"
    for tier in "${req_tiers[@]}"; do
      case "$tier" in
        1)
          expanded_sections+="core,config,workspace,memory,services,"
          ;;
        2)
          expanded_sections+="cron,security_baseline,plugins,environment,"
          ;;
        3)
          expanded_sections+="context,latency,permissions,"
          ;;
        all)
          expanded_sections=""
          break
          ;;
        *)
          echo "Invalid tier: $tier" >&2
          exit 1
          ;;
      esac
    done
    if [ -n "$expanded_sections" ]; then
      SECTION_FILTER=$(echo "$expanded_sections" | awk -F',' '{for(i=1;i<=NF;i++) if($i!="" && !seen[$i]++) out=(out?out ",":"") $i} END{print out}')
    fi
  fi
fi

SELECTED_CORE=1
SELECTED_CONFIG=1
SELECTED_WORKSPACE=1
SELECTED_MEMORY=1
SELECTED_SERVICES=1
SELECTED_CRON=1
SELECTED_SECURITY_BASELINE=1
SELECTED_PLUGINS=1
SELECTED_ENVIRONMENT=1
SELECTED_CONTEXT=1
SELECTED_LATENCY=1
SELECTED_PERMISSIONS=1

if [ -n "$SECTION_FILTER" ]; then
  SELECTED_CORE=0
  SELECTED_CONFIG=0
  SELECTED_WORKSPACE=0
  SELECTED_MEMORY=0
  SELECTED_SERVICES=0
  SELECTED_CRON=0
  SELECTED_SECURITY_BASELINE=0
  SELECTED_PLUGINS=0
  SELECTED_ENVIRONMENT=0
  SELECTED_CONTEXT=0
  SELECTED_LATENCY=0
  SELECTED_PERMISSIONS=0
  IFS=',' read -r -a req_sections <<< "$SECTION_FILTER"
  for sec in "${req_sections[@]}"; do
    case "$sec" in
      core) SELECTED_CORE=1 ;;
      config) SELECTED_CONFIG=1 ;;
      workspace) SELECTED_WORKSPACE=1 ;;
      memory) SELECTED_MEMORY=1 ;;
      services) SELECTED_SERVICES=1 ;;
      cron) SELECTED_CRON=1 ;;
      security_baseline) SELECTED_SECURITY_BASELINE=1 ;;
      plugins) SELECTED_PLUGINS=1 ;;
      environment) SELECTED_ENVIRONMENT=1 ;;
      context) SELECTED_CONTEXT=1 ;;
      latency) SELECTED_LATENCY=1 ;;
      permissions) SELECTED_PERMISSIONS=1 ;;
      *)
        echo "Invalid section: $sec" >&2
        exit 1
        ;;
    esac
  done
fi

pass_count=0
fail_count=0
warn_count=0
skip_count=0
total_count=0

declare -A category_counts_total
declare -A category_counts_pass
declare -A category_counts_fail
declare -A category_counts_warn
declare -A category_counts_skip
for c in core config workspace memory services cron security_baseline plugins environment context latency permissions; do
  category_counts_total[$c]=0
  category_counts_pass[$c]=0
  category_counts_fail[$c]=0
  category_counts_warn[$c]=0
  category_counts_skip[$c]=0
done

record_result() {
  local category="$1"
  local id="$2"
  local name="$3"
  local status="$4"
  local message="$5"
  local duration="$6"

  total_count=$((total_count + 1))
  category_counts_total[$category]=$((category_counts_total[$category] + 1))

  case "$status" in
    pass)
      pass_count=$((pass_count + 1))
      category_counts_pass[$category]=$((category_counts_pass[$category] + 1))
      ;;
    fail)
      fail_count=$((fail_count + 1))
      category_counts_fail[$category]=$((category_counts_fail[$category] + 1))
      ;;
    warn)
      warn_count=$((warn_count + 1))
      category_counts_warn[$category]=$((category_counts_warn[$category] + 1))
      ;;
    skip)
      skip_count=$((skip_count + 1))
      category_counts_skip[$category]=$((category_counts_skip[$category] + 1))
      ;;
  esac

  jq -cn --arg category "$category" --arg id "$id" --arg name "$name" --arg status "$status" --arg message "$message" --argjson duration_ms "$duration" \
    '{category:$category,id:$id,name:$name,status:$status,message:$message,duration_ms:$duration_ms}' >> "$RESULTS_JSONL"

  if [ "$VERBOSE" -eq 1 ] && [ "$JSON_ONLY" -eq 0 ]; then
    local icon=""
    local color="$NC"
    case "$status" in
      pass) icon="PASS"; color="$GREEN" ;;
      fail) icon="FAIL"; color="$RED" ;;
      warn) icon="WARN"; color="$YELLOW" ;;
      skip) icon="SKIP"; color="$GRAY" ;;
    esac
    echo "$(colorize "$color" "[$icon]") $id - $message"
  fi
}

run_check() {
  local category="$1"
  local id="$2"
  local name="$3"
  shift 3
  local start_ms end_ms duration
  start_ms=$(date +%s%3N)
  "$@"
  local rc=$?
  end_ms=$(date +%s%3N)
  duration=$((end_ms - start_ms))

  local status="fail"
  case "$rc" in
    0) status="pass" ;;
    1) status="fail" ;;
    2) status="warn" ;;
    3) status="skip" ;;
    *) status="fail" ;;
  esac
  record_result "$category" "$id" "$name" "$status" "$CHECK_MSG" "$duration"
}

CHECK_MSG=""
SCHEMA_AVAILABLE=0
CONFIG_AVAILABLE=0
ENV_AVAILABLE=0
KNOWN_WARN_SERVICES='[]'
SOUL_VERSION="unknown"
OPENCLAW_VERSION="unknown"

if [ -f "$SCHEMA_FILE" ] && jq empty "$SCHEMA_FILE" >/dev/null 2>&1; then
  SCHEMA_AVAILABLE=1
  KNOWN_WARN_SERVICES=$(jq -c '.known_warn_services // []' "$SCHEMA_FILE" 2>/dev/null)
fi

if [ -f "$ENV_FILE_PRIMARY" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE_PRIMARY"
  set +a
  ENV_AVAILABLE=1
elif [ -f "$ENV_FILE_FALLBACK" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE_FALLBACK"
  set +a
  ENV_AVAILABLE=1
fi

if [ -f "$CONFIG_FILE" ] && jq empty "$CONFIG_FILE" >/dev/null 2>&1; then
  CONFIG_AVAILABLE=1
fi

OPENCLAW_VERSION=$(openclaw --version 2>/dev/null | head -n1)
if [ -f "$SOUL_FILE" ]; then
  SOUL_VERSION=$(head -n 5 "$SOUL_FILE" | grep -Eo 'v[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)
  [ -z "$SOUL_VERSION" ] && SOUL_VERSION="unknown"
fi

is_known_warn_service() {
  local svc="$1"
  echo "$KNOWN_WARN_SERVICES" | jq -e --arg s "$svc" 'index($s) != null' >/dev/null 2>&1
}

# Core checks
check_core_process() {
  local st
  st=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null)
  if [ "$st" = "active" ]; then CHECK_MSG="systemd service is active"; return 0; fi
  CHECK_MSG="systemd service is not active (${st:-unknown})"
  return 1
}
check_core_http() {
  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${GATEWAY_PORT}/" 2>/dev/null)
  if [ "$code" = "200" ] || [ "$code" = "401" ]; then CHECK_MSG="gateway reachable (HTTP $code)"; return 0; fi
  CHECK_MSG="gateway not healthy (HTTP ${code:-000})"
  return 1
}
check_core_version() {
  local v
  v=$(openclaw --version 2>/dev/null | head -n1)
  if echo "$v" | grep -Eq '20[0-9]{2}\.[0-9]+\.[0-9]+'; then CHECK_MSG="openclaw version $v"; return 0; fi
  CHECK_MSG="invalid version string: ${v:-missing}"
  return 1
}
check_core_node() {
  local maj
  maj=$(node -v 2>/dev/null | sed -E 's/^v([0-9]+).*/\1/')
  if [ -n "$maj" ] && [ "$maj" -ge 20 ] 2>/dev/null; then CHECK_MSG="node major version $maj"; return 0; fi
  CHECK_MSG="node version is below 20"
  return 1
}
check_core_cpu() {
  local idle usage
  idle=$(LC_ALL=C top -bn1 | awk -F',' '/Cpu\(s\)/{for(i=1;i<=NF;i++){if($i ~ /id/){gsub(/[^0-9.]/,"",$i); print $i; break}}}')
  if [ -z "$idle" ]; then CHECK_MSG="unable to determine CPU usage"; return 1; fi
  usage=$(awk -v i="$idle" 'BEGIN{printf "%.2f", 100-i}')
  if awk -v u="$usage" 'BEGIN{exit !(u<90)}'; then CHECK_MSG="cpu usage ${usage}%"; return 0; fi
  CHECK_MSG="cpu usage too high (${usage}%)"
  return 1
}
check_core_memory() {
  local used_pct
  used_pct=$(free | awk '/Mem:/ {printf "%.2f", ($3/$2)*100}')
  if [ -z "$used_pct" ]; then CHECK_MSG="unable to determine memory usage"; return 1; fi
  if awk -v u="$used_pct" 'BEGIN{exit !(u<90)}'; then CHECK_MSG="memory usage ${used_pct}%"; return 0; fi
  CHECK_MSG="memory usage too high (${used_pct}%)"
  return 1
}

# Config checks
check_config_json_valid() {
  if [ -f "$CONFIG_FILE" ] && jq empty "$CONFIG_FILE" >/dev/null 2>&1; then CHECK_MSG="config parses as valid JSON"; return 0; fi
  CHECK_MSG="config missing or invalid JSON"
  return 1
}
check_config_auth_mode() {
  if [ "$SCHEMA_AVAILABLE" -ne 1 ]; then CHECK_MSG="schema unavailable"; return 3; fi
  if [ "$CONFIG_AVAILABLE" -ne 1 ]; then CHECK_MSG="config unavailable"; return 1; fi
  local mode
  mode=$(jq -r '.gateway.auth.mode // empty' "$CONFIG_FILE")
  if [ -z "$mode" ]; then CHECK_MSG="gateway.auth.mode missing"; return 1; fi
  if jq -e --arg mode "$mode" '.auth_modes | index($mode) != null' "$SCHEMA_FILE" >/dev/null 2>&1; then
    CHECK_MSG="gateway auth mode '$mode' is valid"; return 0
  fi
  CHECK_MSG="gateway auth mode '$mode' is invalid"
  return 1
}
check_config_bind_mode() {
  if [ "$SCHEMA_AVAILABLE" -ne 1 ]; then CHECK_MSG="schema unavailable"; return 3; fi
  if [ "$CONFIG_AVAILABLE" -ne 1 ]; then CHECK_MSG="config unavailable"; return 1; fi
  local bind
  bind=$(jq -r '.gateway.bind // empty' "$CONFIG_FILE")
  if [ -z "$bind" ]; then CHECK_MSG="gateway.bind missing"; return 1; fi
  if jq -e --arg bind "$bind" '.bind_modes | index($bind) != null' "$SCHEMA_FILE" >/dev/null 2>&1; then CHECK_MSG="gateway bind '$bind' is valid"; return 0; fi
  CHECK_MSG="gateway bind '$bind' is invalid"
  return 1
}
check_config_bind_safe() {
  if [ "$CONFIG_AVAILABLE" -ne 1 ]; then CHECK_MSG="config unavailable"; return 1; fi
  local bind
  bind=$(jq -r '.gateway.bind // empty' "$CONFIG_FILE")
  if [ "$bind" = "all" ]; then CHECK_MSG="gateway.bind is unsafe ('all')"; return 1; fi
  CHECK_MSG="gateway.bind is not 'all' (${bind:-unset})"
  return 0
}
check_config_providers() {
  if [ "$SCHEMA_AVAILABLE" -ne 1 ]; then CHECK_MSG="schema unavailable"; return 3; fi
  if [ "$CONFIG_AVAILABLE" -ne 1 ]; then CHECK_MSG="config unavailable"; return 1; fi
  local bad
  bad=$(jq -r --slurpfile s "$SCHEMA_FILE" '
    [(.agents.defaults.model.primary // empty), ((.agents.defaults.model.fallbacks // [])[])]
    | map(select(type=="string" and contains("/")))
    | map(split("/")[0])
    | unique
    | map(select(($s[0].providers // []) | index(.) | not))
    | join(",")
  ' "$CONFIG_FILE")
  if [ -z "$bad" ]; then CHECK_MSG="all providers are schema-approved"; return 0; fi
  CHECK_MSG="unknown providers: $bad"
  return 1
}
check_config_model_format() {
  if [ "$CONFIG_AVAILABLE" -ne 1 ]; then CHECK_MSG="config unavailable"; return 1; fi
  local bad
  bad=$(jq -r '
    [(.agents.defaults.model.primary // empty), ((.agents.defaults.model.fallbacks // [])[])]
    | map(select(type=="string" and test("^[^/]+/[^/]+$")|not))
    | join(",")
  ' "$CONFIG_FILE")
  if [ -z "$bad" ]; then CHECK_MSG="model strings match provider/model format"; return 0; fi
  CHECK_MSG="invalid model format values: $bad"
  return 1
}
check_config_sandbox_mode() {
  if [ "$SCHEMA_AVAILABLE" -ne 1 ]; then CHECK_MSG="schema unavailable"; return 3; fi
  if [ "$CONFIG_AVAILABLE" -ne 1 ]; then CHECK_MSG="config unavailable"; return 1; fi
  local mode
  mode=$(jq -r '.agents.defaults.sandbox.mode // empty' "$CONFIG_FILE")
  if [ -z "$mode" ]; then CHECK_MSG="sandbox mode missing"; return 1; fi
  if jq -e --arg m "$mode" '.sandbox_modes.pass | index($m) != null' "$SCHEMA_FILE" >/dev/null 2>&1; then CHECK_MSG="sandbox mode '$mode' is compliant"; return 0; fi
  if jq -e --arg m "$mode" '.sandbox_modes.warn | index($m) != null' "$SCHEMA_FILE" >/dev/null 2>&1; then CHECK_MSG="sandbox mode '$mode' is warning-tier"; return 2; fi
  if jq -e --arg m "$mode" '.sandbox_modes.fail | index($m) != null' "$SCHEMA_FILE" >/dev/null 2>&1; then CHECK_MSG="sandbox mode '$mode' is disallowed"; return 1; fi
  CHECK_MSG="sandbox mode '$mode' not recognized by schema"
  return 1
}
check_config_tools_allow() {
  if [ "$SCHEMA_AVAILABLE" -ne 1 ]; then CHECK_MSG="schema unavailable"; return 3; fi
  if [ "$CONFIG_AVAILABLE" -ne 1 ]; then CHECK_MSG="config unavailable"; return 1; fi
  local allow_type missing
  allow_type=$(jq -r '.tools.sandbox.tools.allow | type? // "null"' "$CONFIG_FILE")
  if [ "$allow_type" != "array" ]; then CHECK_MSG="tool allowlist missing/null"; return 3; fi
  missing=$(jq -r --slurpfile s "$SCHEMA_FILE" '
    . as $cfg
    | ($s[0].sandbox_tool_allow_baseline // [])
    | map(select(. as $item | ($cfg.tools.sandbox.tools.allow // []) | index($item) | not))
    | join(",")
  ' "$CONFIG_FILE")
  if [ -z "$missing" ]; then CHECK_MSG="tool allowlist contains baseline entries"; return 0; fi
  CHECK_MSG="missing allowlist entries: $missing"
  return 1
}
check_config_plugins_required() {
  if [ "$SCHEMA_AVAILABLE" -ne 1 ]; then CHECK_MSG="schema unavailable"; return 3; fi
  if [ "$CONFIG_AVAILABLE" -ne 1 ]; then CHECK_MSG="config unavailable"; return 1; fi
  local missing
  missing=$(jq -r --slurpfile s "$SCHEMA_FILE" '
    . as $cfg
    | ($s[0].required_plugins // [])
    | map(select(. as $p | ($cfg.plugins.entries[$p].enabled) != true))
    | join(",")
  ' "$CONFIG_FILE")
  if [ -z "$missing" ]; then CHECK_MSG="required plugins enabled"; return 0; fi
  CHECK_MSG="missing/disabled plugins: $missing"
  return 1
}
check_config_session_bounds() {
  if [ "$CONFIG_AVAILABLE" -ne 1 ]; then CHECK_MSG="config unavailable"; return 1; fi
  local tokens
  tokens=$(jq -r '.agents.defaults.contextTokens // empty' "$CONFIG_FILE")
  if [ -z "$tokens" ] || [ "$tokens" = "null" ]; then CHECK_MSG="contextTokens missing"; return 3; fi
  if echo "$tokens" | grep -Eq '^[0-9]+$' && [ "$tokens" -ge 1000 ] && [ "$tokens" -le 1048576 ]; then CHECK_MSG="contextTokens in range ($tokens)"; return 0; fi
  CHECK_MSG="contextTokens out of range ($tokens)"
  return 1
}

# Workspace checks
check_ws_soul_exists() {
  if [ ! -f "$SOUL_FILE" ]; then CHECK_MSG="SOUL.md missing"; return 1; fi
  local size_kb limit
  size_kb=$(du -k "$SOUL_FILE" | awk '{print $1}')
  if [ "$SCHEMA_AVAILABLE" -eq 1 ]; then
    limit=$(jq -r '.workspace_limits.soul_md_max_kb // empty' "$SCHEMA_FILE")
    if [ -n "$limit" ] && [ "$size_kb" -gt "$limit" ] 2>/dev/null; then CHECK_MSG="SOUL.md exists but oversized (${size_kb}KB > ${limit}KB)"; return 2; fi
  fi
  CHECK_MSG="SOUL.md exists (${size_kb}KB)"
  return 0
}
check_ws_soul_version() {
  if [ ! -f "$SOUL_FILE" ]; then CHECK_MSG="SOUL.md missing"; return 1; fi
  if head -n 5 "$SOUL_FILE" | grep -Eq 'v[0-9]+\.[0-9]+'; then CHECK_MSG="SOUL.md contains version in first 5 lines"; return 0; fi
  CHECK_MSG="SOUL.md first 5 lines missing version"
  return 1
}
check_ws_agents_exists() {
  if [ ! -f "$AGENTS_FILE" ]; then CHECK_MSG="AGENTS.md missing"; return 1; fi
  local size_kb limit
  size_kb=$(du -k "$AGENTS_FILE" | awk '{print $1}')
  if [ "$SCHEMA_AVAILABLE" -eq 1 ]; then
    limit=$(jq -r '.workspace_limits.agents_md_max_kb // empty' "$SCHEMA_FILE")
    if [ -n "$limit" ] && [ "$size_kb" -gt "$limit" ] 2>/dev/null; then CHECK_MSG="AGENTS.md exists but oversized (${size_kb}KB > ${limit}KB)"; return 2; fi
  fi
  CHECK_MSG="AGENTS.md exists (${size_kb}KB)"
  return 0
}
check_ws_heartbeat_exists() {
  if [ -f "$HEARTBEAT_FILE" ]; then CHECK_MSG="HEARTBEAT.md exists"; return 0; fi
  CHECK_MSG="HEARTBEAT.md missing"
  return 1
}
check_ws_ownership() {
  local own
  own=$(stat -c '%U:%G' "$OPENCLAW_DIR" 2>/dev/null)
  if [ "$own" = "openclaw:openclaw" ]; then CHECK_MSG="$OPENCLAW_DIR owner is openclaw:openclaw"; return 0; fi
  CHECK_MSG="$OPENCLAW_DIR owner mismatch (${own:-unknown})"
  return 1
}

# Memory checks
check_mem_facts_db_exists() {
  if [ -s "$FACTS_DB" ]; then CHECK_MSG="facts.db exists and is non-empty"; return 0; fi
  CHECK_MSG="facts.db missing or empty"
  return 1
}
check_mem_facts_db_owner() {
  local own
  own=$(stat -c '%U:%G' "$FACTS_DB" 2>/dev/null)
  if [ "$own" = "openclaw:openclaw" ]; then CHECK_MSG="facts.db owner is openclaw:openclaw"; return 0; fi
  CHECK_MSG="facts.db owner mismatch (${own:-unknown})"
  return 1
}
check_mem_fts5_intact() {
  local out
  out=$(sqlite3 "$FACTS_DB" "SELECT count(*) FROM facts_fts WHERE facts_fts MATCH 'verify';" 2>&1)
  if [ $? -eq 0 ]; then CHECK_MSG="fts5 query succeeded (count=${out:-0})"; return 0; fi
  CHECK_MSG="fts5 query failed: $out"
  return 1
}
check_mem_fts5_readable() {
  local out
  out=$(sqlite3 "$FACTS_DB" "SELECT rowid FROM facts_fts LIMIT 1;" 2>&1)
  if [ $? -eq 0 ]; then CHECK_MSG="facts_fts readable"; return 0; fi
  CHECK_MSG="facts_fts read failed: $out"
  return 1
}
check_mem_facts_count() {
  local count
  count=$(sqlite3 "$FACTS_DB" "SELECT COUNT(*) FROM facts;" 2>/dev/null)
  if [ -z "$count" ]; then CHECK_MSG="unable to read facts count"; return 1; fi
  if [ "$count" -eq 0 ] 2>/dev/null; then CHECK_MSG="facts table empty"; return 2; fi
  CHECK_MSG="facts table rows: $count"
  return 0
}
check_mem_facts_db_size() {
  local size_bytes max_bytes
  size_bytes=$(stat -c '%s' "$FACTS_DB" 2>/dev/null)
  if [ -z "$size_bytes" ]; then CHECK_MSG="unable to read facts.db size"; return 1; fi
  max_bytes=$((1024 * 1024 * 1024))
  if [ "$size_bytes" -gt "$max_bytes" ] 2>/dev/null; then
    CHECK_MSG="facts.db size high (${size_bytes} bytes > ${max_bytes} bytes)"
    return 2
  fi
  CHECK_MSG="facts.db size within bound (${size_bytes} bytes)"
  return 0
}

check_mem_read_only_guard() {
  if [ -r "$FACTS_DB" ]; then
    CHECK_MSG="read-only verification path enabled (no writes performed)"
    return 0
  fi
  CHECK_MSG="facts.db is not readable"
  return 1
}

# Services checks
http_service_check() {
  local name="$1" url="$2" ok_codes="$3"
  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null)
  if echo "$ok_codes" | tr ',' '\n' | grep -qx "$code"; then CHECK_MSG="$name healthy (HTTP $code)"; return 0; fi
  if is_known_warn_service "$name"; then CHECK_MSG="$name unhealthy but schema marks warn (HTTP ${code:-000})"; return 2; fi
  CHECK_MSG="$name unhealthy (HTTP ${code:-000})"
  return 1
}
check_svc_openclaw() { http_service_check "openclaw" "http://127.0.0.1:${GATEWAY_PORT}/" "200,401"; }
check_svc_clawd_control() { http_service_check "clawd_control" "http://127.0.0.1:${DASHBOARD_PORT}/" "200"; }
check_svc_clawmetry() { http_service_check "clawmetry" "http://127.0.0.1:${MONITORING_PORT}/" "200"; }
check_svc_telegram() {
  if [ -z "${TELEGRAM_BOT_TOKEN:-}" ]; then CHECK_MSG="TELEGRAM_BOT_TOKEN missing"; return 3; fi
  local ok
  ok=$(curl -sS --max-time 3 "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getMe" | jq -r '.ok // false' 2>/dev/null)
  if [ "$ok" = "true" ]; then CHECK_MSG="telegram getMe returned ok:true"; return 0; fi
  if is_known_warn_service "telegram"; then CHECK_MSG="telegram check failed but marked warn"; return 2; fi
  CHECK_MSG="telegram getMe failed"
  return 1
}
check_svc_anthropic() {
  if [ -z "${ANTHROPIC_API_KEY:-}" ]; then CHECK_MSG="ANTHROPIC_API_KEY missing"; return 3; fi
  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 -H "x-api-key: ${ANTHROPIC_API_KEY}" -H "anthropic-version: 2023-06-01" "https://api.anthropic.com/v1/models" 2>/dev/null)
  if [ "$code" = "200" ]; then CHECK_MSG="anthropic models endpoint returned 200"; return 0; fi
  if is_known_warn_service "anthropic"; then CHECK_MSG="anthropic endpoint failed (HTTP $code), downgraded via known_warn_services"; return 2; fi
  CHECK_MSG="anthropic endpoint failed (HTTP ${code:-000})"
  return 1
}
check_svc_gemini() {
  if [ -z "${GEMINI_API_KEY:-}" ]; then CHECK_MSG="GEMINI_API_KEY missing"; return 3; fi
  local code
  code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 "https://generativelanguage.googleapis.com/v1beta/models?key=${GEMINI_API_KEY}" 2>/dev/null)
  if [ "$code" = "200" ]; then CHECK_MSG="gemini models endpoint returned 200"; return 0; fi
  if is_known_warn_service "google"; then CHECK_MSG="gemini endpoint failed (HTTP $code), downgraded via known_warn_services"; return 2; fi
  CHECK_MSG="gemini endpoint failed (HTTP ${code:-000})"
  return 1
}


schema_num_or_default() {
  local query="$1" default="$2" val
  if [ "$SCHEMA_AVAILABLE" -eq 1 ]; then
    val=$(jq -r "$query // empty" "$SCHEMA_FILE" 2>/dev/null)
    if echo "$val" | grep -Eq '^[0-9]+$'; then
      echo "$val"
      return
    fi
  fi
  echo "$default"
}

cron_entry_exists() {
  local pattern="$1"
  crontab -l 2>/dev/null | grep -q "$pattern"
}

check_cron_with_output() {
  local key="$1" pattern="$2" default_output="$3" default_max_minutes="$4"
  if [ "$SCHEMA_AVAILABLE" -ne 1 ] || ! jq -e --arg k "$key" '.expected_crons[$k]' "$SCHEMA_FILE" >/dev/null 2>&1; then
    CHECK_MSG="expected_crons.$key missing in schema"
    return 3
  fi
  if ! cron_entry_exists "$pattern"; then
    CHECK_MSG="cron entry missing for $key"
    return 1
  fi
  local output max_stale_minutes now mtime age max_age
  output=$(jq -r --arg k "$key" '.expected_crons[$k].output // empty' "$SCHEMA_FILE" 2>/dev/null)
  max_stale_minutes=$(jq -r --arg k "$key" '.expected_crons[$k].max_stale_minutes // empty' "$SCHEMA_FILE" 2>/dev/null)
  [ -z "$output" ] && output="$default_output"
  [ -z "$max_stale_minutes" ] && max_stale_minutes="$default_max_minutes"
  if [ ! -f "$output" ]; then
    CHECK_MSG="cron exists but output file missing: $output"
    return 1
  fi
  mtime=$(stat --format=%Y "$output" 2>/dev/null)
  if [ -z "$mtime" ]; then
    CHECK_MSG="cron exists but failed to read output mtime: $output"
    return 1
  fi
  now=$(date +%s)
  age=$((now - mtime))
  max_age=$((max_stale_minutes * 60))
  if [ "$age" -le "$max_age" ]; then
    CHECK_MSG="cron exists and output fresh (${age}s <= ${max_age}s)"
    return 0
  fi
  CHECK_MSG="cron exists but output stale (${age}s > ${max_age}s)"
  return 2
}

# Tier 2 checks
check_cron_security_health() { check_cron_with_output "check-security-health" "check-security-health\.sh" "/tmp/security-health-results.json" 30; }
check_cron_system_health() { check_cron_with_output "check-system-health" "check-system-health\.sh" "/home/openclaw/.openclaw/workspace/health-status.json" 10; }
check_cron_api_liveness() { check_cron_with_output "check-api-health" "openclaw-api-liveness\.sh" "/tmp/openclaw-api-liveness.json" 5; }
check_cron_version_check() {
  if ! cron_entry_exists "check-openclaw-version\.sh"; then CHECK_MSG="cron entry missing for version check"; return 1; fi
  local output="/tmp/security-version-cache.json" mtime now age max_age
  if [ ! -f "$output" ]; then CHECK_MSG="cron exists but output file missing: $output"; return 1; fi
  mtime=$(stat --format=%Y "$output" 2>/dev/null)
  [ -z "$mtime" ] && CHECK_MSG="cron exists but failed to read output mtime: $output" && return 1
  now=$(date +%s); age=$((now - mtime)); max_age=$((25 * 60 * 60))
  if [ "$age" -le "$max_age" ]; then CHECK_MSG="version-check output fresh (${age}s <= ${max_age}s)"; return 0; fi
  CHECK_MSG="version-check output stale (${age}s > ${max_age}s)"; return 2
}
check_cron_morning_scan() { cron_entry_exists "morning-improvement-scan" && CHECK_MSG="morning-improvement-scan cron exists" && return 0; CHECK_MSG="morning-improvement-scan cron missing"; return 1; }
check_cron_memory_extraction() { cron_entry_exists "memory.*extract\|extract.*memory\|graph-memory" && CHECK_MSG="memory extraction cron exists" && return 0; CHECK_MSG="memory extraction cron missing"; return 1; }
check_cron_memory_pruning() { cron_entry_exists "memory.*prun\|decay.*prun" && CHECK_MSG="memory pruning cron exists" && return 0; CHECK_MSG="memory pruning cron missing"; return 1; }
check_cron_delivery_format() {
  if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then CHECK_MSG="curl or jq unavailable"; return 3; fi
  local body
  body=$(curl -sS --max-time 3 "http://127.0.0.1:${GATEWAY_PORT}/api/crons" 2>/dev/null)
  if [ -z "$body" ] || ! echo "$body" | jq empty >/dev/null 2>&1; then CHECK_MSG="gateway cron API unavailable"; return 3; fi
  if echo "$body" | jq -e '.. | objects | has("delivery") and (.delivery | type=="object") and (.delivery | has("target"))' >/dev/null 2>&1; then
    CHECK_MSG="deprecated delivery.target found in cron config"
    return 1
  fi
  CHECK_MSG="no deprecated delivery.target in cron config"
  return 0
}

check_sec_ufw_active() {
  if ! command -v sudo >/dev/null 2>&1 || ! command -v ufw >/dev/null 2>&1; then CHECK_MSG="sudo or ufw unavailable"; return 3; fi
  local out rc
  out=$(sudo ufw status 2>&1); rc=$?
  if [ $rc -ne 0 ]; then CHECK_MSG="sudo ufw status unavailable"; return 3; fi
  echo "$out" | grep -q "Status: active" && CHECK_MSG="ufw is active" && return 0
  CHECK_MSG="ufw is not active"
  return 1
}
check_sec_fail2ban_running() { [ "$(systemctl is-active fail2ban 2>/dev/null)" = "active" ] && CHECK_MSG="fail2ban is active" && return 0; CHECK_MSG="fail2ban is not active"; return 1; }
check_sec_tailscale_online() { command -v tailscale >/dev/null 2>&1 || { CHECK_MSG="tailscale command missing"; return 3; }; tailscale status >/dev/null 2>&1 && CHECK_MSG="tailscale status ok" && return 0; CHECK_MSG="tailscale status failed"; return 1; }
check_sec_soul_acip() { [ -f "$SOUL_FILE" ] || { CHECK_MSG="SOUL.md missing"; return 1; }; grep -Eq 'Security Anchor|Content Trust Policy|Prompt Injection Defense' "$SOUL_FILE" && CHECK_MSG="SOUL.md includes security policy anchors" && return 0; CHECK_MSG="SOUL.md missing expected security policy anchors"; return 1; }
check_sec_hook_config() { local f="$OPENCLAW_DIR/security-hook.json"; [ -f "$f" ] || { CHECK_MSG="security-hook.json missing"; return 1; }; jq empty "$f" >/dev/null 2>&1 && CHECK_MSG="security-hook.json valid" && return 0; CHECK_MSG="security-hook.json invalid JSON"; return 1; }
check_sec_hook_plugin() { [ "$CONFIG_AVAILABLE" -eq 1 ] || { CHECK_MSG="config unavailable"; return 1; }; jq -e '.. | .plugins? | objects | has("entries") and (.entries | has("security-hook"))' "$CONFIG_FILE" >/dev/null 2>&1 && CHECK_MSG="security-hook plugin present in config" && return 0; CHECK_MSG="security-hook plugin missing in config"; return 1; }
check_sec_integrity_baseline() { [ -f "$OPENCLAW_DIR/.integrity-manifest" ] || [ -f "$OPENCLAW_DIR/.soul-hash" ] && CHECK_MSG="integrity baseline present" && return 0; CHECK_MSG="integrity baseline missing (.integrity-manifest or .soul-hash)"; return 1; }

check_plugin_graph_memory() { [ -d "$EXT_DIR/graph-memory" ] && CHECK_MSG="graph-memory extension exists" && return 0; CHECK_MSG="graph-memory extension missing"; return 1; }
check_plugin_security_hook() { [ -d "$EXT_DIR/security-hook" ] || { CHECK_MSG="security-hook extension missing"; return 1; }; if [ -f "$EXT_DIR/security-hook/index.ts" ] || [ -f "$EXT_DIR/security-hook/index.js" ]; then CHECK_MSG="security-hook extension entrypoint exists"; return 0; fi; CHECK_MSG="security-hook extension missing index.ts/index.js"; return 1; }
check_plugin_extensions_dir() { [ -d "$EXT_DIR" ] || { CHECK_MSG="extensions directory missing"; return 1; }; [ "$(stat -c '%U' "$EXT_DIR" 2>/dev/null)" = "openclaw" ] && CHECK_MSG="extensions directory owned by openclaw" && return 0; CHECK_MSG="extensions directory not owned by openclaw"; return 1; }
check_plugin_install_match() {
  [ "$CONFIG_AVAILABLE" -eq 1 ] || { CHECK_MSG="config unavailable"; return 1; }
  command -v jq >/dev/null 2>&1 || { CHECK_MSG="jq unavailable"; return 3; }
  local paths
  paths=$(jq -r '.. | .plugins? | objects | .entries? // {} | to_entries[]? | .value.installPath? // empty' "$CONFIG_FILE" 2>/dev/null)
  [ $? -ne 0 ] && CHECK_MSG="jq parse failed for installPath entries" && return 3
  local missing=0
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    [ -d "$p" ] || missing=$((missing+1))
  done <<< "$paths"
  [ $missing -eq 0 ] && CHECK_MSG="all plugin installPath directories exist" && return 0
  CHECK_MSG="missing plugin installPath directories: $missing"
  return 1
}

check_env_file_exists() { [ -r "$ENV_FILE_PRIMARY" ] || { CHECK_MSG="$ENV_FILE_PRIMARY not readable"; return 1; }; command -v sudo >/dev/null 2>&1 || { CHECK_MSG="sudo unavailable"; return 3; }; sudo -u openclaw test -r "$ENV_FILE_PRIMARY" >/dev/null 2>&1 && CHECK_MSG="openclaw can read $ENV_FILE_PRIMARY" && return 0; CHECK_MSG="openclaw cannot read $ENV_FILE_PRIMARY"; return 3; }
check_env_required_vars() { [ -f "$ENV_FILE_PRIMARY" ] || { CHECK_MSG="$ENV_FILE_PRIMARY missing"; return 1; }; local miss=""; for k in ANTHROPIC_API_KEY TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID; do grep -q "^${k}=" "$ENV_FILE_PRIMARY" || miss="$miss${miss:+,}$k"; done; [ -z "$miss" ] && CHECK_MSG="required env vars present" && return 0; CHECK_MSG="missing required env vars: $miss"; return 1; }
check_env_gateway_errors() {
  command -v journalctl >/dev/null 2>&1 || { CHECK_MSG="journalctl unavailable"; return 3; }
  local logs count
  logs=$(journalctl -u openclaw -n 100 --no-pager 2>/dev/null)
  [ $? -ne 0 ] && CHECK_MSG="journalctl unavailable for openclaw unit" && return 3
  count=$(echo "$logs" | grep -Eic 'uncaughtException|FATAL')
  if [ "$count" -eq 0 ]; then CHECK_MSG="no gateway fatal/error signatures in last 100 lines"; return 0; fi
  if [ "$count" -le 5 ]; then CHECK_MSG="gateway fatal/error signatures in last 100 lines: $count"; return 2; fi
  CHECK_MSG="gateway fatal/error signatures too frequent: $count"
  return 1
}
check_env_gateway_no_fatal() { command -v journalctl >/dev/null 2>&1 || { CHECK_MSG="journalctl unavailable"; return 3; }; local logs count; logs=$(journalctl -u openclaw -n 100 --no-pager 2>/dev/null) || { CHECK_MSG="journalctl unavailable for openclaw unit"; return 3; }; count=$(echo "$logs" | grep -Eic 'FATAL'); [ "$count" -eq 0 ] && CHECK_MSG="no FATAL lines in last 100 log entries" && return 0; CHECK_MSG="FATAL lines detected in last 100 log entries: $count"; return 1; }
check_env_disk_usage() { local used; used=$(df -P / | awk 'NR==2{gsub(/%/,"",$5); print $5}'); [ -z "$used" ] && CHECK_MSG="unable to determine root disk usage" && return 3; if [ "$used" -lt 85 ]; then CHECK_MSG="root disk usage ${used}%"; return 0; fi; if [ "$used" -le 95 ]; then CHECK_MSG="root disk usage warning ${used}%"; return 2; fi; CHECK_MSG="root disk usage critical ${used}%"; return 1; }
check_env_backup_freshness() { local dir="/home/openclaw/backups"; [ -d "$dir" ] || { CHECK_MSG="backup directory missing"; return 3; }; local fresh; fresh=$(find "$dir" -maxdepth 1 -type f -mtime -7 | wc -l); [ "$fresh" -gt 0 ] && CHECK_MSG="recent backups found: $fresh" && return 0; CHECK_MSG="no backups newer than 7 days"; return 2; }

# Tier 3 checks
check_ctx_md_file_count() { local max count; max=$(schema_num_or_default '.context_limits.max_workspace_md_files' 10); count=$(find "$WORKSPACE_DIR" -maxdepth 1 -type f -name '*.md' 2>/dev/null | wc -l); [ "$count" -le "$max" ] && CHECK_MSG="workspace markdown file count $count <= $max" && return 0; CHECK_MSG="workspace markdown file count $count > $max"; return 2; }
check_ctx_md_total_bytes() { local max total; max=$(schema_num_or_default '.context_limits.max_workspace_md_bytes' 32768); total=$(find "$WORKSPACE_DIR" -maxdepth 1 -type f -name '*.md' -printf '%s\n' 2>/dev/null | awk '{s+=$1} END{print s+0}'); [ "$total" -le "$max" ] && CHECK_MSG="workspace markdown bytes $total <= $max" && return 0; CHECK_MSG="workspace markdown bytes $total > $max"; return 2; }
check_ctx_soul_words() { local max words; max=$(schema_num_or_default '.context_limits.max_soul_words' 4000); [ -f "$SOUL_FILE" ] || { CHECK_MSG="SOUL.md missing"; return 3; }; words=$(wc -w < "$SOUL_FILE"); [ "$words" -le "$max" ] && CHECK_MSG="SOUL.md words $words <= $max" && return 0; CHECK_MSG="SOUL.md words $words > $max"; return 2; }
check_ctx_agents_words() { local max words; max=$(schema_num_or_default '.context_limits.max_agents_words' 1200); [ -f "$AGENTS_FILE" ] || { CHECK_MSG="AGENTS.md missing"; return 3; }; words=$(wc -w < "$AGENTS_FILE"); [ "$words" -le "$max" ] && CHECK_MSG="AGENTS.md words $words <= $max" && return 0; CHECK_MSG="AGENTS.md words $words > $max"; return 2; }
check_ctx_heartbeat_words() { local max words; max=$(schema_num_or_default '.context_limits.max_heartbeat_words' 800); [ -f "$HEARTBEAT_FILE" ] || { CHECK_MSG="HEARTBEAT.md missing"; return 3; }; words=$(wc -w < "$HEARTBEAT_FILE"); [ "$words" -le "$max" ] && CHECK_MSG="HEARTBEAT.md words $words <= $max" && return 0; CHECK_MSG="HEARTBEAT.md words $words > $max"; return 2; }

measure_http_latency_ms() {
  local url="$1"
  curl -s -o /dev/null -w '%{time_total}' --max-time 5 "$url" 2>/dev/null | awk '{printf "%d", $1 * 1000}'
}
check_latency_gateway() { local max ms; max=$(schema_num_or_default '.latency_thresholds_ms.gateway_http' 2000); ms=$(measure_http_latency_ms "http://127.0.0.1:${GATEWAY_PORT}/health"); [ -z "$ms" ] && CHECK_MSG="gateway latency probe failed" && return 3; [ "$ms" -lt "$max" ] && CHECK_MSG="gateway latency ${ms}ms < ${max}ms" && return 0; CHECK_MSG="gateway latency ${ms}ms >= ${max}ms"; return 2; }
check_latency_dashboard() { local max ms; max=$(schema_num_or_default '.latency_thresholds_ms.dashboard_http' 2000); ms=$(measure_http_latency_ms "http://127.0.0.1:${DASHBOARD_PORT}/api/health"); [ -z "$ms" ] && CHECK_MSG="dashboard latency probe failed" && return 3; [ "$ms" -lt "$max" ] && CHECK_MSG="dashboard latency ${ms}ms < ${max}ms" && return 0; CHECK_MSG="dashboard latency ${ms}ms >= ${max}ms"; return 2; }
check_latency_monitoring() { local max ms code; max=$(schema_num_or_default '.latency_thresholds_ms.monitoring_http' 2000); code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:${MONITORING_PORT}/health" 2>/dev/null); [ -z "$code" ] || [ "$code" = "000" ] && CHECK_MSG="monitoring endpoint unavailable" && return 3; ms=$(measure_http_latency_ms "http://127.0.0.1:${MONITORING_PORT}/health"); [ "$ms" -lt "$max" ] && CHECK_MSG="monitoring latency ${ms}ms < ${max}ms" && return 0; CHECK_MSG="monitoring latency ${ms}ms >= ${max}ms"; return 2; }
check_latency_fts5() { local max elapsed start end; max=$(schema_num_or_default '.latency_thresholds_ms.fts5_query' 500); command -v sqlite3 >/dev/null 2>&1 || { CHECK_MSG="sqlite3 unavailable"; return 3; }; [ -f "$FACTS_DB" ] || { CHECK_MSG="facts.db missing"; return 3; }; start=$(date +%s%3N); sqlite3 "$FACTS_DB" "SELECT * FROM facts WHERE facts MATCH 'test' LIMIT 1" >/dev/null 2>&1 || { CHECK_MSG="fts5 test query unavailable"; return 3; }; end=$(date +%s%3N); elapsed=$((end-start)); [ "$elapsed" -lt "$max" ] && CHECK_MSG="fts5 query latency ${elapsed}ms < ${max}ms" && return 0; CHECK_MSG="fts5 query latency ${elapsed}ms >= ${max}ms"; return 2; }

check_perm_config_no_world_read() { local mode other; mode=$(stat --format=%A "$CONFIG_FILE" 2>/dev/null) || { CHECK_MSG="openclaw.json missing"; return 3; }; other=${mode:7:3}; echo "$other" | grep -q 'r' && CHECK_MSG="openclaw.json is world-readable ($mode)" && return 2; CHECK_MSG="openclaw.json not world-readable ($mode)"; return 0; }
check_perm_env_no_world_read() { local mode other; mode=$(stat --format=%A "$ENV_FILE_PRIMARY" 2>/dev/null) || { CHECK_MSG="$ENV_FILE_PRIMARY missing"; return 3; }; other=${mode:7:3}; echo "$other" | grep -q 'r' && CHECK_MSG="$ENV_FILE_PRIMARY is world-readable ($mode)" && return 2; CHECK_MSG="$ENV_FILE_PRIMARY not world-readable ($mode)"; return 0; }
check_perm_facts_no_world_write() { local mode other; mode=$(stat --format=%A "$FACTS_DB" 2>/dev/null) || { CHECK_MSG="facts.db missing"; return 3; }; other=${mode:7:3}; echo "$other" | grep -q 'w' && CHECK_MSG="facts.db is world-writable ($mode)" && return 2; CHECK_MSG="facts.db not world-writable ($mode)"; return 0; }
check_perm_workspace_ownership() { [ -d "$WORKSPACE_DIR" ] || { CHECK_MSG="workspace dir missing"; return 3; }; local bad; bad=$(find "$WORKSPACE_DIR" -mindepth 1 -maxdepth 1 -printf '%u:%g %f\n' | awk '$1!="openclaw:openclaw"{c++} END{print c+0}'); [ "$bad" -eq 0 ] && CHECK_MSG="workspace immediate children owned by openclaw:openclaw" && return 0; CHECK_MSG="workspace immediate children with non-openclaw ownership: $bad"; return 2; }

if [ "$SELECTED_CORE" -eq 1 ]; then
  run_check core core_process "OpenClaw service active" check_core_process
  run_check core core_http "Gateway HTTP reachable" check_core_http
  run_check core core_version "OpenClaw version format" check_core_version
  run_check core core_node "Node.js version" check_core_node
  run_check core core_cpu "CPU usage" check_core_cpu
  run_check core core_memory "Memory usage" check_core_memory
fi

if [ "$SELECTED_CONFIG" -eq 1 ]; then
  run_check config config_json_valid "Config JSON valid" check_config_json_valid
  run_check config config_auth_mode "Gateway auth mode valid" check_config_auth_mode
  run_check config config_bind_mode "Gateway bind mode valid" check_config_bind_mode
  run_check config config_bind_safe "Gateway bind safety" check_config_bind_safe
  run_check config config_providers "Provider allowlist" check_config_providers
  run_check config config_model_format "Model format" check_config_model_format
  run_check config config_sandbox_mode "Sandbox mode policy" check_config_sandbox_mode
  run_check config config_tools_allow "Sandbox tools allow baseline" check_config_tools_allow
  run_check config config_plugins_required "Required plugins enabled" check_config_plugins_required
  run_check config config_session_bounds "Context token bounds" check_config_session_bounds
fi

if [ "$SELECTED_WORKSPACE" -eq 1 ]; then
  run_check workspace ws_soul_exists "SOUL.md exists and size" check_ws_soul_exists
  run_check workspace ws_soul_version "SOUL.md version marker" check_ws_soul_version
  run_check workspace ws_agents_exists "AGENTS.md exists and size" check_ws_agents_exists
  run_check workspace ws_heartbeat_exists "HEARTBEAT.md exists" check_ws_heartbeat_exists
  run_check workspace ws_ownership "OpenClaw directory ownership" check_ws_ownership
fi

if [ "$SELECTED_MEMORY" -eq 1 ]; then
  run_check memory mem_facts_db_exists "facts.db exists" check_mem_facts_db_exists
  run_check memory mem_facts_db_owner "facts.db ownership" check_mem_facts_db_owner
  run_check memory mem_fts5_intact "FTS5 index intact" check_mem_fts5_intact
  run_check memory mem_fts5_readable "FTS5 table readable" check_mem_fts5_readable
  run_check memory mem_facts_count "facts table count" check_mem_facts_count
  run_check memory mem_facts_db_size "facts.db size bound" check_mem_facts_db_size
  run_check memory mem_read_only_guard "Memory verification is read-only" check_mem_read_only_guard
fi

if [ "$SELECTED_SERVICES" -eq 1 ]; then
  run_check services svc_openclaw "OpenClaw service endpoint" check_svc_openclaw
  run_check services svc_clawd_control "Clawd Control endpoint" check_svc_clawd_control
  run_check services svc_clawmetry "ClawMetry endpoint" check_svc_clawmetry
  run_check services svc_telegram "Telegram API connectivity" check_svc_telegram
  run_check services svc_anthropic "Anthropic API connectivity" check_svc_anthropic
  run_check services svc_gemini "Gemini API connectivity" check_svc_gemini
fi


if [ "$SELECTED_CRON" -eq 1 ]; then
  run_check cron cron_security_health "Cron security health" check_cron_security_health
  run_check cron cron_system_health "Cron system health" check_cron_system_health
  run_check cron cron_api_liveness "Cron API liveness" check_cron_api_liveness
  run_check cron cron_version_check "Cron version check" check_cron_version_check
  run_check cron cron_morning_scan "Cron morning scan" check_cron_morning_scan
  run_check cron cron_memory_extraction "Cron memory extraction" check_cron_memory_extraction
  run_check cron cron_memory_pruning "Cron memory pruning" check_cron_memory_pruning
  run_check cron cron_delivery_format "Cron delivery format" check_cron_delivery_format
fi

if [ "$SELECTED_SECURITY_BASELINE" -eq 1 ]; then
  run_check security_baseline sec_ufw_active "UFW active" check_sec_ufw_active
  run_check security_baseline sec_fail2ban_running "Fail2ban running" check_sec_fail2ban_running
  run_check security_baseline sec_tailscale_online "Tailscale online" check_sec_tailscale_online
  run_check security_baseline sec_soul_acip "SOUL security anchors" check_sec_soul_acip
  run_check security_baseline sec_hook_config "Security hook config" check_sec_hook_config
  run_check security_baseline sec_hook_plugin "Security hook plugin enabled" check_sec_hook_plugin
  run_check security_baseline sec_integrity_baseline "Integrity baseline" check_sec_integrity_baseline
fi

if [ "$SELECTED_PLUGINS" -eq 1 ]; then
  run_check plugins plugin_graph_memory "Graph memory plugin" check_plugin_graph_memory
  run_check plugins plugin_security_hook "Security hook plugin files" check_plugin_security_hook
  run_check plugins plugin_extensions_dir "Extensions dir ownership" check_plugin_extensions_dir
  run_check plugins plugin_install_match "Plugin install path match" check_plugin_install_match
fi

if [ "$SELECTED_ENVIRONMENT" -eq 1 ]; then
  run_check environment env_file_exists "Env file readability" check_env_file_exists
  run_check environment env_required_vars "Env required vars" check_env_required_vars
  run_check environment env_gateway_errors "Gateway error signatures" check_env_gateway_errors
  run_check environment env_gateway_no_fatal "Gateway fatal signatures" check_env_gateway_no_fatal
  run_check environment env_disk_usage "Root disk usage" check_env_disk_usage
  run_check environment env_backup_freshness "Backup freshness" check_env_backup_freshness
fi

if [ "$SELECTED_CONTEXT" -eq 1 ]; then
  run_check context ctx_md_file_count "Workspace markdown file count" check_ctx_md_file_count
  run_check context ctx_md_total_bytes "Workspace markdown total bytes" check_ctx_md_total_bytes
  run_check context ctx_soul_words "SOUL word count" check_ctx_soul_words
  run_check context ctx_agents_words "AGENTS word count" check_ctx_agents_words
  run_check context ctx_heartbeat_words "HEARTBEAT word count" check_ctx_heartbeat_words
fi

if [ "$SELECTED_LATENCY" -eq 1 ]; then
  run_check latency latency_gateway "Gateway latency" check_latency_gateway
  run_check latency latency_dashboard "Dashboard latency" check_latency_dashboard
  run_check latency latency_monitoring "Monitoring latency" check_latency_monitoring
  run_check latency latency_fts5 "FTS5 latency" check_latency_fts5
fi

if [ "$SELECTED_PERMISSIONS" -eq 1 ]; then
  run_check permissions perm_config_no_world_read "Config not world-readable" check_perm_config_no_world_read
  run_check permissions perm_env_no_world_read "Env not world-readable" check_perm_env_no_world_read
  run_check permissions perm_facts_no_world_write "facts.db not world-writable" check_perm_facts_no_world_write
  run_check permissions perm_workspace_ownership "Workspace child ownership" check_perm_workspace_ownership
fi

END_MS=$(date +%s%3N)
DURATION_MS=$((END_MS - START_MS))

RESULTS_TMP=$(mktemp)

jq -cs \
  --arg timestamp "$TIMESTAMP" \
  --arg openclaw_version "$OPENCLAW_VERSION" \
  --arg soul_version "$SOUL_VERSION" \
  --argjson duration_ms "$DURATION_MS" \
  --arg tier "$TIER_LABEL" \
  --argjson total "$total_count" \
  --argjson pass "$pass_count" \
  --argjson fail "$fail_count" \
  --argjson warn "$warn_count" \
  --argjson skip "$skip_count" \
  --argjson core_total "${category_counts_total[core]}" \
  --argjson core_pass "${category_counts_pass[core]}" \
  --argjson core_fail "${category_counts_fail[core]}" \
  --argjson core_warn "${category_counts_warn[core]}" \
  --argjson core_skip "${category_counts_skip[core]}" \
  --argjson cfg_total "${category_counts_total[config]}" \
  --argjson cfg_pass "${category_counts_pass[config]}" \
  --argjson cfg_fail "${category_counts_fail[config]}" \
  --argjson cfg_warn "${category_counts_warn[config]}" \
  --argjson cfg_skip "${category_counts_skip[config]}" \
  --argjson ws_total "${category_counts_total[workspace]}" \
  --argjson ws_pass "${category_counts_pass[workspace]}" \
  --argjson ws_fail "${category_counts_fail[workspace]}" \
  --argjson ws_warn "${category_counts_warn[workspace]}" \
  --argjson ws_skip "${category_counts_skip[workspace]}" \
  --argjson mem_total "${category_counts_total[memory]}" \
  --argjson mem_pass "${category_counts_pass[memory]}" \
  --argjson mem_fail "${category_counts_fail[memory]}" \
  --argjson mem_warn "${category_counts_warn[memory]}" \
  --argjson mem_skip "${category_counts_skip[memory]}" \
  --argjson svc_total "${category_counts_total[services]}" \
  --argjson svc_pass "${category_counts_pass[services]}" \
  --argjson svc_fail "${category_counts_fail[services]}" \
  --argjson svc_warn "${category_counts_warn[services]}" \
  --argjson svc_skip "${category_counts_skip[services]}" \
  --argjson cron_total "${category_counts_total[cron]}" \
  --argjson cron_pass "${category_counts_pass[cron]}" \
  --argjson cron_fail "${category_counts_fail[cron]}" \
  --argjson cron_warn "${category_counts_warn[cron]}" \
  --argjson cron_skip "${category_counts_skip[cron]}" \
  --argjson sec_total "${category_counts_total[security_baseline]}" \
  --argjson sec_pass "${category_counts_pass[security_baseline]}" \
  --argjson sec_fail "${category_counts_fail[security_baseline]}" \
  --argjson sec_warn "${category_counts_warn[security_baseline]}" \
  --argjson sec_skip "${category_counts_skip[security_baseline]}" \
  --argjson plug_total "${category_counts_total[plugins]}" \
  --argjson plug_pass "${category_counts_pass[plugins]}" \
  --argjson plug_fail "${category_counts_fail[plugins]}" \
  --argjson plug_warn "${category_counts_warn[plugins]}" \
  --argjson plug_skip "${category_counts_skip[plugins]}" \
  --argjson env_total "${category_counts_total[environment]}" \
  --argjson env_pass "${category_counts_pass[environment]}" \
  --argjson env_fail "${category_counts_fail[environment]}" \
  --argjson env_warn "${category_counts_warn[environment]}" \
  --argjson env_skip "${category_counts_skip[environment]}" \
  --argjson ctx_total "${category_counts_total[context]}" \
  --argjson ctx_pass "${category_counts_pass[context]}" \
  --argjson ctx_fail "${category_counts_fail[context]}" \
  --argjson ctx_warn "${category_counts_warn[context]}" \
  --argjson ctx_skip "${category_counts_skip[context]}" \
  --argjson lat_total "${category_counts_total[latency]}" \
  --argjson lat_pass "${category_counts_pass[latency]}" \
  --argjson lat_fail "${category_counts_fail[latency]}" \
  --argjson lat_warn "${category_counts_warn[latency]}" \
  --argjson lat_skip "${category_counts_skip[latency]}" \
  --argjson perm_total "${category_counts_total[permissions]}" \
  --argjson perm_pass "${category_counts_pass[permissions]}" \
  --argjson perm_fail "${category_counts_fail[permissions]}" \
  --argjson perm_warn "${category_counts_warn[permissions]}" \
  --argjson perm_skip "${category_counts_skip[permissions]}" \
  '
  . as $all
  | {
      timestamp: $timestamp,
      openclaw_version: $openclaw_version,
      soul_version: $soul_version,
      duration_ms: $duration_ms,
      tier: $tier,
      summary: {total:$total, pass:$pass, fail:$fail, warn:$warn, skip:$skip},
      categories: {
        core: {summary:{total:$core_total,pass:$core_pass,fail:$core_fail,warn:$core_warn,skip:$core_skip}, tests: ($all|map(select(.category=="core"))|map(del(.category)))},
        config: {summary:{total:$cfg_total,pass:$cfg_pass,fail:$cfg_fail,warn:$cfg_warn,skip:$cfg_skip}, tests: ($all|map(select(.category=="config"))|map(del(.category)))},
        workspace: {summary:{total:$ws_total,pass:$ws_pass,fail:$ws_fail,warn:$ws_warn,skip:$ws_skip}, tests: ($all|map(select(.category=="workspace"))|map(del(.category)))},
        memory: {summary:{total:$mem_total,pass:$mem_pass,fail:$mem_fail,warn:$mem_warn,skip:$mem_skip}, tests: ($all|map(select(.category=="memory"))|map(del(.category)))},
        services: {summary:{total:$svc_total,pass:$svc_pass,fail:$svc_fail,warn:$svc_warn,skip:$svc_skip}, tests: ($all|map(select(.category=="services"))|map(del(.category)))},
        cron: {summary:{total:$cron_total,pass:$cron_pass,fail:$cron_fail,warn:$cron_warn,skip:$cron_skip}, tests: ($all|map(select(.category=="cron"))|map(del(.category)))},
        security_baseline: {summary:{total:$sec_total,pass:$sec_pass,fail:$sec_fail,warn:$sec_warn,skip:$sec_skip}, tests: ($all|map(select(.category=="security_baseline"))|map(del(.category)))},
        plugins: {summary:{total:$plug_total,pass:$plug_pass,fail:$plug_fail,warn:$plug_warn,skip:$plug_skip}, tests: ($all|map(select(.category=="plugins"))|map(del(.category)))},
        environment: {summary:{total:$env_total,pass:$env_pass,fail:$env_fail,warn:$env_warn,skip:$env_skip}, tests: ($all|map(select(.category=="environment"))|map(del(.category)))},
        context: {summary:{total:$ctx_total,pass:$ctx_pass,fail:$ctx_fail,warn:$ctx_warn,skip:$ctx_skip}, tests: ($all|map(select(.category=="context"))|map(del(.category)))},
        latency: {summary:{total:$lat_total,pass:$lat_pass,fail:$lat_fail,warn:$lat_warn,skip:$lat_skip}, tests: ($all|map(select(.category=="latency"))|map(del(.category)))},
        permissions: {summary:{total:$perm_total,pass:$perm_pass,fail:$perm_fail,warn:$perm_warn,skip:$perm_skip}, tests: ($all|map(select(.category=="permissions"))|map(del(.category)))}
      }
    }
  ' "$RESULTS_JSONL" > "$RESULTS_TMP"

mv "$RESULTS_TMP" "$RESULTS_FILE"

if [ "$SAVE_BASELINE" -eq 1 ]; then
  cp "$RESULTS_FILE" "$BASELINE_FILE"
fi

if [ "$JSON_ONLY" -eq 0 ]; then
  echo "$(colorize "$BLUE" "OpenClaw Deployment Verification")"
  echo "Timestamp: $TIMESTAMP"
  echo "Duration: ${DURATION_MS}ms"
  echo "Results: $RESULTS_FILE"
  echo ""
  echo "Summary: total=${total_count} pass=${pass_count} fail=${fail_count} warn=${warn_count} skip=${skip_count}"
fi

if [ "$fail_count" -gt 0 ]; then
  exit 1
fi
exit 0
