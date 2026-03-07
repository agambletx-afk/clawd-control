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
  --section core,config,workspace,memory,services
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

SELECTED_CORE=1
SELECTED_CONFIG=1
SELECTED_WORKSPACE=1
SELECTED_MEMORY=1
SELECTED_SERVICES=1

if [ -n "$SECTION_FILTER" ]; then
  SELECTED_CORE=0
  SELECTED_CONFIG=0
  SELECTED_WORKSPACE=0
  SELECTED_MEMORY=0
  SELECTED_SERVICES=0
  IFS=',' read -r -a req_sections <<< "$SECTION_FILTER"
  for sec in "${req_sections[@]}"; do
    case "$sec" in
      core) SELECTED_CORE=1 ;;
      config) SELECTED_CONFIG=1 ;;
      workspace) SELECTED_WORKSPACE=1 ;;
      memory) SELECTED_MEMORY=1 ;;
      services) SELECTED_SERVICES=1 ;;
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
for c in core config workspace memory services; do
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
    ($s[0].sandbox_tool_allow_baseline // [])
    | map(select((. as $item | (.tools.sandbox.tools.allow // []) | index($item)) | not))
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
    ($s[0].required_plugins // [])
    | map(select((. as $p | .plugins.entries[$p].enabled) != true))
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
VERIFY_TEST_ID="__verify_test_$(date +%s)_$$"
STORE_OK=0
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
check_mem_facts_count() {
  local count
  count=$(sqlite3 "$FACTS_DB" "SELECT COUNT(*) FROM facts;" 2>/dev/null)
  if [ -z "$count" ]; then CHECK_MSG="unable to read facts count"; return 1; fi
  if [ "$count" -eq 0 ] 2>/dev/null; then CHECK_MSG="facts table empty"; return 2; fi
  CHECK_MSG="facts table rows: $count"
  return 0
}
check_mem_crud_store() {
  local sql
  sql=$(cat <<SQL
INSERT INTO facts (id,text,category,importance,entity,key,value,source,decay_class,confidence,expires_at,last_confirmed_at)
VALUES ('$VERIFY_TEST_ID','verify test row','ops',1.0,'verify','verify_key','$VERIFY_TEST_ID','verify-script','short',1.0,NULL,datetime('now'));
SQL
)
  sqlite3 "$FACTS_DB" "$sql" >/dev/null 2>&1
  if [ $? -eq 0 ]; then STORE_OK=1; CHECK_MSG="crud store insert succeeded"; return 0; fi
  STORE_OK=0
  CHECK_MSG="crud store insert failed"
  return 1
}
check_mem_crud_recall() {
  if [ "$STORE_OK" -ne 1 ]; then CHECK_MSG="skipped because store failed"; return 3; fi
  local val
  val=$(sqlite3 "$FACTS_DB" "SELECT value FROM facts WHERE id='$VERIFY_TEST_ID' LIMIT 1;" 2>/dev/null)
  if [ "$val" = "$VERIFY_TEST_ID" ]; then CHECK_MSG="crud recall matched stored value"; return 0; fi
  CHECK_MSG="crud recall value mismatch"
  return 1
}
check_mem_crud_cleanup() {
  sqlite3 "$FACTS_DB" "DELETE FROM facts WHERE id LIKE '__verify_test_%';" >/dev/null 2>&1
  sqlite3 "$FACTS_DB" "DELETE FROM facts_fts WHERE rowid IN (SELECT rowid FROM facts_fts WHERE facts_fts MATCH '__verify_test_*');" >/dev/null 2>&1
  local left
  left=$(sqlite3 "$FACTS_DB" "SELECT COUNT(*) FROM facts WHERE id LIKE '__verify_test_%';" 2>/dev/null)
  if [ "$left" = "0" ]; then CHECK_MSG="crud cleanup removed all verify rows"; return 0; fi
  CHECK_MSG="crud cleanup left $left verify rows"
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
  if is_known_warn_service "openai"; then CHECK_MSG="anthropic endpoint failed (HTTP $code), downgraded via known_warn_services"; return 2; fi
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
  run_check memory mem_facts_count "facts table count" check_mem_facts_count
  run_check memory mem_crud_store "Memory CRUD store" check_mem_crud_store
  run_check memory mem_crud_recall "Memory CRUD recall" check_mem_crud_recall
  run_check memory mem_crud_cleanup "Memory CRUD cleanup" check_mem_crud_cleanup
fi

if [ "$SELECTED_SERVICES" -eq 1 ]; then
  run_check services svc_openclaw "OpenClaw service endpoint" check_svc_openclaw
  run_check services svc_clawd_control "Clawd Control endpoint" check_svc_clawd_control
  run_check services svc_clawmetry "ClawMetry endpoint" check_svc_clawmetry
  run_check services svc_telegram "Telegram API connectivity" check_svc_telegram
  run_check services svc_anthropic "Anthropic API connectivity" check_svc_anthropic
  run_check services svc_gemini "Gemini API connectivity" check_svc_gemini
fi

END_MS=$(date +%s%3N)
DURATION_MS=$((END_MS - START_MS))

RESULTS_TMP=$(mktemp)

jq -cs \
  --arg timestamp "$TIMESTAMP" \
  --arg openclaw_version "$OPENCLAW_VERSION" \
  --arg soul_version "$SOUL_VERSION" \
  --argjson duration_ms "$DURATION_MS" \
  --argjson tier 1 \
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
        services: {summary:{total:$svc_total,pass:$svc_pass,fail:$svc_fail,warn:$svc_warn,skip:$svc_skip}, tests: ($all|map(select(.category=="services"))|map(del(.category)))}
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
