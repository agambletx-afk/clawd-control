#!/usr/bin/env bash
set -u

CONFIG_PATH="/home/openclaw/clawd-control/apis-config.json"
PRIMARY_ENV_PATH="/home/openclaw/clawd-control/.env"
SECONDARY_ENV_PATH="/home/openclaw/.openclaw/workspace/.env"
TERTIARY_ENV_PATH="/opt/openclaw.env"
AUTH_PROFILES_PATH="/home/openclaw/.openclaw/agents/main/agent/auth-profiles.json"
OUT_PATH="/tmp/api-health-results.json"

SERVICE_FILTER="${1:-}"

load_env_file() {
  local env_file="$1"
  [[ -f "$env_file" ]] || return 0

  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^[[:space:]]*export[[:space:]]+ ]] && line="${line#export }"

    if [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
      local key="${line%%=*}"
      local value="${line#*=}"
      if [[ ( "$value" == '"'*'"' ) || ( "$value" == "'"*"'" ) ]]; then
        value="${value:1:${#value}-2}"
      fi
      export "$key=$value"
    fi
  done < "$env_file"
}

resolve_placeholders() {
  local input="$1"
  local output="$input"
  local guard=0

  while [[ "$output" =~ (\$\{[A-Za-z_][A-Za-z0-9_]*\}) ]]; do
    local token="${BASH_REMATCH[1]}"
    local var_name="${token:2:${#token}-3}"
    local var_value="${!var_name-}"
    output="${output//$token/$var_value}"
    guard=$((guard + 1))
    if (( guard > 100 )); then
      break
    fi
  done

  printf '%s' "$output"
}

iso_now() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

to_curl_error() {
  case "$1" in
    6) printf 'Could not resolve host' ;;
    7) printf 'Failed to connect' ;;
    28) printf 'Connection timed out' ;;
    *) printf 'Curl failed (code %s)' "$1" ;;
  esac
}

ms_from_seconds() {
  awk -v sec="$1" 'BEGIN { printf "%d", (sec * 1000) + 0.5 }'
}

write_error_payload() {
  local checked_at
  checked_at="$(iso_now)"
  jq -n \
    --arg checked_at "$checked_at" \
    --arg error_msg "$1" \
    '{
      checked_at: $checked_at,
      results: {
        "__script": {
          status: "error",
          response_ms: 0,
          http_status: 0,
          error: $error_msg,
          checked_at: $checked_at
        }
      }
    }' > "$OUT_PATH"
}

load_env_file "$PRIMARY_ENV_PATH"
load_env_file "$SECONDARY_ENV_PATH"
load_env_file "$TERTIARY_ENV_PATH"

if [[ -z "${GEMINI_API_KEY:-}" && -r "$AUTH_PROFILES_PATH" ]]; then
  gemini_fallback_token="$(jq -r '.profiles.google.manual.token // empty' "$AUTH_PROFILES_PATH" 2>/dev/null)"
  if [[ -n "$gemini_fallback_token" ]]; then
    export GEMINI_API_KEY="$gemini_fallback_token"
  fi
fi

if [[ -z "${OPENAI_API_KEY:-}" && -r "$AUTH_PROFILES_PATH" ]]; then
  openai_fallback_token="$(jq -r '.profiles["openai:manual"].token // empty' "$AUTH_PROFILES_PATH" 2>/dev/null)"
  if [[ -n "$openai_fallback_token" ]]; then
    export OPENAI_API_KEY="$openai_fallback_token"
  fi
fi

if [[ ! -f "$CONFIG_PATH" ]]; then
  write_error_payload "Config file not found: $CONFIG_PATH"
  exit 1
fi

if ! jq -e '.services and (.services | type == "array")' "$CONFIG_PATH" >/dev/null 2>&1; then
  write_error_payload 'Malformed config: .services array missing'
  exit 1
fi

checked_at_global="$(iso_now)"
results='{}'

if [[ -n "$SERVICE_FILTER" ]]; then
  services_json="$(jq -c --arg id "$SERVICE_FILTER" '[.services[] | select(.id == $id)]' "$CONFIG_PATH")"
else
  services_json="$(jq -c '.services' "$CONFIG_PATH")"
fi

service_count="$(jq 'length' <<< "$services_json")"
if [[ "$service_count" -eq 0 ]]; then
  if [[ -n "$SERVICE_FILTER" ]]; then
    write_error_payload "Service not found: $SERVICE_FILTER"
    exit 1
  fi
fi

while IFS= read -r service; do
  [[ -z "$service" ]] && continue

  service_id="$(jq -r '.id // empty' <<< "$service")"
  checked_at="$(iso_now)"
  status="error"
  response_ms=0
  http_status=0
  error_msg='Malformed service config'

  method="$(jq -r '.health_check.method // empty' <<< "$service")"

  if [[ -z "$service_id" || -z "$method" ]]; then
    :
  elif [[ "$method" == "process_check" ]]; then
    process_name="$(jq -r '.health_check.process_name // empty' <<< "$service")"
    if [[ -z "$process_name" ]]; then
      status="error"
      error_msg='process_check requires process_name'
    elif pgrep -x "$process_name" >/dev/null 2>&1 || pgrep -f "$process_name" >/dev/null 2>&1; then
      status="healthy"
      response_ms=0
      http_status=200
      error_msg=''
    else
      status="down"
      response_ms=0
      http_status=0
      error_msg='Process not running'
    fi
  else
    url_raw="$(jq -r '.health_check.url // empty' <<< "$service")"
    expected_status="$(jq -r '.health_check.expected_status // 200' <<< "$service")"
    timeout_ms="$(jq -r '.health_check.timeout_ms // 5000' <<< "$service")"
    body_raw="$(jq -r '.health_check.body // empty' <<< "$service")"

    if [[ -z "$url_raw" ]]; then
      status="error"
      error_msg='health_check.url is required'
    else
      url_resolved="$(resolve_placeholders "$url_raw")"
      body_resolved="$(resolve_placeholders "$body_raw")"
      timeout_sec=$(( (timeout_ms + 999) / 1000 ))
      if (( timeout_sec < 1 )); then timeout_sec=1; fi

      curl_args=(
        --silent
        --output /dev/null
        --write-out "%{http_code} %{time_total}"
        --max-time "$timeout_sec"
        -X "$method"
        "$url_resolved"
      )

      while IFS= read -r header; do
        [[ -z "$header" ]] && continue
        header_key="${header%%=*}"
        header_val="${header#*=}"
        header_line="$header_key: $(resolve_placeholders "$header_val")"
        curl_args+=( -H "$header_line" )
      done < <(jq -r '.health_check.headers // {} | to_entries[]? | "\(.key)=\(.value)"' <<< "$service")

      if [[ "$method" != "GET" && -n "$body_raw" ]]; then
        curl_args+=( --data "$body_resolved" )
      fi

      curl_output=""
      if curl_output="$(curl "${curl_args[@]}" 2>/dev/null)"; then
        http_status="$(awk '{print $1}' <<< "$curl_output")"
        time_total="$(awk '{print $2}' <<< "$curl_output")"
        response_ms="$(ms_from_seconds "${time_total:-0}")"

        if [[ "$http_status" == "$expected_status" ]]; then
          status="healthy"
          error_msg=''
        else
          status="down"
          error_msg="Unexpected status: $http_status"
        fi
      else
        curl_exit=$?
        status="down"
        response_ms="$timeout_ms"
        http_status=0
        error_msg="$(to_curl_error "$curl_exit")"
      fi
    fi
  fi

  if [[ -z "$error_msg" ]]; then
    results="$(jq -c \
      --arg id "$service_id" \
      --arg status "$status" \
      --argjson response_ms "$response_ms" \
      --argjson http_status "$http_status" \
      --arg checked_at "$checked_at" \
      '. + {
        ($id): {
          status: $status,
          response_ms: $response_ms,
          http_status: $http_status,
          error: null,
          checked_at: $checked_at
        }
      }' <<< "$results")"
  else
    results="$(jq -c \
      --arg id "$service_id" \
      --arg status "$status" \
      --argjson response_ms "$response_ms" \
      --argjson http_status "$http_status" \
      --arg error "$error_msg" \
      --arg checked_at "$checked_at" \
      '. + {
        ($id): {
          status: $status,
          response_ms: $response_ms,
          http_status: $http_status,
          error: $error,
          checked_at: $checked_at
        }
      }' <<< "$results")"
  fi

done < <(jq -c '.[]' <<< "$services_json")

jq -n \
  --arg checked_at "$checked_at_global" \
  --argjson results "$results" \
  '{checked_at: $checked_at, results: $results}' > "$OUT_PATH"
