#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="/etc/jarvis/watcher.json"
STATUS_FILE="/home/openclaw/.openclaw/workspace/watcher-status.json"
SYSLOG_FILE="/var/log/syslog"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"

if [[ -f /opt/openclaw.env ]]; then
  # shellcheck disable=SC1091
  . /opt/openclaw.env
fi

send_telegram_alert() {
  local message="$1"
  if [[ -z "${TELEGRAM_BOT_TOKEN:-}" || -z "${TELEGRAM_CHAT_ID:-}" ]]; then
    return 0
  fi

  curl -sS --max-time 8 -X POST \
    "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_CHAT_ID}" \
    --data-urlencode "text=${message}" >/dev/null || true
}

iso_from_epoch() {
  local epoch="$1"
  date -u -d "@${epoch}" +%Y-%m-%dT%H:%M:%SZ
}

minutes_between() {
  local newer="$1"
  local older="$2"
  awk -v n="$newer" -v o="$older" 'BEGIN { printf "%.2f", (n-o)/60 }'
}

epoch_from_iso() {
  local iso_ts="$1"
  if [[ -z "$iso_ts" || "$iso_ts" == "null" ]]; then
    echo ""
    return 0
  fi

  date -u -d "$iso_ts" +%s 2>/dev/null || echo ""
}

duration_seconds_from_ms() {
  local duration_ms="$1"
  awk -v ms="$duration_ms" 'BEGIN { printf "%.1f", ms/1000 }'
}

find_last_syslog_match_epoch() {
  local needle="$1"
  local cutoff_epoch="$2"
  local now_epoch="$3"

  if [[ ! -r "$SYSLOG_FILE" ]]; then
    echo ""
    return 0
  fi

  awk -v needle="$needle" -v cutoff="$cutoff_epoch" -v now="$now_epoch" '
    BEGIN {
      split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", months, " ")
      for (i = 1; i <= 12; i++) month_num[months[i]] = i
      year = strftime("%Y", now)
      latest = 0
    }
    index($0, needle) > 0 {
      mon = month_num[$1]
      day = $2
      split($3, t, ":")
      ts = mktime(sprintf("%04d %02d %02d %02d %02d %02d", year, mon, day, t[1], t[2], t[3]))
      if (ts > now + 86400) {
        ts = mktime(sprintf("%04d %02d %02d %02d %02d %02d", year - 1, mon, day, t[1], t[2], t[3]))
      }
      if (ts >= cutoff && ts > latest) {
        latest = ts
      }
    }
    END {
      if (latest > 0) {
        printf "%d", latest
      }
    }
  ' "$SYSLOG_FILE"
}

collect_description_warnings() {
  local tmp_file="$1"
  : >"$tmp_file"

  local source_file
  for source_file in /etc/cron.d/openclaw*; do
    [[ -e "$source_file" ]] || continue
    awk -v src="$source_file" '
      function is_schedule(tok) {
        return (tok ~ /^(@reboot|@yearly|@annually|@monthly|@weekly|@daily|@midnight|@hourly)$/ || tok ~ /^[0-9*\/,-]+$/)
      }
      {
        raw=$0
        trimmed=raw
        sub(/^[ \t]+/, "", trimmed)

        if (trimmed ~ /^#/ || trimmed == "") {
          if (trimmed ~ /^# Description:/) {
            prev_desc=1
          } else if (trimmed != "") {
            prev_desc=0
          }
          next
        }

        split(trimmed, p, /[ \t]+/)
        if (is_schedule(p[1])) {
          if (prev_desc != 1) {
            printf "%s\t%d\t%s\n", src, NR, raw
          }
        }
        prev_desc=0
      }
    ' "$source_file" >>"$tmp_file"
  done

  if crontab -u openclaw -l >/tmp/openclaw-crontab.$$ 2>/dev/null; then
    awk '
      function is_schedule(tok) {
        return (tok ~ /^(@reboot|@yearly|@annually|@monthly|@weekly|@daily|@midnight|@hourly)$/ || tok ~ /^[0-9*\/,-]+$/)
      }
      {
        raw=$0
        trimmed=raw
        sub(/^[ \t]+/, "", trimmed)

        if (trimmed ~ /^#/ || trimmed == "") {
          if (trimmed ~ /^# Description:/) {
            prev_desc=1
          } else if (trimmed != "") {
            prev_desc=0
          }
          next
        }

        split(trimmed, p, /[ \t]+/)
        if (is_schedule(p[1])) {
          if (prev_desc != 1) {
            printf "crontab -u openclaw\t%d\t%s\n", NR, raw
          }
        }
        prev_desc=0
      }
    ' /tmp/openclaw-crontab.$$ >>"$tmp_file"
    rm -f /tmp/openclaw-crontab.$$
  fi
}

main() {
  local now_epoch now_iso staleness_multiplier
  now_epoch="$(date +%s)"
  now_iso="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  if [[ ! -r "$CONFIG_FILE" ]]; then
    echo "Missing config: $CONFIG_FILE" >&2
    exit 1
  fi

  staleness_multiplier="$(jq -r '.staleness_multiplier // 2.5' "$CONFIG_FILE")"

  declare -A prev_system_status=()
  declare -A prev_gateway_status=()

  if [[ -r "$STATUS_FILE" ]]; then
    while IFS=$'\t' read -r id status; do
      [[ -n "$id" ]] && prev_system_status["$id"]="$status"
    done < <(jq -r '.system_crons[]? | [.id, .status] | @tsv' "$STATUS_FILE" 2>/dev/null || true)

    while IFS=$'\t' read -r id status; do
      [[ -n "$id" ]] && prev_gateway_status["$id"]="$status"
    done < <(jq -r '.gateway_crons[]? | [.id, .status] | @tsv' "$STATUS_FILE" 2>/dev/null || true)
  fi

  local system_tmp gateway_tmp warnings_tmp
  system_tmp="$(mktemp)"
  gateway_tmp="$(mktemp)"
  warnings_tmp="$(mktemp)"

  local system_stale=0 system_missing=0 system_unknown=0 system_healthy=0 system_total=0 system_failed=0 system_stuck=0

  while IFS=$'	' read -r id description cadence output_path check_method heartbeat_path; do
    [[ -n "$id" ]] || continue
    system_total=$((system_total + 1))

    local threshold_minutes threshold_seconds status last_seen age_minutes message
    local started_at finished_at duration_ms exit_code heartbeat_version check_method_used
    threshold_minutes="$(awk -v c="$cadence" -v m="$staleness_multiplier" 'BEGIN { printf "%.2f", c*m }')"
    threshold_seconds="$(awk -v t="$threshold_minutes" 'BEGIN { printf "%d", t*60 }')"
    status="healthy"
    last_seen="null"
    age_minutes="null"
    message="null"
    started_at="null"
    finished_at="null"
    duration_ms="null"
    exit_code="null"
    heartbeat_version="null"
    check_method_used="$check_method"

    local heartbeat_file
    heartbeat_file="/tmp/${id}-heartbeat.json"
    if [[ -n "$heartbeat_path" && "$heartbeat_path" != "null" ]]; then
      heartbeat_file="$heartbeat_path"
    fi

    if [[ -e "$heartbeat_file" ]]; then
      local hb_version
      hb_version="$(jq -r '.version // empty' "$heartbeat_file" 2>/dev/null || true)"
      if [[ "$hb_version" == "2" ]]; then
        local hb_status hb_started hb_finished hb_duration hb_exit
        hb_status="$(jq -r '.status // empty' "$heartbeat_file" 2>/dev/null || true)"
        hb_started="$(jq -r '.started_at // empty' "$heartbeat_file" 2>/dev/null || true)"
        hb_finished="$(jq -r '.finished_at // empty' "$heartbeat_file" 2>/dev/null || true)"
        hb_duration="$(jq -r '.duration_ms // empty' "$heartbeat_file" 2>/dev/null || true)"
        hb_exit="$(jq -r '.exit_code // empty' "$heartbeat_file" 2>/dev/null || true)"

        check_method_used="heartbeat_v2"
        heartbeat_version='"2"'
        if [[ -n "$hb_started" && "$hb_started" != "null" ]]; then
          started_at='"'"$hb_started"'"'
        fi
        if [[ -n "$hb_finished" && "$hb_finished" != "null" ]]; then
          finished_at='"'"$hb_finished"'"'
        fi
        [[ "$hb_duration" =~ ^[0-9]+$ ]] && duration_ms="$hb_duration"
        [[ "$hb_exit" =~ ^-?[0-9]+$ ]] && exit_code="$hb_exit"

        if [[ "$hb_status" == "success" ]]; then
          status="healthy"
          if [[ -n "$hb_finished" && "$hb_finished" != "null" ]]; then
            local finished_epoch
            last_seen='"'"$hb_finished"'"'
            finished_epoch="$(epoch_from_iso "$hb_finished")"
            if [[ -n "$finished_epoch" ]]; then
              age_minutes="$(minutes_between "$now_epoch" "$finished_epoch")"
            fi
          fi
        elif [[ "$hb_status" == "failed" ]]; then
          status="failed"
          if [[ -n "$hb_finished" && "$hb_finished" != "null" ]]; then
            last_seen='"'"$hb_finished"'"'
          elif [[ -n "$hb_started" && "$hb_started" != "null" ]]; then
            last_seen='"'"$hb_started"'"'
          fi
          message="\"Exit code ${hb_exit:-unknown}\""
        elif [[ "$hb_status" == "running" ]]; then
          local started_epoch running_seconds
          started_epoch="$(epoch_from_iso "$hb_started")"
          if [[ -n "$started_epoch" ]]; then
            running_seconds=$((now_epoch - started_epoch))
            age_minutes="$(minutes_between "$now_epoch" "$started_epoch")"
            last_seen='"'"$hb_started"'"'
            if (( running_seconds > threshold_seconds )); then
              status="stuck"
              message="\"Heartbeat running longer than threshold\""
            else
              status="running"
              message="\"Heartbeat currently running\""
            fi
          else
            status="unknown"
            message="\"Heartbeat missing started_at\""
          fi
        else
          status="unknown"
          message="\"Invalid heartbeat status\""
        fi
      fi
    fi

    if [[ "$check_method_used" != "heartbeat_v2" ]]; then
      if [[ "$check_method" == "mtime" || "$check_method" == "heartbeat_v2" ]]; then
        if [[ -n "$output_path" && "$output_path" != "null" && -e "$output_path" ]]; then
          local mtime age_seconds
          mtime="$(stat -c %Y "$output_path")"
          age_seconds=$((now_epoch - mtime))
          age_minutes="$(minutes_between "$now_epoch" "$mtime")"
          last_seen="\"$(iso_from_epoch "$mtime")\""

          if (( age_seconds > threshold_seconds )); then
            status="stale"
            message="\"Output file is stale\""
          else
            status="healthy"
            message="null"
          fi
        else
          status="missing"
          message="\"Output file not found\""
        fi
        check_method_used="$check_method"
      elif [[ "$check_method" == "cron_log" ]]; then
        local cutoff_epoch match_epoch
        cutoff_epoch=$(( now_epoch - threshold_seconds ))
        match_epoch="$(find_last_syslog_match_epoch "$id" "$cutoff_epoch" "$now_epoch")"
        if [[ -n "$match_epoch" ]]; then
          status="healthy"
          last_seen="\"$(iso_from_epoch "$match_epoch")\""
          age_minutes="$(minutes_between "$now_epoch" "$match_epoch")"
        else
          status="unknown"
          message="\"No matching syslog entry in threshold window\""
        fi
        check_method_used="$check_method"
      else
        status="unknown"
        message="\"Unsupported check method\""
      fi
    fi

    case "$status" in
      healthy|running) system_healthy=$((system_healthy + 1)) ;;
      stale) system_stale=$((system_stale + 1)) ;;
      missing) system_missing=$((system_missing + 1)) ;;
      failed) system_failed=$((system_failed + 1)) ;;
      stuck) system_stuck=$((system_stuck + 1)) ;;
      unknown) system_unknown=$((system_unknown + 1)) ;;
    esac

    jq -n \
      --arg id "$id" \
      --arg description "$description" \
      --arg status "$status" \
      --argjson last_seen "$last_seen" \
      --argjson age_minutes "$age_minutes" \
      --argjson threshold_minutes "$threshold_minutes" \
      --arg check_method "$check_method_used" \
      --arg output_path "$output_path" \
      --argjson message "$message" \
      --argjson started_at "$started_at" \
      --argjson finished_at "$finished_at" \
      --argjson duration_ms "$duration_ms" \
      --argjson exit_code "$exit_code" \
      --argjson heartbeat_version "$heartbeat_version" \
      '{
        id: $id,
        description: $description,
        status: $status,
        last_seen: $last_seen,
        age_minutes: $age_minutes,
        threshold_minutes: $threshold_minutes,
        check_method: $check_method,
        output_path: (if ($output_path == "null" or $output_path == "") then null else $output_path end),
        message: $message,
        started_at: $started_at,
        finished_at: $finished_at,
        duration_ms: $duration_ms,
        exit_code: $exit_code,
        heartbeat_version: $heartbeat_version
      }' >>"$system_tmp"
  done < <(jq -r '.system_crons[] | [.id, .description, .cadence_minutes, (.output_path // "null"), .check_method, (.heartbeat_path // "null")] | @tsv' "$CONFIG_FILE")

  local jobs_file alert_on_consecutive_errors alert_on_disabled_with_errors
  jobs_file="$(jq -r '.gateway_crons.jobs_file' "$CONFIG_FILE")"
  alert_on_consecutive_errors="$(jq -r '.gateway_crons.alert_on_consecutive_errors // 1' "$CONFIG_FILE")"
  alert_on_disabled_with_errors="$(jq -r '.gateway_crons.alert_on_disabled_with_errors // true' "$CONFIG_FILE")"

  local gateway_total=0 gateway_healthy=0 gateway_erroring=0 gateway_disabled=0 gateway_disabled_with_errors=0
  # Note: gateway while-loop runs in a subshell (jq pipe), so counters are derived from gateway_tmp after the loop

  if [[ -r "$jobs_file" ]]; then
    jq -c '.jobs[]? | {
      id: (.id // ""),
      name: (.name // .id // ""),
      enabled: (.enabled // false),
      last_run: ((.state.lastRunAtMs // null) | if . then tostring else null end),
      last_duration_ms: (.state.lastDurationMs // 0),
      last_status: (.state.lastStatus // null),
      consecutive_errors: (.state.consecutiveErrors // 0),
      last_error: (.state.lastError // null),
      model: (.modelOverride // .payload.model // null),
      agent: (.agentId // null),
      schedule: ((.schedule.expr) // ""),
      schedule_tz: ((.schedule.tz) // null)
    }' "$jobs_file" | while IFS= read -r gw_json; do
      [[ -n "$gw_json" ]] || continue
      gateway_total=$((gateway_total + 1))
      local gw_enabled gw_errors gw_lstatus gw_status
      gw_enabled="$(jq -r '.enabled' <<< "$gw_json")"
      gw_errors="$(jq -r '.consecutive_errors' <<< "$gw_json")"
      gw_lstatus="$(jq -r '.last_status // empty' <<< "$gw_json")"
      if [[ "$gw_enabled" == "true" ]]; then
        if [[ "$gw_errors" =~ ^[0-9]+$ ]] && (( gw_errors >= alert_on_consecutive_errors )); then
          gw_status="erroring"; gateway_erroring=$((gateway_erroring + 1))
        else
          gw_status="healthy"; gateway_healthy=$((gateway_healthy + 1))
        fi
      else
        if [[ "$alert_on_disabled_with_errors" == "true" && "$gw_lstatus" == "error" ]]; then
          gw_status="disabled_with_errors"; gateway_disabled_with_errors=$((gateway_disabled_with_errors + 1))
        else
          gw_status="disabled"; gateway_disabled=$((gateway_disabled + 1))
        fi
      fi
      jq --arg status "$gw_status" '. + {status: $status}' <<< "$gw_json" >> "$gateway_tmp"
    done
  fi

  # Derive gateway counts from written JSON (subshell counters lost)
  if [[ -s "$gateway_tmp" ]]; then
    gateway_total=$(jq -s 'length' "$gateway_tmp")
    gateway_healthy=$(jq -s '[.[] | select(.status == "healthy")] | length' "$gateway_tmp")
    gateway_erroring=$(jq -s '[.[] | select(.status == "erroring")] | length' "$gateway_tmp")
    gateway_disabled=$(jq -s '[.[] | select(.status == "disabled" or .status == "disabled_with_errors")] | length' "$gateway_tmp")
    gateway_disabled_with_errors=$(jq -s '[.[] | select(.status == "disabled_with_errors")] | length' "$gateway_tmp")
  fi

  if [[ -s "$gateway_tmp" ]]; then
    gateway_total=$(jq -s 'length' "$gateway_tmp")
    gateway_healthy=$(jq -s '[.[] | select(.status == "healthy")] | length' "$gateway_tmp")
    gateway_erroring=$(jq -s '[.[] | select(.status == "erroring")] | length' "$gateway_tmp")
    gateway_disabled=$(jq -s '[.[] | select(.status == "disabled" or .status == "disabled_with_errors")] | length' "$gateway_tmp")
    gateway_disabled_with_errors=$(jq -s '[.[] | select(.status == "disabled_with_errors")] | length' "$gateway_tmp")
  fi

  collect_description_warnings "$warnings_tmp"

  local description_warning_count
  description_warning_count="$(wc -l <"$warnings_tmp" | tr -d ' ')"

  local overall_status="healthy"
  if (( system_missing > 0 || gateway_erroring > 0 || system_stale >= 3 || system_failed > 0 || system_stuck > 0 )); then
    overall_status="critical"
  elif (( system_stale > 0 || description_warning_count > 0 || gateway_disabled_with_errors > 0 )); then
    overall_status="warning"
  fi

  local status_tmp
  status_tmp="${STATUS_FILE}.tmp.$$"

  jq -n \
    --arg generated_at "$now_iso" \
    --arg overall_status "$overall_status" \
    --slurpfile system_crons "$system_tmp" \
    --slurpfile gateway_crons "$gateway_tmp" \
    --argjson description_warnings "$(
      jq -R -s '
        split("\n")
        | map(select(length > 0))
        | map(split("\t"))
        | map({
            file: .[0],
            line: (.[1] | tonumber),
            entry: .[2],
            message: "Missing # Description: comment on preceding line"
          })
      ' "$warnings_tmp"
    )" \
    --argjson system_total "$system_total" \
    --argjson system_healthy "$system_healthy" \
    --argjson system_stale "$system_stale" \
    --argjson system_missing "$system_missing" \
    --argjson system_unknown "$system_unknown" \
    --argjson system_failed "$system_failed" \
    --argjson system_stuck "$system_stuck" \
    --argjson gateway_total "$gateway_total" \
    --argjson gateway_healthy "$gateway_healthy" \
    --argjson gateway_erroring "$gateway_erroring" \
    --argjson gateway_disabled "$((gateway_disabled + gateway_disabled_with_errors))" \
    --argjson description_warning_count "$description_warning_count" \
    '{
      generated_at: $generated_at,
      overall_status: $overall_status,
      system_crons: $system_crons,
      gateway_crons: $gateway_crons,
      description_warnings: $description_warnings,
      summary: {
        system_total: $system_total,
        system_healthy: $system_healthy,
        system_stale: $system_stale,
        system_missing: $system_missing,
        system_unknown: $system_unknown,
        system_failed: $system_failed,
        system_stuck: $system_stuck,
        gateway_total: $gateway_total,
        gateway_healthy: $gateway_healthy,
        gateway_erroring: $gateway_erroring,
        gateway_disabled: $gateway_disabled,
        description_warnings: $description_warning_count
      }
    }' >"$status_tmp"

  local -a alert_lines=()
  local -a recovery_lines=()

  while IFS=$'\t' read -r id description status age threshold exit_code duration_ms; do
    local prev="${prev_system_status[$id]:-}"
    if [[ "$status" == "unknown" ]]; then
      continue
    fi

    if [[ "$prev" == "healthy" && "$status" != "healthy" && "$status" != "running" ]]; then
      if [[ "$status" == "stale" ]]; then
        alert_lines+=("[STALE] ${description} - last seen ${age}m ago (threshold: ${threshold}m)")
      elif [[ "$status" == "missing" ]]; then
        alert_lines+=("[MISSING] ${description} - output file missing")
      elif [[ "$status" == "failed" ]]; then
        local failed_duration_seconds
        failed_duration_seconds="n/a"
        if [[ "$duration_ms" =~ ^[0-9]+$ ]]; then
          failed_duration_seconds="$(duration_seconds_from_ms "$duration_ms")s"
        fi
        alert_lines+=("[FAILED] ${description} - exit code ${exit_code} after ${failed_duration_seconds}")
      elif [[ "$status" == "stuck" ]]; then
        alert_lines+=("[STUCK] ${description} - running for ${age}m (threshold: ${threshold}m)")
      fi
    elif [[ "$prev" =~ ^(stale|missing|failed|stuck)$ && ( "$status" == "healthy" || "$status" == "running" ) ]]; then
      recovery_lines+=("[OK] ${description} - back to healthy")
    fi
  done < <(jq -r '.system_crons[] | [.id, .description, .status, (.age_minutes // 0), .threshold_minutes, (.exit_code // ""), (.duration_ms // "")] | @tsv' "$status_tmp")

  while IFS=$'\t' read -r id name status consecutive_errors last_error; do
    local prev="${prev_gateway_status[$id]:-}"

    if [[ "$prev" == "healthy" && "$status" =~ ^(erroring|disabled_with_errors)$ ]]; then
      if [[ "$status" == "erroring" ]]; then
        alert_lines+=("[ERROR] ${name} - ${consecutive_errors} consecutive errors: \"${last_error}\"")
      else
        alert_lines+=("[ERROR] ${name} - disabled with last status error")
      fi
    elif [[ "$prev" =~ ^(erroring|disabled_with_errors)$ && "$status" == "healthy" ]]; then
      recovery_lines+=("[OK] ${name} - errors cleared")
    fi
  done < <(jq -r '.gateway_crons[] | [.id, .name, .status, .consecutive_errors, (.last_error // "")] | @tsv' "$status_tmp")

  if (( ${#alert_lines[@]} > 0 )); then
    local alert_message
    alert_message="$({
      echo "WATCHER Alert"
      echo
      printf '%s\n' "${alert_lines[@]}"
      echo
      printf '%s system crons: %s healthy, %s stale, %s failed, %s stuck\n' "$system_total" "$system_healthy" "$system_stale" "$system_failed" "$system_stuck"
      printf '%s gateway crons: %s erroring\n' "$gateway_total" "$gateway_erroring"
    })"
    send_telegram_alert "$alert_message"
  fi

  if (( ${#recovery_lines[@]} > 0 )); then
    local recovery_message
    recovery_message="$({
      echo "WATCHER Recovery"
      echo
      printf '%s\n' "${recovery_lines[@]}"
      echo
      printf '%s system crons: %s healthy\n' "$system_total" "$system_healthy"
      printf '%s gateway crons: %s healthy\n' "$gateway_total" "$gateway_healthy"
    })"
    send_telegram_alert "$recovery_message"
  fi

  mkdir -p "$(dirname "$STATUS_FILE")"
  mv "$status_tmp" "$STATUS_FILE"
  rm -f "$system_tmp" "$gateway_tmp" "$warnings_tmp"
}

main "$@"
