#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="/etc/jarvis/watcher.json"
CRON_DIR="/etc/cron.d"
WRAPPER_DIR="/usr/local/bin"
LOCK_FILE="/tmp/watcher-discover.lock"
DRY_RUN=0

# Timers monitored via Monitoring Layers (not WATCHER) - exclude from discovery
EXCLUDED_TIMERS="jarvis-pulse jarvis-sweep jarvis-audit"

if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
elif [[ $# -gt 0 ]]; then
  echo "Usage: $0 [--dry-run]" >&2
  exit 1
fi

log() {
  echo "[WATCHER-DISCOVER] $*"
}

dry_log() {
  echo "[DRY-RUN] $*"
}

iso_now() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

cadence_from_schedule() {
  local min="$1" hour="$2" dom="$3" mon="$4" dow="$5"

  if [[ "$min" =~ ^\*/([0-9]+)$ && "$hour" == "*" && "$dom" == "*" && "$mon" == "*" && "$dow" == "*" ]]; then
    echo $(( ${BASH_REMATCH[1]} * 60 ))
    return
  fi

  if [[ "$min" =~ ^[0-9]+$ && "$hour" == "*" && "$dom" == "*" && "$mon" == "*" && "$dow" == "*" ]]; then
    echo 3600
    return
  fi

  if [[ "$min" =~ ^[0-9]+$ && "$hour" =~ ^\*/([0-9]+)$ && "$dom" == "*" && "$mon" == "*" && "$dow" == "*" ]]; then
    echo $(( ${BASH_REMATCH[1]} * 3600 ))
    return
  fi

  if [[ "$min" =~ ^[0-9]+$ && "$hour" =~ ^[0-9]+$ && "$dom" == "*" && "$mon" == "*" && "$dow" == "*" ]]; then
    echo 86400
    return
  fi

  if [[ "$min" =~ ^[0-9]+$ && "$hour" =~ ^[0-9]+$ && "$dom" == "*" && "$mon" == "*" && "$dow" =~ ^[0-9,\*-]+$ ]]; then
    echo 86400
    return
  fi

  echo 86400
}

contains_metachar() {
  local cmd="$1"
  [[ "$cmd" =~ [\|\;\`\{\(\<\>] ]] && return 0
  [[ "$cmd" == *'&&'* ]] && return 0
  [[ "$cmd" == *'||'* ]] && return 0
  [[ "$cmd" == *'$('* ]] && return 0
  [[ "$cmd" =~ (^|[[:space:]])2\> ]] && return 0
  [[ "$cmd" =~ (^|[[:space:]])\&($|[[:space:]]) ]] && return 0
  return 1
}

strip_env_prefix() {
  local raw="$1"
  local prefix=""
  local remaining="$raw"

  if [[ "$remaining" =~ ^[[:space:]]*\.([[:space:]]+[^[:space:]]+)[[:space:]]*\&\&[[:space:]]*(.+)$ ]]; then
    prefix=".${BASH_REMATCH[1]}"
    remaining="${BASH_REMATCH[2]}"
  fi

  printf '%s\t%s\n' "$prefix" "$remaining"
}

strip_redirections() {
  local cmd="$1"
  # Aggressively strip all output redirections (multiple passes)
  cmd="$(echo "$cmd" | sed -E "s/[[:space:]]+2>&1//g")"
  cmd="$(echo "$cmd" | sed -E "s/[[:space:]]+2>[[:space:]]*[^[:space:]]+//g")"
  cmd="$(echo "$cmd" | sed -E "s/[[:space:]]+>>[[:space:]]*[^[:space:]]+//g")"
  cmd="$(echo "$cmd" | sed -E "s/[[:space:]]+>[[:space:]]*[^[:space:]]+//g")"
  # Trim trailing whitespace
  cmd="$(echo "$cmd" | sed -E "s/[[:space:]]+$//")"
  printf '%s' "$cmd"
}

classify_command() {
  local id="$1"
  local raw="$2"
  raw="$(strip_redirections "$raw")"
  local parsed prefix remaining

  if [[ "$id" == "watcher" ]]; then
    printf 'monitor_only\tcircular dependency\t\t\t%s\n' "$raw"
    return
  fi

  parsed="$(strip_env_prefix "$raw")"
  prefix="${parsed%%$'\t'*}"
  remaining="${parsed#*$'\t'}"

  if contains_metachar "$remaining"; then
    printf 'monitor_only\tshell metacharacters present\t%s\t\t%s\n' "${prefix:-NONE}" "$remaining"
    return
  fi

  if [[ "$remaining" =~ (^|[[:space:]])(sh|bash)[[:space:]]+-c([[:space:]]|$) ]]; then
    printf 'monitor_only\tshell indirection (sh -c/bash -c)\t%s\t\t%s\n' "${prefix:-NONE}" "$remaining"
    return
  fi

  local first
  first="${remaining%%[[:space:]]*}"
  if [[ "$first" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
    printf 'monitor_only\tinline env assignment\t%s\t\t%s\n' "${prefix:-NONE}" "$remaining"
    return
  fi

  if [[ "$first" != /* ]]; then
    printf 'monitor_only\texecutable path must be absolute\t%s\t\t%s\n' "${prefix:-NONE}" "$remaining"
    return
  fi

  if [[ ! -r "$first" || ! -x "$first" ]]; then
    printf 'monitor_only\texecutable missing or not executable\t%s\t%s\t%s\n' "${prefix:-NONE}" "$first" "$remaining"
    return
  fi

  local args=""
  if [[ "$remaining" == *" "* ]]; then
    args="${remaining#* }"
  fi

  printf 'safe_to_wrap\tabsolute executable\t%s\t%s\t%s\n' "${prefix:-NONE}" "$first" "$args"
}

extract_output_file() {
  local raw="$1"
  if [[ "$raw" =~ [[:space:]]\>\>?[[:space:]]([^[:space:]]+) ]]; then
    echo "${BASH_REMATCH[1]}"
    return
  fi
  echo ""
}

fallback_method_for_monitor_only() {
  local id="$1" raw="$2" cadence="$3"
  local hb_file="/tmp/heartbeat-${id}.json"
  if [[ -f "$hb_file" ]]; then
    printf 'heartbeat\t%s\tfalse\n' "$hb_file"
    return
  fi

  local out_file
  out_file="$(extract_output_file "$raw")"
  if [[ -n "$out_file" ]]; then
    printf 'output_mtime\t%s\tfalse\n' "$out_file"
    return
  fi

  local lookback=$(( cadence * 3 ))
  if journalctl --since "-${lookback} seconds" 2>/dev/null | grep -Fq "$id"; then
    printf 'syslog\t\tfalse\n'
    return
  fi

  printf 'none\t\ttrue\n'
}

load_config_sets() {
  mapfile -t CONFIG_IDS < <(jq -r '.system_crons[]?.id // empty' "$CONFIG_FILE")
  mapfile -t CONFIG_CRON_FILES < <(jq -r '.system_crons[]? | .cron_file // empty' "$CONFIG_FILE")
}

id_in_config() {
  local id="$1"
  local existing
  for existing in "${CONFIG_IDS[@]:-}"; do
    [[ "$existing" == "$id" ]] && return 0
    if [[ "$existing" == *"$id"* || "$id" == *"$existing"* ]]; then
      log "dedupe-fuzzy-match id='$id' config_id='$existing' (treating as monitored)"
      return 0
    fi
  done
  return 1
}

cron_file_in_config() {
  local file="$1"
  local existing
  for existing in "${CONFIG_CRON_FILES[@]:-}"; do
    [[ "$existing" == "$file" ]] && return 0
  done
  return 1
}

append_entries_to_config() {
  local entries_json="$1"
  [[ "$entries_json" == "[]" ]] && return 0

  local tmp_file
  tmp_file="${CONFIG_FILE}.tmp.$$"

  jq --argjson entries "$entries_json" '
    reduce $entries[] as $entry (.;
      if any(.system_crons[]; .id == $entry.id) then .
      else .system_crons += [$entry]
      end
    )
  ' "$CONFIG_FILE" > "$tmp_file"

  mv "$tmp_file" "$CONFIG_FILE"
}

create_wrapper() {
  local id="$1" raw="$2" prefix="$3" executable="$4" args="$5"
  local wrapper_path="${WRAPPER_DIR}/${id}-heartbeat-wrapper.sh"
  local generated_at
  generated_at="$(iso_now)"

  {
    echo '#!/usr/bin/env bash'
    echo 'set -u'
    echo '# Heartbeat v2 wrapper (auto-generated by WATCHER auto-discovery)'
    echo "# Original command: ${raw}"
    echo "# Generated: ${generated_at}"
    echo "export HEARTBEAT_ID=\"${id}\""
    echo 'source /usr/local/bin/heartbeat-lib.sh'
    echo
    if [[ -n "$prefix" ]]; then
      echo "$prefix"
      echo
    fi
    if [[ -n "$args" ]]; then
      echo "${executable} ${args}"
    else
      echo "${executable}"
    fi
    echo '_exit_code=$?'
    echo
    echo 'heartbeat_finish'
    echo 'exit $_exit_code'
  } > "$wrapper_path"

  chmod 755 "$wrapper_path"

  if ! bash -n "$wrapper_path"; then
    rm -f "$wrapper_path"
    log "ROLLBACK ${id}: wrapper failed validation (bash -n)"
    return 1
  fi

  if [[ ! -x "$executable" ]]; then
    rm -f "$wrapper_path"
    log "ROLLBACK ${id}: wrapper failed validation (executable missing)"
    return 1
  fi

  return 0
}

update_cron_file_with_wrapper() {
  local cron_path="$1" wrapper_path="$2"
  local tmp
  tmp="${cron_path}.tmp.$$"

  awk -v wrapper="$wrapper_path" '
    function is_schedule(tok) {
      return (tok ~ /^(@reboot|@yearly|@annually|@monthly|@weekly|@daily|@midnight|@hourly)$/ || tok ~ /^[0-9*\/,-]+$/)
    }
    {
      line=$0
      trimmed=line
      sub(/^[ \t]+/, "", trimmed)
      if (trimmed ~ /^#/ || trimmed == "") {
        print line
        next
      }

      n=split(trimmed, p, /[ \t]+/)
      if (n >= 7 && is_schedule(p[1])) {
        print p[1] " " p[2] " " p[3] " " p[4] " " p[5] " " p[6] " " wrapper
      } else {
        print line
      }
    }
  ' "$cron_path" > "$tmp"

  mv "$tmp" "$cron_path"
}

build_wrapped_entry() {
  local id="$1" description="$2" cron_file="$3" cadence_seconds="$4" discovered_at="$5" wrapper_path="$6"
  local cadence_minutes=$(( (cadence_seconds + 59) / 60 ))
  jq -n \
    --arg id "$id" \
    --arg description "$description" \
    --arg cron_file "$cron_file" \
    --arg heartbeat_file "/tmp/heartbeat-${id}.json" \
    --argjson cadence_seconds "$cadence_seconds" \
    --argjson cadence_minutes "$cadence_minutes" \
    --arg discovered_at "$discovered_at" \
    --arg wrapper_path "$wrapper_path" \
    '{
      id: $id,
      description: $description,
      cron_file: $cron_file,
      heartbeat_file: $heartbeat_file,
      cadence_seconds: $cadence_seconds,
      cadence_minutes: $cadence_minutes,
      log_file: null,
      auto_discovered: true,
      discovered_at: $discovered_at,
      wrapper_path: $wrapper_path,
      validation: null,
      output_path: $heartbeat_file,
      check_method: "heartbeat_v2",
      heartbeat_path: $heartbeat_file
    }'
}

build_monitor_entry() {
  local id="$1" description="$2" cron_file="$3" cadence_seconds="$4" discovered_at="$5" method="$6" output_file="$7" unverifiable="$8"
  local cadence_minutes=$(( (cadence_seconds + 59) / 60 ))
  jq -n \
    --arg id "$id" \
    --arg description "$description" \
    --arg cron_file "$cron_file" \
    --argjson cadence_seconds "$cadence_seconds" \
    --argjson cadence_minutes "$cadence_minutes" \
    --arg discovered_at "$discovered_at" \
    --arg method "$method" \
    --arg output_file "$output_file" \
    --argjson unverifiable "${unverifiable:-false}" \
    '{
      id: $id,
      description: $description,
      cron_file: $cron_file,
      heartbeat_file: null,
      cadence_seconds: $cadence_seconds,
      cadence_minutes: $cadence_minutes,
      log_file: null,
      auto_discovered: true,
      discovered_at: $discovered_at,
      monitor_method: $method,
      output_file: (if $output_file == "" then null else $output_file end),
      needs_manual_review: true,
      status_unverifiable: $unverifiable,
      validation: null,
      output_path: (if $output_file == "" then null else $output_file end),
      check_method: (if $method == "output_mtime" then "mtime" elif $method == "heartbeat" then "heartbeat_v2" elif $method == "syslog" then "cron_log" else "cron_log" end),
      heartbeat_path: null
    }'
}

build_systemd_entry() {
  local id="$1" description="$2" unit="$3" cadence_seconds="$4" discovered_at="$5"
  local cadence_minutes=$(( (cadence_seconds + 59) / 60 ))
  jq -n \
    --arg id "$id" \
    --arg description "$description" \
    --arg unit "$unit" \
    --arg discovered_at "$discovered_at" \
    --argjson cadence_seconds "$cadence_seconds" \
    --argjson cadence_minutes "$cadence_minutes" \
    '{
      id: $id,
      description: $description,
      cron_file: null,
      heartbeat_file: null,
      cadence_seconds: $cadence_seconds,
      cadence_minutes: $cadence_minutes,
      log_file: null,
      auto_discovered: true,
      discovered_at: $discovered_at,
      monitor_method: "systemd_status",
      timer_unit: $unit,
      output_file: null,
      needs_manual_review: true,
      validation: null,
      check_method: "cron_log",
      output_path: null
    }'
}

main() {
  if [[ ! -r "$CONFIG_FILE" ]]; then
    echo "[WATCHER-DISCOVER] Missing config: $CONFIG_FILE" >&2
    exit 1
  fi

  exec 200>"$LOCK_FILE"
  flock -n 200 || { echo "[WATCHER-DISCOVER] Another instance running, skipping"; exit 0; }

  load_config_sets

  local discovered=()
  local entry

  local cron_path
  for cron_path in "$CRON_DIR"/openclaw*; do
    [[ -f "$cron_path" ]] || continue
    [[ "$cron_path" == *.pre-heartbeat* ]] && continue
    local cron_file id description
    cron_file="$(basename "$cron_path")"
    id="${cron_file#openclaw-}"
    description="$(awk -F': ' '/^# Description:/ {print $2; exit}' "$cron_path")"
    [[ -z "$description" ]] && description="$id"

    while IFS= read -r line; do
      [[ -z "$line" ]] && continue
      [[ "$line" =~ ^[[:space:]]*# ]] && continue
      local fields schedule_min schedule_hour schedule_dom schedule_mon schedule_dow user raw_command cadence
      read -r schedule_min schedule_hour schedule_dom schedule_mon schedule_dow user raw_command <<<"$line"
      [[ -n "${schedule_dow:-}" && -n "${user:-}" ]] || continue
      raw_command="${line#* * * * * }"
      raw_command="${raw_command#* }"
      cadence="$(cadence_from_schedule "$schedule_min" "$schedule_hour" "$schedule_dom" "$schedule_mon" "$schedule_dow")"
      discovered+=("cron|$id|$description|$cron_file|$cadence|$user|$raw_command|$cron_path")
    done < "$cron_path"
  done

  while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    local id description cadence
    id="${unit%.timer}"
    if [[ " $EXCLUDED_TIMERS " == *" $id "* ]]; then
      continue
    fi
    description="$(systemctl show "$unit" -p Description --value 2>/dev/null || true)"
    [[ -z "$description" ]] && description="$id"

    local on_active
    on_active="$(systemctl show "$unit" -p OnUnitActiveSec --value 2>/dev/null || true)"
    if [[ "$on_active" =~ ^[0-9]+$ ]]; then
      cadence="$on_active"
    else
      cadence="86400"
    fi

    discovered+=("systemd|$id|$description||$cadence||$unit|")
  done < <(systemctl list-timers --no-legend --all 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /\.timer$/) print $i}' | grep -E '^(jarvis-|openclaw-).*\.timer$' || true)

  local new_entries_json='[]'
  local dry_count=0

  for entry in "${discovered[@]}"; do
    IFS='|' read -r kind id description cron_file cadence user raw_command cron_path <<<"$entry"

    if [[ "$kind" == "cron" ]]; then
      if id_in_config "$id" || cron_file_in_config "$cron_file"; then
        continue
      fi

      local class reason prefix executable args
      IFS=$'\t' read -r class reason prefix executable args < <(classify_command "$id" "$raw_command")
      [[ "$prefix" == "NONE" ]] && prefix=""
      log "$id: classified as $class - $reason"

      if (( DRY_RUN == 1 )); then
        dry_count=$((dry_count + 1))
        dry_log "  $id: $class ($reason)"
        if [[ "$class" == "safe_to_wrap" ]]; then
          dry_log "    → Would create wrapper, update cron file, add config (cadence: ${cadence}s)"
        else
          local method output_file unverifiable
          IFS=$'\t' read -r method output_file unverifiable < <(fallback_method_for_monitor_only "$id" "$raw_command" "$cadence")
          dry_log "    → Would add config with monitor_method: $method"
        fi
        continue
      fi

      local wrapper_path="${WRAPPER_DIR}/${id}-heartbeat-wrapper.sh"
      local config_exists=0
      id_in_config "$id" && config_exists=1 || true
      local wrapper_exists=0
      [[ -f "$wrapper_path" ]] && wrapper_exists=1

      if [[ "$class" == "safe_to_wrap" ]]; then
        if (( wrapper_exists == 1 && config_exists == 1 )); then
          log "$id: wrapper and config already present, skipping"
          continue
        fi

        if (( wrapper_exists == 0 )); then
          if ! create_wrapper "$id" "$raw_command" "$prefix" "$executable" "$args"; then
            class="monitor_only"
            reason="wrapper validation failed"
          fi
        fi

        if [[ "$class" == "safe_to_wrap" ]]; then
          local backup_path
          backup_path="${cron_path}.pre-heartbeat"
          if [[ ! -f "$backup_path" ]]; then
            cp "$cron_path" "$backup_path"
          fi

          update_cron_file_with_wrapper "$cron_path" "$wrapper_path"

          if (( config_exists == 0 )); then
            local wrapped_json
            wrapped_json="$(build_wrapped_entry "$id" "$description" "$cron_file" "$cadence" "$(iso_now)" "$wrapper_path")"
            new_entries_json="$(jq --argjson item "$wrapped_json" '. + [$item]' <<<"$new_entries_json")"
          fi

          continue
        fi
      fi

      local method output_file unverifiable
      IFS=$'\t' read -r method output_file unverifiable < <(fallback_method_for_monitor_only "$id" "$raw_command" "$cadence")
      log "$id: monitor_only ($reason), fallback: $method"

      if (( config_exists == 0 )); then
        local mon_json
        mon_json="$(build_monitor_entry "$id" "$description" "$cron_file" "$cadence" "$(iso_now)" "$method" "$output_file" "$unverifiable")"
        new_entries_json="$(jq --argjson item "$mon_json" '. + [$item]' <<<"$new_entries_json")"
      fi
    else
      if id_in_config "$id"; then
        continue
      fi

      if (( DRY_RUN == 1 )); then
        dry_count=$((dry_count + 1))
        dry_log "  $id: systemd timer (${raw_command})"
        dry_log "    → Would add config with monitor_method: systemd_status"
        continue
      fi

      local sys_json
      sys_json="$(build_systemd_entry "$id" "$description" "$raw_command" "$cadence" "$(iso_now)")"
      new_entries_json="$(jq --argjson item "$sys_json" '. + [$item]' <<<"$new_entries_json")"
      log "$id: systemd timer, discovery-only (no wrapping in v1)"
    fi
  done

  if (( DRY_RUN == 1 )); then
    if (( dry_count == 0 )); then
      dry_log "No unmonitored crons found"
    else
      dry_log "Found ${dry_count} unmonitored entries:"
    fi
    dry_log "No files modified."
    return 0
  fi

  append_entries_to_config "$new_entries_json"

  local added
  added="$(jq 'length' <<<"$new_entries_json")"
  if [[ "$added" == "0" ]]; then
    log "No unmonitored crons found"
  else
    log "Added ${added} auto-discovered entries"
  fi
}

main "$@"
