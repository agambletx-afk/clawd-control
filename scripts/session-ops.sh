#!/usr/bin/env bash
set -euo pipefail

DEFAULT_MAX_SIZE=256000
CONFIG_FILE="/etc/jarvis/session-ops.conf"
AGENTS_ROOT="/home/openclaw/.openclaw/agents"
DOCTOR_MAX_AGE_SEC=300
SCRIPT_MAX_AGE_SEC=300

log() {
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] session-ops: $*"
}

load_threshold_for_agent() {
  local agent_id="$1"
  local threshold="$DEFAULT_MAX_SIZE"

  if [[ -f "$CONFIG_FILE" ]]; then
    while IFS=':' read -r cfg_agent cfg_size _rest; do
      [[ -z "${cfg_agent:-}" ]] && continue
      [[ "${cfg_agent:0:1}" == "#" ]] && continue
      if [[ "$cfg_agent" == "$agent_id" && "$cfg_size" =~ ^[0-9]+$ ]]; then
        threshold="$cfg_size"
      fi
    done < "$CONFIG_FILE"
  fi

  echo "$threshold"
}

kill_pid_with_timeout() {
  local pid="$1"
  timeout --signal=KILL 2s setsid bash -c "kill -TERM '$pid' 2>/dev/null || true; while kill -0 '$pid' 2>/dev/null; do sleep 0.1; done" >/dev/null 2>&1 || true
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
  fi
}

cleanup_processes() {
  log "phase 1/3: process cleanup"

  while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue
    local age
    age="$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ' || true)"
    if [[ -n "$age" && "$age" =~ ^[0-9]+$ && "$age" -gt "$DOCTOR_MAX_AGE_SEC" ]]; then
      kill_pid_with_timeout "$pid"
      log "killed stale openclaw-doctor pid=$pid age=${age}s"
    fi
  done < <(pgrep -f 'openclaw-doctor' 2>/dev/null || true)

  for pattern in 'check-security-health\.sh' 'run-security-test\.sh'; do
    while IFS= read -r pid; do
      [[ -z "$pid" ]] && continue
      local age
      age="$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ' || true)"
      if [[ -n "$age" && "$age" =~ ^[0-9]+$ && "$age" -gt "$SCRIPT_MAX_AGE_SEC" ]]; then
        kill -KILL "$pid" 2>/dev/null || true
        log "killed stuck script pid=$pid pattern=$pattern age=${age}s"
      fi
    done < <(pgrep -f "$pattern" 2>/dev/null || true)
  done
}

discover_session_dirs() {
  local dir
  for dir in "$AGENTS_ROOT"/*/sessions/; do
    [[ -d "$dir" ]] || continue
    printf '%s\n' "${dir%/}"
  done

  return 0
}

cleanup_temp_files() {
  log "phase 2/3: temp file cleanup"
  local dir debris
  while IFS= read -r dir; do
    while IFS= read -r debris; do
      rm -f -- "$debris"
      log "removed temp/debris file: $debris"
    done < <(find "$dir" -mindepth 1 -maxdepth 1 -type f \( -name '*.tmp' -o -name '*.lock' -o -name '*.bak' -o -name '.deleted.*' \) -print)
  done < <(discover_session_dirs)
}

session_state() {
  local index_file="$1"
  local session_id="$2"
  local entry

  entry="$(jq -c --arg sid "$session_id" '
    if type == "array" then
      first(.[] | select((.sessionId // .id // "") == $sid))
    elif type == "object" then
      first(to_entries[]?.value | select((.sessionId // .id // "") == $sid))
    else
      empty
    end
  ' "$index_file" 2>/dev/null || true)"

  if [[ -z "$entry" || "$entry" == "null" ]]; then
    echo "unknown"
    return
  fi

  if jq -e '((.isActive // false) == true) or ((.active // false) == true) or ((.status // "") | ascii_downcase | test("active|running|open")) or ((.state // "") | ascii_downcase | test("active|running|open"))' >/dev/null <<<"$entry"; then
    echo "active"
    return
  fi

  if jq -e '((.isActive // true) == false) or ((.active // true) == false) or ((.status // "") | ascii_downcase | test("idle|closed|inactive|archived|complete|completed")) or ((.state // "") | ascii_downcase | test("idle|closed|inactive|archived|complete|completed")) or (.closedAt != null) or (.endedAt != null)' >/dev/null <<<"$entry"; then
    echo "archivable"
    return
  fi

  echo "unknown"
}

rotate_oversized_sessions() {
  local agent_id="$1"
  local sessions_dir="$2"
  local threshold="$3"
  local index_file="$sessions_dir/sessions.json"
  local archive_dir="$sessions_dir/archive"

  [[ -f "$index_file" ]] || {
    log "skip rotation for agent=$agent_id (missing sessions.json)"
    return
  }

  mkdir -p "$archive_dir"

  local session_file
  while IFS= read -r session_file; do
    local filename session_id size state ts archived_file
    filename="$(basename "$session_file")"
    session_id="${filename%.jsonl}"
    [[ "$session_id" =~ ^[0-9a-fA-F-]{36}$ ]] || continue

    size="$(stat -c '%s' "$session_file")"
    (( size > threshold )) || continue

    state="$(session_state "$index_file" "$session_id")"
    if [[ "$state" != "active" ]]; then
      log "skip oversized session agent=$agent_id session=$session_id size=$size state=$state"
      continue
    fi

    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    archived_file="$archive_dir/${session_id}-${ts}.jsonl"

    mv -- "$session_file" "$archived_file"
    : > "$session_file"
    log "rotated oversized session agent=$agent_id session=$session_id size=$size archive=$archived_file"

    local tmp_json
    tmp_json="$(mktemp)"
    jq --arg sid "$session_id" --arg rotated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
      if type == "array" then
        map(if (.sessionId // .id // "") == $sid then . + {lastRotatedAt: $rotated_at} else . end)
      elif type == "object" then
        with_entries(
          if ((.value.sessionId // .value.id // "") == $sid)
          then .value = (.value + {lastRotatedAt: $rotated_at})
          else .
          end
        )
      else .
      end
    ' "$index_file" > "$tmp_json"
    mv "$tmp_json" "$index_file"
  done < <(find "$sessions_dir" -mindepth 1 -maxdepth 1 -type f -name '*.jsonl' -print)
}

cleanup_orphan_jsonl() {
  local agent_id="$1"
  local sessions_dir="$2"
  local index_file="$sessions_dir/sessions.json"

  [[ -f "$index_file" ]] || return

  local referenced_file
  local -A referenced=()
  while IFS= read -r referenced_file; do
    [[ -z "$referenced_file" ]] && continue
    referenced["$referenced_file"]=1
    referenced["$(basename "$referenced_file")"]=1
  done < <(jq -r '
    [
      .. | objects | .sessionFile?,
      .. | objects | .file?,
      .. | objects | .path?,
      .. | objects | .jsonl?
    ] | map(select(type == "string" and endswith(".jsonl"))) | unique[]?
  ' "$index_file" 2>/dev/null || true)

  local jsonl_file base
  while IFS= read -r jsonl_file; do
    base="$(basename "$jsonl_file")"
    if [[ -z "${referenced[$jsonl_file]+x}" && -z "${referenced[$base]+x}" ]]; then
      rm -f -- "$jsonl_file"
      log "removed orphan jsonl agent=$agent_id file=$jsonl_file"
    fi
  done < <(find "$sessions_dir" -mindepth 1 -maxdepth 1 -type f -name '*.jsonl' -print)
}

rotate_and_prune_sessions() {
  log "phase 3/3: session rotation + orphan cleanup"
  local sessions_dir agent_id threshold
  while IFS= read -r sessions_dir; do
    agent_id="$(basename "$(dirname "$sessions_dir")")"
    threshold="$(load_threshold_for_agent "$agent_id")"
    log "processing agent=$agent_id dir=$sessions_dir threshold=$threshold"
    rotate_oversized_sessions "$agent_id" "$sessions_dir" "$threshold"
    cleanup_orphan_jsonl "$agent_id" "$sessions_dir"
  done < <(discover_session_dirs)
}

main() {
  cleanup_processes
  cleanup_temp_files
  rotate_and_prune_sessions
  log "completed"
}

main "$@"
