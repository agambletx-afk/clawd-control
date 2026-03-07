#!/bin/bash
set -euo pipefail

SESSIONS_DIR="${SESSIONS_DIR:-/home/openclaw/.openclaw/agents/main/sessions}"
MAX_SIZE="${MAX_SIZE:-256000}"
SESSIONS_INDEX="$SESSIONS_DIR/sessions.json"

log_json() {
  local action="$1"
  local session_id="${2:-}"
  local file_size="${3:-}"
  local file_path="${4:-}"

  jq -nc \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg action "$action" \
    --arg session_id "$session_id" \
    --arg file_path "$file_path" \
    --arg file_size "$file_size" \
    '{timestamp:$timestamp,action:$action,sessionId:(if $session_id=="" then null else $session_id end),file:(if $file_path=="" then null else $file_path end),fileSize:(if $file_size=="" then null else ($file_size|tonumber) end)}'
}

require_prereqs() {
  [[ -d "$SESSIONS_DIR" ]] || {
    log_json "error" "" "" "$SESSIONS_DIR"
    echo "missing sessions directory: $SESSIONS_DIR" >&2
    exit 1
  }

  [[ -f "$SESSIONS_INDEX" ]] || {
    log_json "error" "" "" "$SESSIONS_INDEX"
    echo "missing sessions index: $SESSIONS_INDEX" >&2
    exit 1
  }

  [[ "$MAX_SIZE" =~ ^[0-9]+$ ]] || {
    log_json "error"
    echo "MAX_SIZE must be an integer" >&2
    exit 1
  }
}

cleanup_debris() {
  while IFS= read -r debris; do
    rm -f -- "$debris"
    log_json "delete_debris" "" "" "$debris"
  done < <(
    find "$SESSIONS_DIR" -mindepth 1 -maxdepth 1 -type f \
      \( -name '.deleted.*' -o -name '.bak*' -o -name '*.tmp' -o -name '*.lock' \) -print
  )
}

session_is_active() {
  local session_id="$1"
  jq -e --arg sid "$session_id" '[.[] | .sessionId] | index($sid) != null' "$SESSIONS_INDEX" >/dev/null
}

remove_session_from_index() {
  local session_id="$1"
  local tmp_file
  tmp_file=$(mktemp "$SESSIONS_DIR/sessions.json.tmp.XXXXXX")

  jq --arg sid "$session_id" 'with_entries(select(.value.sessionId != $sid))' "$SESSIONS_INDEX" > "$tmp_file"
  mv "$tmp_file" "$SESSIONS_INDEX"
  log_json "remove_session_index" "$session_id" "" "$SESSIONS_INDEX"
}

process_jsonl_files() {
  while IFS= read -r session_file; do
    local filename session_id size
    filename=$(basename "$session_file")
    session_id="${filename%.jsonl}"

    if ! [[ "$session_id" =~ ^[0-9a-fA-F-]{36}$ ]]; then
      continue
    fi

    if ! session_is_active "$session_id"; then
      rm -f -- "$session_file"
      log_json "delete_orphan_session" "$session_id" "" "$session_file"
      continue
    fi

    size=$(stat -c '%s' "$session_file")
    if (( size > MAX_SIZE )); then
      rm -f -- "$session_file"
      log_json "rotate_oversized_session" "$session_id" "$size" "$session_file"
      remove_session_from_index "$session_id"
    fi
  done < <(find "$SESSIONS_DIR" -mindepth 1 -maxdepth 1 -type f -name '*.jsonl' -print)
}

main() {
  require_prereqs
  cleanup_debris
  process_jsonl_files
  log_json "completed"
}

main "$@"
