#!/bin/bash
set -euo pipefail

SESSIONS_DIR="${SESSIONS_DIR:-/home/openclaw/.openclaw/agents/main/sessions}"
MAX_SIZE="${MAX_SIZE:-256000}"
SESSIONS_INDEX="$SESSIONS_DIR/sessions.json"
ARCHIVE_DIR="${ARCHIVE_DIR:-/home/openclaw/.openclaw/workspace/sessions-archive}"
ARCHIVE_RETENTION_DAYS="${ARCHIVE_RETENTION_DAYS:-7}"

log_json() {
  local action="$1"
  local session_id="${2:-}"
  local file_size="${3:-}"
  local file_path="${4:-}"
  local detail="${5:-}"

  jq -nc \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg action "$action" \
    --arg session_id "$session_id" \
    --arg file_path "$file_path" \
    --arg file_size "$file_size" \
    --arg detail "$detail" \
    '{timestamp:$timestamp,action:$action,sessionId:(if $session_id=="" then null else $session_id end),file:(if $file_path=="" then null else $file_path end),fileSize:(if $file_size=="" then null else ($file_size|tonumber) end),detail:(if $detail=="" then null else $detail end)}'
}

require_prereqs() {
  [[ -d "$SESSIONS_DIR" ]] || {
    log_json "error" "" "" "$SESSIONS_DIR" "missing sessions directory"
    echo "missing sessions directory: $SESSIONS_DIR" >&2
    exit 1
  }

  [[ -f "$SESSIONS_INDEX" ]] || {
    log_json "error" "" "" "$SESSIONS_INDEX" "missing sessions index"
    echo "missing sessions index: $SESSIONS_INDEX" >&2
    exit 1
  }

  [[ "$MAX_SIZE" =~ ^[0-9]+$ ]] || {
    log_json "error" "" "" "" "MAX_SIZE must be an integer"
    echo "MAX_SIZE must be an integer" >&2
    exit 1
  }

  [[ "$ARCHIVE_RETENTION_DAYS" =~ ^[0-9]+$ ]] || {
    log_json "error" "" "" "" "ARCHIVE_RETENTION_DAYS must be an integer"
    echo "ARCHIVE_RETENTION_DAYS must be an integer" >&2
    exit 1
  }

  mkdir -p "$ARCHIVE_DIR"
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

session_entry() {
  local session_id="$1"
  jq -c --arg sid "$session_id" '
    if type == "array" then
      first(.[] | select(.sessionId == $sid))
    elif type == "object" then
      first(.[] | select((.sessionId // "") == $sid))
    else
      empty
    end
  ' "$SESSIONS_INDEX"
}

session_state() {
  local session_id="$1"
  local entry
  entry="$(session_entry "$session_id")"
  if [[ -z "$entry" ]]; then
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

archive_session() {
  local session_id="$1"
  local session_file="$2"
  local size="$3"
  local ts dest
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  dest="$ARCHIVE_DIR/${session_id}-${ts}.jsonl"

  mv -- "$session_file" "$dest"
  log_json "archive_oversized_session" "$session_id" "$size" "$dest" "archived oversized idle/closed session"
}

process_jsonl_files() {
  while IFS= read -r session_file; do
    local filename session_id size state
    filename=$(basename "$session_file")
    session_id="${filename%.jsonl}"

    if ! [[ "$session_id" =~ ^[0-9a-fA-F-]{36}$ ]]; then
      continue
    fi

    size=$(stat -c '%s' "$session_file")
    if (( size <= MAX_SIZE )); then
      continue
    fi

    state="$(session_state "$session_id")"

    case "$state" in
      archivable)
        archive_session "$session_id" "$session_file" "$size"
        ;;
      active)
        log_json "skip_active_oversized_session" "$session_id" "$size" "$session_file" "session is active; archival skipped"
        ;;
      *)
        log_json "skip_unknown_state_oversized_session" "$session_id" "$size" "$session_file" "session state unknown; archival skipped"
        ;;
    esac
  done < <(find "$SESSIONS_DIR" -mindepth 1 -maxdepth 1 -type f -name '*.jsonl' -print)
}

cleanup_archive() {
  while IFS= read -r archived; do
    local size
    size=$(stat -c '%s' "$archived")
    rm -f -- "$archived"
    log_json "delete_expired_archive" "" "$size" "$archived" "archive retention exceeded ${ARCHIVE_RETENTION_DAYS} days"
  done < <(find "$ARCHIVE_DIR" -mindepth 1 -type f -name '*.jsonl' -mtime "+$ARCHIVE_RETENTION_DAYS" -print)
}

main() {
  require_prereqs
  cleanup_debris
  process_jsonl_files
  cleanup_archive
  log_json "completed"
}

main "$@"
