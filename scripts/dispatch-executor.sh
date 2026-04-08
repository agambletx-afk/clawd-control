#!/usr/bin/env bash
set -u
EXECUTOR=""; REPO=""; BRANCH=""; TIMEOUT_SECONDS=300
BRIEF_FILE="/tmp/dispatch-brief-$$.md"; STDOUT_FILE="/tmp/dispatch-stdout-$$.log"; STDERR_FILE="/tmp/dispatch-stderr-$$.log"
status="error"; exit_code=1; error_msg=""; base_commit=""; new_commit=""; brief_hash=""
changed_files_json="[]"; diff_stat=""; diff_text=""; diff_truncated="false"; cli_output_summary=""
start_ts=$(date +%s); repo_ready=0
cleanup(){ rm -f "$BRIEF_FILE" "$STDOUT_FILE" "$STDERR_FILE"; }; trap cleanup EXIT
json_escape(){ sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g' -e 's/\r/\\r/g' -e 's/\t/\\t/g'; }
strip_ansi(){ sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g'; }
to_json_array(){ local first=1 out="[" escaped; while IFS= read -r line; do [ -z "$line" ]&&continue; escaped=$(printf '%s' "$line"|json_escape); [ $first -eq 1 ]&&out="$out\"$escaped\""&&first=0||out="$out,\"$escaped\""; done; printf '%s]' "$out"; }
emit_json(){ local duration_seconds error_json="null"; duration_seconds=$(( $(date +%s)-start_ts )); [ -n "$error_msg" ]&&error_json="\"$(printf '%s' "$error_msg"|json_escape)\""; printf '{"status":"%s","executor":"%s","base_commit":"%s","new_commit":"%s","brief_hash":"%s","changed_files":%s,"diff_stat":"%s","diff_text":"%s","diff_truncated":%s,"exit_code":%s,"cli_output_summary":"%s","error":%s,"duration_seconds":%s}\n' "$status" "$(printf '%s' "$EXECUTOR"|json_escape)" "$(printf '%s' "$base_commit"|json_escape)" "$(printf '%s' "$new_commit"|json_escape)" "$(printf '%s' "$brief_hash"|json_escape)" "$changed_files_json" "$(printf '%s' "$diff_stat"|json_escape)" "$(printf '%s' "$diff_text"|json_escape)" "$diff_truncated" "$exit_code" "$(printf '%s' "$cli_output_summary"|json_escape)" "$error_json" "$duration_seconds"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --executor)
      EXECUTOR="${2:-}"
      shift 2 ;;
    --repo)
      REPO="${2:-}"
      shift 2 ;;
    --branch)
      BRANCH="${2:-}"
      shift 2 ;;
    --timeout)
      TIMEOUT_SECONDS="${2:-}"
      shift 2 ;;
    *)
      error_msg="Unknown argument: $1"
      status="error"
      emit_json; exit 1 ;;
  esac
done

cat > "$BRIEF_FILE"
brief_hash=$(sha256sum "$BRIEF_FILE" | awk '{print $1}')

if [ -z "$EXECUTOR" ] || [ -z "$REPO" ] || [ -z "$BRANCH" ]; then error_msg="Missing required parameters. Required: --executor, --repo, --branch"; status="error"; emit_json; exit 1; fi

if [ "$EXECUTOR" != "codex" ] && [ "$EXECUTOR" != "claude-code" ]; then error_msg="Invalid executor: $EXECUTOR. Expected codex or claude-code"; status="error"; emit_json; exit 1; fi

if ! printf '%s' "$TIMEOUT_SECONDS" | grep -Eq '^[0-9]+$'; then error_msg="Invalid timeout: $TIMEOUT_SECONDS. Must be integer seconds"; status="error"; emit_json; exit 1; fi

if [ ! -d "$REPO" ]; then error_msg="Repository directory not found: $REPO"; status="error"; emit_json; exit 1; fi

if ! git -C "$REPO" rev-parse --is-inside-work-tree >/dev/null 2>&1; then error_msg="Not a git repository: $REPO"; status="error"; emit_json; exit 1; fi

repo_ready=1
cd "$REPO" || { error_msg="Failed to cd into repository: $REPO"; status="error"; emit_json; exit 1; }

if ! git checkout "$BRANCH" >/dev/null 2>&1; then
  error_msg="Failed to checkout branch: $BRANCH"
  status="error"
  exit_code=1
else
  base_commit=$(git rev-parse HEAD 2>/dev/null || printf '')

  if [ "$EXECUTOR" = "codex" ]; then
    timeout "$TIMEOUT_SECONDS" codex exec "Implement the brief below. Read it carefully." --sandbox workspace-write --json --no-color < "$BRIEF_FILE" > "$STDOUT_FILE" 2> "$STDERR_FILE"; exit_code=$?
  else
    timeout "$TIMEOUT_SECONDS" claude -p "Implement the brief below. Read it carefully." --output-format json --no-ansi < "$BRIEF_FILE" > "$STDOUT_FILE" 2> "$STDERR_FILE"; exit_code=$?
  fi

  cli_output_summary=$(tail -c 500 "$STDOUT_FILE" 2>/dev/null | strip_ansi)

  if [ "$exit_code" -eq 0 ]; then status="success"; elif [ "$exit_code" -eq 124 ] || [ "$exit_code" -eq 137 ]; then status="timeout"; else status="failure"; fi

  if [ "$exit_code" -ne 0 ]; then stderr_snippet=$(head -c 200 "$STDERR_FILE" 2>/dev/null | strip_ansi); error_msg="CLI exited with code $exit_code"; [ -n "$stderr_snippet" ] && error_msg="$error_msg: $stderr_snippet"; fi
fi

if [ $repo_ready -eq 1 ]; then
  new_commit=$(git rev-parse HEAD 2>/dev/null || printf '')
  [ -z "$base_commit" ] && base_commit="$new_commit"

  changed_files_json=$(git diff --name-only "$base_commit" HEAD 2>/dev/null | to_json_array)
  diff_stat=$(git diff --stat --no-color "$base_commit" HEAD 2>/dev/null | strip_ansi)

  diff_text=$(git diff --no-color "$base_commit" HEAD 2>/dev/null | strip_ansi)
  diff_bytes=$(printf '%s' "$diff_text" | wc -c | tr -d ' ')
  if [ "$diff_bytes" -gt 51200 ]; then diff_text=$(printf '%s' "$diff_text" | head -c 51200); diff_truncated="true"; fi
fi

emit_json

[ "$status" = "success" ] && exit 0
exit 1
