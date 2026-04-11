#!/usr/bin/env bash
set -u

# dispatch-executor.sh v2.0
# Unified dispatch wrapper for Codex (repo files) and Claude Code (repo + non-repo files)
#
# REPO PATH:     --executor codex --repo /path --branch feat/x < brief.md
# NON-REPO PATH: --executor claude-code --target-files "/usr/local/bin/foo.sh,/etc/bar.json" < brief.md
# HYBRID:        --executor claude-code --repo /path --branch feat/x < brief.md  (Claude Code on repo)

EXECUTOR=""; REPO=""; BRANCH=""; TIMEOUT_SECONDS=300; TARGET_FILES=""
BRIEF_FILE="/tmp/dispatch-brief-$$.md"
STDOUT_FILE="/tmp/dispatch-stdout-$$.log"
STDERR_FILE="/tmp/dispatch-stderr-$$.log"

status="error"; exit_code=1; error_msg=""
base_commit=""; new_commit=""; brief_hash=""
changed_files_json="[]"; diff_stat=""; diff_text=""; diff_truncated="false"
cli_output_summary=""; staging_dir=""

start_ts=$(date +%s); repo_ready=0; is_nonrepo=0

cleanup_tmp(){ rm -f "$BRIEF_FILE" "$STDOUT_FILE" "$STDERR_FILE"; }
trap cleanup_tmp EXIT

json_escape(){ sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e ':a;N;$!ba;s/\n/\\n/g' -e 's/\r/\\r/g' -e 's/\t/\\t/g'; }
strip_ansi(){ sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g'; }
to_json_array(){ local first=1 out="[" escaped; while IFS= read -r line; do [ -z "$line" ] && continue; escaped=$(printf '%s' "$line" | json_escape); [ $first -eq 1 ] && out="$out\"$escaped\"" && first=0 || out="$out,\"$escaped\""; done; printf '%s]' "$out"; }

emit_json(){
  local duration_seconds error_json="null" staging_json="null"
  duration_seconds=$(( $(date +%s) - start_ts ))
  [ -n "$error_msg" ] && error_json="\"$(printf '%s' "$error_msg" | json_escape)\""
  [ -n "$staging_dir" ] && staging_json="\"$(printf '%s' "$staging_dir" | json_escape)\""
  printf '{"status":"%s","executor":"%s","base_commit":"%s","new_commit":"%s","brief_hash":"%s","changed_files":%s,"diff_stat":"%s","diff_text":"%s","diff_truncated":%s,"exit_code":%s,"cli_output_summary":"%s","error":%s,"staging_dir":%s,"duration_seconds":%s}\n' \
    "$status" \
    "$(printf '%s' "$EXECUTOR" | json_escape)" \
    "$(printf '%s' "$base_commit" | json_escape)" \
    "$(printf '%s' "$new_commit" | json_escape)" \
    "$(printf '%s' "$brief_hash" | json_escape)" \
    "$changed_files_json" \
    "$(printf '%s' "$diff_stat" | json_escape)" \
    "$(printf '%s' "$diff_text" | json_escape)" \
    "$diff_truncated" \
    "$exit_code" \
    "$(printf '%s' "$cli_output_summary" | json_escape)" \
    "$error_json" \
    "$staging_json" \
    "$duration_seconds"
}

# --- Parse arguments ---
while [ $# -gt 0 ]; do
  case "$1" in
    --executor)      EXECUTOR="${2:-}";        shift 2 ;;
    --repo)          REPO="${2:-}";             shift 2 ;;
    --branch)        BRANCH="${2:-}";           shift 2 ;;
    --timeout)       TIMEOUT_SECONDS="${2:-}";  shift 2 ;;
    --target-files)  TARGET_FILES="${2:-}";     shift 2 ;;
    *) error_msg="Unknown argument: $1"; emit_json; exit 1 ;;
  esac
done

# --- Read brief from stdin ---
cat > "$BRIEF_FILE"
brief_hash=$(sha256sum "$BRIEF_FILE" | awk '{print $1}')

# --- Validate common params ---
if [ -z "$EXECUTOR" ]; then
  error_msg="Missing required parameter: --executor"
  emit_json; exit 1
fi

if [ "$EXECUTOR" != "codex" ] && [ "$EXECUTOR" != "claude-code" ]; then
  error_msg="Invalid executor: $EXECUTOR. Expected codex or claude-code"
  emit_json; exit 1
fi

if ! printf '%s' "$TIMEOUT_SECONDS" | grep -Eq '^[0-9]+$'; then
  error_msg="Invalid timeout: $TIMEOUT_SECONDS. Must be integer seconds"
  emit_json; exit 1
fi

# --- Determine path: repo or non-repo ---
if [ -n "$TARGET_FILES" ]; then
  # ============================================================
  # NON-REPO PATH: staging-based editing
  # ============================================================
  is_nonrepo=1

  if [ "$EXECUTOR" = "codex" ]; then
    error_msg="Codex executor cannot be used with --target-files. Use claude-code."
    emit_json; exit 1
  fi

  # Create staging directory
  staging_dir="/tmp/jarvis-staging-$(date +%s)-$$"
  mkdir -p "$staging_dir/originals" "$staging_dir/work"

  # Build manifest
  manifest="$staging_dir/manifest.json"
  printf '[\n' > "$manifest"
  first_file=1

  IFS=',' read -ra FILE_LIST <<< "$TARGET_FILES"
  for target_path in "${FILE_LIST[@]}"; do
    # Trim whitespace
    target_path=$(printf '%s' "$target_path" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [ -z "$target_path" ] && continue

    # Derive a safe filename for staging (replace / with __)
    safe_name=$(printf '%s' "$target_path" | sed 's|^/||;s|/|__|g')

    is_new="false"
    file_owner=""; file_mode=""; file_immutable="false"

    if [ -f "$target_path" ]; then
      # Validate text file
      mime_type=$(file --mime-type -b "$target_path" 2>/dev/null || echo "unknown")
      case "$mime_type" in
        text/*|application/json|application/xml|application/x-shellscript|inode/x-empty) ;;
        *)
          error_msg="Target file is not a text file: $target_path (mime: $mime_type)"
          rm -rf "$staging_dir"; staging_dir=""
          emit_json; exit 1
          ;;
      esac

      # Capture metadata
      file_owner=$(stat -c '%u:%g' "$target_path" 2>/dev/null || echo "1000:1000")
      file_mode=$(stat -c '%a' "$target_path" 2>/dev/null || echo "644")

      # Check immutable flag
      if lsattr "$target_path" 2>/dev/null | grep -q -- '----i'; then
        file_immutable="true"
      fi

      # Copy to originals and work
      cp -p "$target_path" "$staging_dir/originals/$safe_name"
      cp -p "$target_path" "$staging_dir/work/$safe_name"
    else
      # New file: no original to copy
      is_new="true"
      file_owner="1000:1000"
      file_mode="644"
      touch "$staging_dir/work/$safe_name"
    fi

    # Write manifest entry
    [ $first_file -eq 0 ] && printf ',\n' >> "$manifest"
    printf '  {"path":"%s","safe_name":"%s","owner":"%s","mode":"%s","immutable":%s,"is_new":%s}' \
      "$(printf '%s' "$target_path" | json_escape)" \
      "$(printf '%s' "$safe_name" | json_escape)" \
      "$file_owner" \
      "$file_mode" \
      "$file_immutable" \
      "$is_new" >> "$manifest"
    first_file=0
  done

  printf '\n]\n' >> "$manifest"

  # Run Claude Code against staging work directory
  timeout "$TIMEOUT_SECONDS" claude -p \
    "Implement the brief below. Read it carefully. The files in this directory are copies of production files. Edit them as needed." \
    --cwd "$staging_dir/work" --output-format json --no-ansi \
    < "$BRIEF_FILE" > "$STDOUT_FILE" 2> "$STDERR_FILE"
  exit_code=$?

  cli_output_summary=$(tail -c 500 "$STDOUT_FILE" 2>/dev/null | strip_ansi)

  if [ "$exit_code" -eq 0 ]; then status="success"
  elif [ "$exit_code" -eq 124 ] || [ "$exit_code" -eq 137 ]; then status="timeout"
  else status="failure"; fi

  if [ "$exit_code" -ne 0 ]; then
    stderr_snippet=$(head -c 200 "$STDERR_FILE" 2>/dev/null | strip_ansi)
    error_msg="CLI exited with code $exit_code"
    [ -n "$stderr_snippet" ] && error_msg="$error_msg: $stderr_snippet"
  fi

  # Compute diffs for all staged files
  all_diffs=""
  changed_list=""
  for target_path in "${FILE_LIST[@]}"; do
    target_path=$(printf '%s' "$target_path" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [ -z "$target_path" ] && continue
    safe_name=$(printf '%s' "$target_path" | sed 's|^/||;s|/|__|g')

    orig_file="$staging_dir/originals/$safe_name"
    work_file="$staging_dir/work/$safe_name"

    # For new files, diff against /dev/null
    [ ! -f "$orig_file" ] && orig_file="/dev/null"

    file_diff=$(diff -u "$orig_file" "$work_file" 2>/dev/null || true)
    if [ -n "$file_diff" ]; then
      # Re-label diff header with actual production paths
      file_diff=$(printf '%s\n' "$file_diff" | sed "1s|^--- .*|--- a$target_path|;2s|^+++ .*|+++ b$target_path|")
      all_diffs="${all_diffs}${file_diff}
"
      changed_list="${changed_list}${target_path}
"
    fi
  done

  diff_text=$(printf '%s' "$all_diffs")
  diff_bytes=$(printf '%s' "$diff_text" | wc -c | tr -d ' ')
  if [ "$diff_bytes" -gt 51200 ]; then
    diff_text=$(printf '%s' "$diff_text" | head -c 51200)
    diff_truncated="true"
  fi

  changed_files_json=$(printf '%s' "$changed_list" | to_json_array)
  diff_stat="non-repo staging diff: $diff_bytes bytes"

  # If no changes detected
  if [ -z "$(printf '%s' "$changed_list" | tr -d '[:space:]')" ] && [ "$status" = "success" ]; then
    status="no_changes"
  fi

else
  # ============================================================
  # REPO PATH (original behavior, unchanged)
  # ============================================================
  if [ -z "$REPO" ] || [ -z "$BRANCH" ]; then
    error_msg="Repo path requires --repo and --branch"
    emit_json; exit 1
  fi

  if [ ! -d "$REPO" ]; then
    error_msg="Repository directory not found: $REPO"
    emit_json; exit 1
  fi

  if ! git -C "$REPO" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    error_msg="Not a git repository: $REPO"
    emit_json; exit 1
  fi

  repo_ready=1
  cd "$REPO" || { error_msg="Failed to cd into repository: $REPO"; emit_json; exit 1; }

  if ! git checkout "$BRANCH" >/dev/null 2>&1; then
    error_msg="Failed to checkout branch: $BRANCH"
    exit_code=1
  else
    base_commit=$(git rev-parse HEAD 2>/dev/null || printf '')

    if [ "$EXECUTOR" = "codex" ]; then
      timeout "$TIMEOUT_SECONDS" codex exec "Implement the brief below. Read it carefully." \
        --sandbox workspace-write --json --no-color \
        < "$BRIEF_FILE" > "$STDOUT_FILE" 2> "$STDERR_FILE"
      exit_code=$?
    else
      timeout "$TIMEOUT_SECONDS" claude -p "Implement the brief below. Read it carefully." \
        --output-format json --no-ansi \
        < "$BRIEF_FILE" > "$STDOUT_FILE" 2> "$STDERR_FILE"
      exit_code=$?
    fi

    cli_output_summary=$(tail -c 500 "$STDOUT_FILE" 2>/dev/null | strip_ansi)

    if [ "$exit_code" -eq 0 ]; then status="success"
    elif [ "$exit_code" -eq 124 ] || [ "$exit_code" -eq 137 ]; then status="timeout"
    else status="failure"; fi

    if [ "$exit_code" -ne 0 ]; then
      stderr_snippet=$(head -c 200 "$STDERR_FILE" 2>/dev/null | strip_ansi)
      error_msg="CLI exited with code $exit_code"
      [ -n "$stderr_snippet" ] && error_msg="$error_msg: $stderr_snippet"
    fi
  fi

  if [ $repo_ready -eq 1 ]; then
    new_commit=$(git rev-parse HEAD 2>/dev/null || printf '')
    [ -z "$base_commit" ] && base_commit="$new_commit"
    changed_files_json=$(git diff --name-only "$base_commit" HEAD 2>/dev/null | to_json_array)
    diff_stat=$(git diff --stat --no-color "$base_commit" HEAD 2>/dev/null | strip_ansi)
    diff_text=$(git diff --no-color "$base_commit" HEAD 2>/dev/null | strip_ansi)
    diff_bytes=$(printf '%s' "$diff_text" | wc -c | tr -d ' ')
    if [ "$diff_bytes" -gt 51200 ]; then
      diff_text=$(printf '%s' "$diff_text" | head -c 51200)
      diff_truncated="true"
    fi
  fi
fi

emit_json

[ "$status" = "success" ] && exit 0
exit 1
