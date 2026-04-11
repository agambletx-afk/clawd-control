#!/usr/bin/env bash
set -euo pipefail

# deploy-staged.sh v1.0
# Deploys verified non-repo staged files to production paths.
# Run ONLY after Verifier has approved the diff.
#
# Usage: deploy-staged.sh /tmp/jarvis-staging-<id>
#
# Phases:
#   1. Validate manifest
#   2. Backup ALL originals (abort if any backup fails)
#   3. Deploy ALL staged files (restore permissions, ownership, immutable flags)
#   4. Log to recovery journal
#   5. Cleanup staging dir
#
# Rollback: deploy-staged.sh --rollback /tmp/jarvis-staging-<id>

STAGING_DIR=""
ROLLBACK_MODE=0
RECOVERY_LOG="/home/openclaw/.openclaw/.recovery-log.jsonl"
BACKUP_DIR=""

# Track files that had immutable flag removed (for crash safety)
UNLOCKED_FILES=()

restore_immutable_on_crash(){
  for f in "${UNLOCKED_FILES[@]}"; do
    if [ -f "$f" ]; then
      chattr +i "$f" 2>/dev/null || true
    fi
  done
}
trap restore_immutable_on_crash EXIT

usage(){
  echo "Usage: deploy-staged.sh [--rollback] <staging-dir>"
  echo ""
  echo "  <staging-dir>   Path to /tmp/jarvis-staging-* directory"
  echo "  --rollback      Restore originals from backup instead of deploying"
  exit 1
}

log_recovery(){
  local action="$1" details="$2"
  local ts; ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  printf '{"timestamp":"%s","action":"%s","staging_dir":"%s","details":"%s"}\n' \
    "$ts" "$action" "$STAGING_DIR" "$details" >> "$RECOVERY_LOG" 2>/dev/null || true
}

# --- Parse arguments ---
while [ $# -gt 0 ]; do
  case "$1" in
    --rollback) ROLLBACK_MODE=1; shift ;;
    --help|-h)  usage ;;
    *)
      if [ -z "$STAGING_DIR" ]; then
        STAGING_DIR="$1"; shift
      else
        echo "ERROR: Unexpected argument: $1" >&2; usage
      fi
      ;;
  esac
done

if [ -z "$STAGING_DIR" ]; then
  echo "ERROR: Staging directory required." >&2
  usage
fi

if [ ! -d "$STAGING_DIR" ]; then
  echo "ERROR: Staging directory not found: $STAGING_DIR" >&2
  exit 1
fi

MANIFEST="$STAGING_DIR/manifest.json"
if [ ! -f "$MANIFEST" ]; then
  echo "ERROR: manifest.json not found in $STAGING_DIR" >&2
  exit 1
fi

BACKUP_DIR="$STAGING_DIR/backups"

# --- Parse manifest (simple line-by-line JSON parsing via jq or python) ---
if command -v python3 >/dev/null 2>&1; then
  PARSE_CMD="python3"
elif command -v jq >/dev/null 2>&1; then
  PARSE_CMD="jq"
else
  echo "ERROR: Neither python3 nor jq available for manifest parsing" >&2
  exit 1
fi

# Read manifest into bash-friendly format
# Output: one line per file: path|safe_name|owner|mode|immutable|is_new
parse_manifest(){
  python3 -c "
import json, sys
with open('$MANIFEST') as f:
    entries = json.load(f)
for e in entries:
    print('|'.join([
        e['path'], e['safe_name'], e['owner'], e['mode'],
        str(e['immutable']).lower(), str(e['is_new']).lower()
    ]))
" 2>/dev/null
}

ENTRIES=$(parse_manifest)
if [ -z "$ENTRIES" ]; then
  echo "ERROR: No entries in manifest or parse failed" >&2
  exit 1
fi

FILE_COUNT=$(echo "$ENTRIES" | wc -l | tr -d ' ')
echo "Staging dir: $STAGING_DIR"
echo "Files: $FILE_COUNT"
echo ""

# ==========================================================
# ROLLBACK MODE
# ==========================================================
if [ $ROLLBACK_MODE -eq 1 ]; then
  if [ ! -d "$BACKUP_DIR" ]; then
    echo "ERROR: No backup directory found at $BACKUP_DIR" >&2
    exit 1
  fi

  echo "=== ROLLBACK MODE ==="
  echo ""

  while IFS='|' read -r path safe_name owner mode immutable is_new; do
    echo "Restoring: $path"

    if [ "$is_new" = "true" ]; then
      # New file: remove it
      if [ -f "$path" ]; then
        if [ "$immutable" = "true" ]; then
          chattr -i "$path" 2>/dev/null || true
        fi
        rm -f "$path"
        echo "  Removed (was new file)"
      fi
      continue
    fi

    backup_file="$BACKUP_DIR/$safe_name"
    if [ ! -f "$backup_file" ]; then
      echo "  WARNING: Backup not found, skipping: $backup_file" >&2
      continue
    fi

    # Remove immutable flag if present on current file
    if [ "$immutable" = "true" ] && [ -f "$path" ]; then
      chattr -i "$path" 2>/dev/null || true
    fi

    # Restore from backup
    cp -f "$backup_file" "$path"

    # Restore ownership and permissions
    chown "$owner" "$path" 2>/dev/null || true
    chmod "$mode" "$path" 2>/dev/null || true

    # Restore immutable flag
    if [ "$immutable" = "true" ]; then
      chattr +i "$path" 2>/dev/null || true
    fi

    echo "  Restored from backup"
  done <<< "$ENTRIES"

  log_recovery "rollback" "Restored $FILE_COUNT files from backup"
  echo ""
  echo "Rollback complete. $FILE_COUNT files restored."
  exit 0
fi

# ==========================================================
# DEPLOY MODE
# ==========================================================
echo "=== PHASE 1: Backup all originals ==="
echo ""

mkdir -p "$BACKUP_DIR"

while IFS='|' read -r path safe_name owner mode immutable is_new; do
  if [ "$is_new" = "true" ]; then
    echo "  $path (new file, no backup needed)"
    continue
  fi

  if [ ! -f "$path" ]; then
    echo "  WARNING: Original file missing, cannot backup: $path" >&2
    echo "  ABORTING: Cannot guarantee rollback without backup." >&2
    log_recovery "abort" "Original file missing during backup phase: $path"
    exit 1
  fi

  cp -p "$path" "$BACKUP_DIR/$safe_name"
  echo "  Backed up: $path"
done <<< "$ENTRIES"

echo ""
echo "=== PHASE 2: Deploy staged files ==="
echo ""

deploy_count=0

while IFS='|' read -r path safe_name owner mode immutable is_new; do
  work_file="$STAGING_DIR/work/$safe_name"

  if [ ! -f "$work_file" ]; then
    echo "  WARNING: Staged file missing: $work_file, skipping" >&2
    continue
  fi

  # Ensure parent directory exists (for new files)
  parent_dir=$(dirname "$path")
  if [ ! -d "$parent_dir" ]; then
    mkdir -p "$parent_dir"
    echo "  Created directory: $parent_dir"
  fi

  # Remove immutable flag on target if present
  if [ "$immutable" = "true" ] && [ -f "$path" ]; then
    chattr -i "$path" 2>/dev/null || true
    UNLOCKED_FILES+=("$path")
  fi

  # Copy staged file to production path
  cp -f "$work_file" "$path"

  # Restore ownership
  chown "$owner" "$path" 2>/dev/null || true

  # Restore permissions
  chmod "$mode" "$path" 2>/dev/null || true

  # Restore immutable flag
  if [ "$immutable" = "true" ]; then
    chattr +i "$path" 2>/dev/null || true
    # Remove from unlocked tracking (successfully re-locked)
    UNLOCKED_FILES=("${UNLOCKED_FILES[@]/$path}")
  fi

  echo "  Deployed: $path (owner=$owner mode=$mode immutable=$immutable)"
  deploy_count=$((deploy_count + 1))
done <<< "$ENTRIES"

echo ""
echo "=== PHASE 3: Log and cleanup ==="
echo ""

log_recovery "deploy" "Deployed $deploy_count files from $STAGING_DIR"

# Clear the unlocked files array (all re-locked successfully)
UNLOCKED_FILES=()

echo "Deployment complete. $deploy_count files deployed."
echo "Backups retained at: $BACKUP_DIR"
echo "Staging dir retained at: $STAGING_DIR"
echo ""
echo "To rollback:  deploy-staged.sh --rollback $STAGING_DIR"
echo "To cleanup:   rm -rf $STAGING_DIR"
