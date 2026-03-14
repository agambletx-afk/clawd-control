#!/bin/bash
SESSIONS_DIR="/home/openclaw/.openclaw/agents/main/sessions"
ARCHIVE_DIR="${SESSIONS_DIR}/archive"
THRESHOLD_KB=500
DRY_RUN="${1:-}"

mkdir -p "$ARCHIVE_DIR"
echo "=== OpenClaw Session Cleanup ==="
echo "Threshold: ${THRESHOLD_KB}KB"

bloated=0
total_freed=0

for f in "$SESSIONS_DIR"/*.jsonl; do
    [ -f "$f" ] || continue
    size_kb=$(du -k "$f" | cut -f1)
    fname=$(basename "$f")
    if [ "$size_kb" -gt "$THRESHOLD_KB" ]; then
        bloated=$((bloated + 1))
        total_freed=$((total_freed + size_kb))
        if [ "$DRY_RUN" = "--dry-run" ]; then
            echo "[DRY RUN] Would archive: $fname (${size_kb}KB)"
        else
            mv "$f" "$ARCHIVE_DIR/${fname}.$(date +%Y%m%d-%H%M%S).bak"
            echo "Archived: $fname (${size_kb}KB)"
        fi
    else
        echo "OK: $fname (${size_kb}KB)"
    fi
done

echo ""
echo "Bloated: $bloated | Freed: ${total_freed}KB"
if [ "$bloated" -gt 0 ] && [ "$DRY_RUN" != "--dry-run" ]; then
    echo "Archived to: $ARCHIVE_DIR"
fi
