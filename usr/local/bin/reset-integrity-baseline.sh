#!/usr/bin/env bash
set -euo pipefail

MANIFEST_FILE='/home/openclaw/.openclaw/.integrity-manifest'
INTEGRITY_FILES=(
  '/home/openclaw/.openclaw/workspace/SOUL.md'
  '/home/openclaw/.openclaw/extensions/security-hook/index.ts'
  '/home/openclaw/.openclaw/security-hook.json'
  '/home/openclaw/.openclaw/openclaw.json'
  '/home/openclaw/.openclaw/workspace/AGENTS.md'
  '/home/openclaw/.openclaw/workspace/HEARTBEAT.md'
  '/home/openclaw/.openclaw/extensions/security-hook/package.json'
)

manifest_dir=$(dirname "$MANIFEST_FILE")
mkdir -p "$manifest_dir"

tmp_file=$(mktemp "${MANIFEST_FILE}.tmp.XXXXXX")
count=0

for file in "${INTEGRITY_FILES[@]}"; do
  if [ -f "$file" ]; then
    sha256sum "$file" >> "$tmp_file"
    count=$((count + 1))
  fi
done

mv "$tmp_file" "$MANIFEST_FILE"
chown openclaw:openclaw "$MANIFEST_FILE"
chmod 0644 "$MANIFEST_FILE"

echo "Integrity baseline updated: ${count} files hashed."
