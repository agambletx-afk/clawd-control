# Manual VPS Patch: Consolidate Integrity Baseline

These changes must be applied manually on the production VPS. They are NOT in the repo.

## 1. Patch `/usr/local/bin/check-security-health.sh`

The script currently reads `.integrity-manifest` (plain text sha256sum format) for the
critical file integrity check. Change it to read `.critical-file-hashes.json` (JSON) instead.

### Find (line 304):

```bash
integrity_manifest='/home/openclaw/.openclaw/.integrity-manifest'
```

### Replace with:

```bash
integrity_hashes_json='/home/openclaw/.openclaw/workspace/.critical-file-hashes.json'
```

### Find (lines 346-351) — the block that creates a new manifest if missing:

```bash
if [ ! -f "$integrity_manifest" ] && [ -f "$legacy_soul_hash" ]; then
  manifest_files=$(write_integrity_manifest "$integrity_manifest")
  rm -f "$legacy_soul_hash"
  integrity_message="Baseline manifest created for ${manifest_files} files."
elif [ ! -f "$integrity_manifest" ]; then
  manifest_files=$(write_integrity_manifest "$integrity_manifest")
  integrity_message="Baseline manifest created for ${manifest_files} files."
else
```

### Replace with:

```bash
if [ ! -f "$integrity_hashes_json" ]; then
  integrity_status='yellow'
  integrity_message="Baseline file missing: ${integrity_hashes_json}. Run rebaseline from dashboard."
  integrity_remediation='Open Security > Integrity and click Acknowledge to generate the baseline.'
else
```

### Find (lines 354-371) — the comparison loop that reads the plain text manifest:

```bash
  while IFS= read -r manifest_line || [ -n "$manifest_line" ]; do
    [ -z "$manifest_line" ] && continue
    expected_hash=$(echo "$manifest_line" | awk '{print $1}')
    tracked_path=$(echo "$manifest_line" | cut -d' ' -f3-)
    [ -z "$tracked_path" ] && continue
    manifest_files=$((manifest_files + 1))

    if [ ! -f "$tracked_path" ]; then
      missing_files+=("$(basename "$tracked_path")")
      continue
    fi

    current_hash=$(sha256sum "$tracked_path" | awk '{print $1}')
    if [ "$current_hash" != "$expected_hash" ]; then
      mismatched_files+=("$(basename "$tracked_path")")
      mismatch_details+=("$(basename "$tracked_path"): expected=${expected_hash:0:12} actual=${current_hash:0:12}")
    fi
  done < "$integrity_manifest"
```

### Replace with:

```bash
  for tracked_path in "${integrity_files[@]}"; do
    manifest_files=$((manifest_files + 1))
    expected_hash=$(jq -r --arg p "$tracked_path" '.files[$p].sha256 // empty' "$integrity_hashes_json")

    if [ -z "$expected_hash" ]; then
      missing_files+=("$(basename "$tracked_path")")
      continue
    fi

    if [ ! -f "$tracked_path" ]; then
      missing_files+=("$(basename "$tracked_path")")
      continue
    fi

    current_hash=$(sha256sum "$tracked_path" | awk '{print $1}')
    if [ "$current_hash" != "$expected_hash" ]; then
      mismatched_files+=("$(basename "$tracked_path")")
      mismatch_details+=("$(basename "$tracked_path"): expected=${expected_hash:0:12} actual=${current_hash:0:12}")
    fi
  done
```

### Also remove the `write_integrity_manifest` function (lines 325-344):

This function writes the old plain-text format and is no longer needed. Delete it entirely:

```bash
write_integrity_manifest() {
  local manifest_path="$1"
  ...
  printf '%s' "$count"
}
```

## 2. Delete the stale manifest file

```bash
rm -f /home/openclaw/.openclaw/.integrity-manifest
```

## 3. Verify

```bash
# Run the security health check
sudo -u openclaw /usr/local/bin/check-security-health.sh

# Check SOUL.md integrity status in results
jq '.checks[] | select(.name | test("integrity"; "i")) | {name, status, message}' /tmp/security-health-results.json

# Expected: status "green", message "All 7 critical files verified..."
```

## 4. Restart the dashboard

```bash
sudo systemctl restart clawd-control
```

## Prerequisites

- `jq` must be installed (verify: `which jq`)
