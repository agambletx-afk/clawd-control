#!/usr/bin/env bash
set -u

OUT_PATH="/tmp/cli-usage.json"
NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

provider_json() {
  local name="$1"
  local status="$2"
  local error="$3"
  jq -n \
    --arg name "$name" \
    --arg status "$status" \
    --arg error "$error" \
    '{
      name: $name,
      session_pct: null,
      session_reset: null,
      weekly_pct: null,
      weekly_reset: null,
      credits: null,
      plan: null,
      status: $status,
      error: (if $error == "" then null else $error end)
    }'
}

if ! have_cmd jq; then
  cat > "$OUT_PATH" <<JSON
{"checked_at":"${NOW_UTC}","providers":{"codex":{"name":"Codex CLI","session_pct":null,"session_reset":null,"weekly_pct":null,"weekly_reset":null,"credits":null,"plan":null,"status":"error","error":"jq not installed"},"claude":{"name":"Claude Code","session_pct":null,"session_reset":null,"weekly_pct":null,"weekly_reset":null,"credits":null,"plan":null,"status":"error","error":"jq not installed"}}}
JSON
  exit 0
fi

if have_cmd codex; then
  codex_json="$(timeout 12 node scripts/codex-usage.mjs 2>/dev/null || true)"
  if [[ -z "$codex_json" ]] || ! jq -e . >/dev/null 2>&1 <<< "$codex_json"; then
    codex_json="$(provider_json "Codex CLI" "error" "Codex CLI usage check failed")"
  fi
else
  codex_json="$(provider_json "Codex CLI" "not_connected" "Codex CLI not installed")"
fi

if have_cmd claude; then
  if [[ -f "$HOME/.claude/.credentials.json" ]]; then
    claude_json="$(provider_json "Claude Code" "ok" "")"
  else
    claude_json="$(provider_json "Claude Code" "not_connected" "Claude Code not authenticated. Run: claude login")"
  fi
else
  claude_json="$(provider_json "Claude Code" "not_connected" "Claude Code not installed")"
fi

tmp_out="$(mktemp)"
jq -n \
  --arg checked_at "$NOW_UTC" \
  --argjson codex "$codex_json" \
  --argjson claude "$claude_json" \
  '{
    checked_at: $checked_at,
    providers: {
      codex: $codex,
      claude: $claude
    }
  }' > "$tmp_out"

mv "$tmp_out" "$OUT_PATH"
chmod 644 "$OUT_PATH" 2>/dev/null || true

printf 'Updated %s\n' "$OUT_PATH"
