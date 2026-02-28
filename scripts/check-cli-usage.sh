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
  codex_json="$(timeout --kill-after=3 12 node scripts/codex-usage.mjs 2>/dev/null || true)"
  if [[ -z "$codex_json" ]] || ! jq -e . >/dev/null 2>&1 <<< "$codex_json"; then
    codex_json="$(provider_json "Codex CLI" "error" "Codex CLI usage check failed")"
  fi
else
  codex_json="$(provider_json "Codex CLI" "not_connected" "Codex CLI not installed")"
fi

if have_cmd claude; then
  # Claude Code CLI stores login state in ~/.claude/.credentials.json
  if [[ -f "$HOME/.claude/.credentials.json" ]]; then
    access_token="$(jq -r '.claudeAiOauth.accessToken // empty' "$HOME/.claude/.credentials.json" 2>/dev/null)"
    expires_at="$(jq -r '.claudeAiOauth.expiresAt // empty' "$HOME/.claude/.credentials.json" 2>/dev/null)"
    now_ms="$(( $(date +%s) * 1000 ))"

    if [[ -z "$access_token" || -z "$expires_at" || ! "$expires_at" =~ ^[0-9]+$ ]]; then
      claude_json="$(provider_json "Claude Code" "ok" "Claude Code OAuth token unavailable. Run: claude login to refresh.")"
    elif (( expires_at <= now_ms )); then
      claude_json="$(provider_json "Claude Code" "ok" "OAuth token expired. Run: claude login to refresh.")"
    else
      # Undocumented API - may change without notice. See: https://gist.github.com/jtbr/4f99671d1cee06b44106456958caba8b
      usage_json="$(timeout --kill-after=3 5 curl --max-time 3 -H "Authorization: Bearer ${access_token}" -H "anthropic-beta: oauth-2025-04-20" -H "Content-Type: application/json" "https://api.anthropic.com/api/oauth/usage" 2>/dev/null)"
      usage_status=$?

      if [[ $usage_status -eq 0 ]] && jq -e . >/dev/null 2>&1 <<< "$usage_json"; then
        claude_json="$(jq -n --argjson usage "$usage_json" '{
          name: "Claude Code",
          session_pct: ($usage.five_hour.utilization | if . == null then null else round end),
          session_reset: ($usage.five_hour.resets_at // null),
          weekly_pct: ($usage.seven_day.utilization | if . == null then null else round end),
          weekly_reset: ($usage.seven_day.resets_at // null),
          credits: (if ($usage.extra_usage.is_enabled // false) then ($usage.extra_usage.used_credits // null) else null end),
          plan: null,
          status: "ok",
          error: null
        }')"
      else
        claude_error="Claude Code usage API request failed"
        if [[ $usage_status -ne 0 ]]; then
          claude_error="Claude Code usage API request failed (exit ${usage_status})"
        elif [[ -z "$usage_json" ]]; then
          claude_error="Claude Code usage API request failed (empty response)"
        else
          claude_error="Claude Code usage API request failed (invalid JSON response)"
        fi
        claude_json="$(provider_json "Claude Code" "ok" "$claude_error")"
      fi
    fi
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
