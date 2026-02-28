#!/usr/bin/env bash
set -u

# Claude Code OAuth Token Auto-Refresh
# Refreshes the access token using the refresh token when expired.
# IMPORTANT: Refresh tokens are single-use. Do NOT run while Claude Code is active.
# The pgrep guard below prevents conflicts with interactive sessions.
# Client ID is hardcoded in Claude Code binary, stable since May 2025.
# Undocumented API - may change without notice.

CREDENTIALS_FILE="$HOME/.claude/.credentials.json"
CLIENT_ID="9d1c250a-e61b-44d9-88ed-5944d1962f5e"
TOKEN_ENDPOINT="https://console.anthropic.com/v1/oauth/token"
EXPIRY_BUFFER_MS=300000

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required"
  exit 1
fi

if [[ ! -f "$CREDENTIALS_FILE" ]]; then
  echo "SKIP: Credentials file not found"
  exit 0
fi

if pgrep -f "claude" >/dev/null 2>&1; then
  echo "SKIP: Claude Code process detected"
  exit 0
fi

access_token="$(jq -r '.claudeAiOauth.accessToken // empty' "$CREDENTIALS_FILE")"
refresh_token="$(jq -r '.claudeAiOauth.refreshToken // empty' "$CREDENTIALS_FILE")"
expires_at="$(jq -r '.claudeAiOauth.expiresAt // 0' "$CREDENTIALS_FILE")"

if [[ -z "$refresh_token" ]]; then
  echo "SKIP: No refresh token available"
  exit 0
fi

now_ms="$(( $(date +%s) * 1000 ))"
expiry_with_buffer="$(( expires_at - EXPIRY_BUFFER_MS ))"

if (( now_ms < expiry_with_buffer )); then
  echo "OK: Token still valid (expiresAt=${expires_at})"
  exit 0
fi

request_body="$(jq -n --arg refresh_token "$refresh_token" --arg client_id "$CLIENT_ID" '{grant_type:"refresh_token",refresh_token:$refresh_token,client_id:$client_id}')"

response="$(curl -sS --max-time 10 -X POST "$TOKEN_ENDPOINT" -H 'Content-Type: application/json' -d "$request_body")"
curl_exit=$?
if (( curl_exit != 0 )); then
  echo "ERROR: Token refresh request failed"
  exit 1
fi

if [[ "$(jq -r 'has("error")' <<< "$response")" == "true" ]]; then
  error_msg="$(jq -r '.error_description // .error // "unknown_error"' <<< "$response")"
  echo "ERROR: OAuth refresh rejected: ${error_msg}"
  exit 1
fi

new_access_token="$(jq -r '.access_token // empty' <<< "$response")"
new_refresh_token="$(jq -r '.refresh_token // empty' <<< "$response")"
expires_in="$(jq -r '.expires_in // 0' <<< "$response")"

if [[ -z "$new_access_token" || -z "$new_refresh_token" || "$expires_in" == "0" ]]; then
  echo "ERROR: Invalid refresh response"
  exit 1
fi

now_epoch="$(date +%s)"
new_expires_at="$(( (now_epoch + expires_in) * 1000 ))"

cp "$CREDENTIALS_FILE" "${CREDENTIALS_FILE}.bak"

tmp_file="$(mktemp)"
jq \
  --arg access_token "$new_access_token" \
  --arg refresh_token "$new_refresh_token" \
  --argjson expires_at "$new_expires_at" \
  '.claudeAiOauth.accessToken = $access_token
   | .claudeAiOauth.refreshToken = $refresh_token
   | .claudeAiOauth.expiresAt = $expires_at' \
  "$CREDENTIALS_FILE" > "$tmp_file"

mv "$tmp_file" "$CREDENTIALS_FILE"
chmod 600 "$CREDENTIALS_FILE"

echo "OK: Token refreshed successfully (new expiresAt=${new_expires_at})"
