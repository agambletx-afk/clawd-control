#!/usr/bin/env bash
set -u

OUT_PATH="/tmp/openclaw-version-check.json"
NPM_URL="https://registry.npmjs.org/openclaw"
GITHUB_URL="https://api.github.com/repos/openclaw/openclaw/releases"
ENV_FILE="/opt/openclaw.env"

iso_now() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

json_out() {
  local timestamp="$1"
  local installed_version="$2"
  local latest_version="$3"
  local status="$4"
  local versions_behind="$5"
  local has_security_patch="$6"
  local has_breaking_changes="$7"
  local releases_between_json="$8"
  local error_msg="$9"

  local tmp_file
  tmp_file="$(mktemp /tmp/openclaw-version-check.json.XXXXXX)" || return 1

  jq -n \
    --arg timestamp "$timestamp" \
    --arg installed_version "$installed_version" \
    --argjson latest_version "$latest_version" \
    --arg status "$status" \
    --argjson versions_behind "$versions_behind" \
    --argjson has_security_patch "$has_security_patch" \
    --argjson has_breaking_changes "$has_breaking_changes" \
    --argjson releases_between "$releases_between_json" \
    --argjson error "$error_msg" \
    '{
      timestamp: $timestamp,
      installed_version: $installed_version,
      latest_version: $latest_version,
      status: $status,
      versions_behind: $versions_behind,
      has_security_patch: $has_security_patch,
      has_breaking_changes: $has_breaking_changes,
      releases_between: $releases_between,
      error: $error
    }' > "$tmp_file" && mv "$tmp_file" "$OUT_PATH"
}

sanitize_version() {
  printf '%s' "$1" | sed -E 's/^v//; s/^[[:space:]]+//; s/[[:space:]]+$//'
}

if [[ -r "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  set +u; set -a
  . "$ENV_FILE"
  set +a; set -u
fi

timestamp="$(iso_now)"

installed_raw="$(openclaw --version 2>/dev/null)"
if [[ $? -ne 0 || -z "$installed_raw" ]]; then
  json_out "$timestamp" "" "null" "error" "null" "false" "false" '[]' '"Failed to read installed version from openclaw --version"'
  exit 1
fi

installed_version="$(sanitize_version "$installed_raw")"

npm_payload=""
if ! npm_payload="$(curl -fsSL --max-time 5 "$NPM_URL" 2>/dev/null)"; then
  json_out "$timestamp" "$installed_version" "null" "check_failed" "null" "false" "false" '[]' '"npm registry unreachable"'
  exit 1
fi

if ! latest_version="$(jq -r '
  (
    (.versions | keys | map(select(test("-") | not))) as $stable
    | .["dist-tags"].latest as $tag_latest
    | if ($tag_latest != null and ($tag_latest | test("-") | not) and ($stable | index($tag_latest) != null))
      then $tag_latest
      else ($stable | sort_by(split(".") | map(tonumber? // 0)) | last)
      end
  ) // empty
' <<< "$npm_payload")"; then
  json_out "$timestamp" "$installed_version" "null" "check_failed" "null" "false" "false" '[]' '"Failed to parse npm registry response"'
  exit 1
fi

if [[ -z "$latest_version" ]]; then
  json_out "$timestamp" "$installed_version" "null" "check_failed" "null" "false" "false" '[]' '"No stable version found in npm registry response"'
  exit 1
fi

versions_behind="$(jq -r --arg installed "$installed_version" --arg latest "$latest_version" '
  (.versions | keys | map(select(test("-") | not)) | sort_by(split(".") | map(tonumber? // 0))) as $ordered
  | ($ordered | index($installed)) as $installed_idx
  | ($ordered | index($latest)) as $latest_idx
  | if ($installed_idx == null or $latest_idx == null) then null
    elif ($latest_idx < $installed_idx) then 0
    else ($latest_idx - $installed_idx)
    end
' <<< "$npm_payload")"

if [[ "$installed_version" == "$latest_version" ]]; then
  json_out "$timestamp" "$installed_version" "\"$latest_version\"" "up_to_date" "0" "false" "false" '[]' 'null'
  exit 0
fi

headers_file="$(mktemp /tmp/openclaw-github-headers.XXXXXX)"
github_body_file="$(mktemp /tmp/openclaw-github-body.XXXXXX)"
http_code="$(curl -sS -L --max-time 10 -D "$headers_file" -o "$github_body_file" -w '%{http_code}' "$GITHUB_URL" 2>/dev/null || echo "000")"

rate_remaining="$(awk -F': *' 'tolower($1)=="x-ratelimit-remaining" {gsub("\r","",$2); print $2}' "$headers_file" | tail -n1)"

if [[ "$http_code" == "403" || "$http_code" == "429" ]]; then
  if [[ "$http_code" == "429" || "${rate_remaining:-}" == "0" ]]; then
    rm -f "$headers_file" "$github_body_file"
    json_out "$timestamp" "$installed_version" "\"$latest_version\"" "update_available" "null" "false" "false" '[]' 'null'
    exit 0
  fi
fi

if [[ "$http_code" -lt 200 || "$http_code" -ge 300 ]]; then
  rm -f "$headers_file" "$github_body_file"
  json_out "$timestamp" "$installed_version" "\"$latest_version\"" "check_failed" "null" "false" "false" '[]' "\"GitHub releases API failed with HTTP $http_code\""
  exit 1
fi

if ! releases_between_json="$(jq -c --arg installed "$installed_version" --arg latest "$latest_version" '
  def norm(v): (v // "") | sub("^v"; "");
  def tuple(v): norm(v) | split(".") | map(tonumber? // 0);
  def is_between(v): (tuple(v) > tuple($installed) and tuple(v) <= tuple($latest));

  [ .[]
    | .tag_name as $tag
    | (norm($tag)) as $version
    | select($version != "")
    | select(is_between($version))
    | .name as $name
    | .body as $body
    | ((($name // "") + "\n" + ($body // "")) | ascii_downcase) as $text
    | {
        version: $version,
        date: (.published_at // .created_at // null),
        has_breaking: ($text | test("breaking")),
        has_security: ($text | test("cve|security|vulnerability")),
        title: ($name // $tag // $version)
      }
  ] | sort_by(.version | split(".") | map(tonumber? // 0))
' "$github_body_file" 2>/dev/null)"; then
  rm -f "$headers_file" "$github_body_file"
  json_out "$timestamp" "$installed_version" "\"$latest_version\"" "check_failed" "null" "false" "false" '[]' '"Failed to parse GitHub releases response"'
  exit 1
fi

rm -f "$headers_file" "$github_body_file"

has_security_patch="$(jq -r 'any(.[]; .has_security == true)' <<< "$releases_between_json")"
has_breaking_changes="$(jq -r 'any(.[]; .has_breaking == true)' <<< "$releases_between_json")"

json_out "$timestamp" "$installed_version" "\"$latest_version\"" "update_available" "$versions_behind" "$has_security_patch" "$has_breaking_changes" "$releases_between_json" 'null'
