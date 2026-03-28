#!/bin/bash

WORKSPACE_PATH="/home/openclaw/.openclaw/workspace/"

preflight_disk_space_check() {
  local available_kb
  local required_kb=512000
  available_kb="$(df -Pk /home/openclaw | awk 'NR==2 {print $4}')"

  if [ -z "$available_kb" ]; then
    echo "FAIL: unable to determine disk space for /home/openclaw"
    return 1
  fi

  if [ "$available_kb" -gt "$required_kb" ]; then
    echo "PASS: disk space check ok (${available_kb}KB free)"
    return 0
  fi

  echo "FAIL: low disk space (${available_kb}KB free, need >${required_kb}KB)"
  return 1
}

preflight_workspace_writable_check() {
  local test_file
  test_file="${WORKSPACE_PATH}.preflight-write-test-$$"

  if ! touch "$test_file" 2>/dev/null; then
    echo "FAIL: workspace not writable: ${WORKSPACE_PATH}"
    return 1
  fi

  if [ ! -f "$test_file" ]; then
    echo "FAIL: test file not created in workspace"
    return 1
  fi

  rm -f "$test_file"
  echo "PASS: workspace writable check ok"
  return 0
}

preflight_config_parseable_check() {
  local config_file last_good tmp_file
  config_file="${WORKSPACE_PATH}health-checks.json"
  last_good="${WORKSPACE_PATH}.health-checks-last-good.json"
  tmp_file="${WORKSPACE_PATH}.health-checks-fallback.tmp.$$"

  if python3 -c "import json; json.load(open('$config_file', 'r', encoding='utf-8'))" >/dev/null 2>&1; then
    echo "PASS: health-checks.json is valid JSON"
    return 0
  fi

  echo "WARN: health-checks.json invalid, attempting fallback restore"
  if [ ! -f "$last_good" ]; then
    echo "FAIL: fallback file missing: $last_good"
    return 1
  fi

  if ! python3 -c "import json; json.load(open('$last_good', 'r', encoding='utf-8'))" >/dev/null 2>&1; then
    echo "FAIL: fallback file is not valid JSON"
    return 1
  fi

  if cp "$last_good" "$tmp_file" && mv "$tmp_file" "$config_file"; then
    echo "PASS: restored health-checks.json from last-good snapshot"
    return 0
  fi

  rm -f "$tmp_file"
  echo "FAIL: unable to restore health-checks.json from fallback"
  return 1
}

preflight_critical_paths_check() {
  local missing=()
  local required_files=(
    "${WORKSPACE_PATH}.kill-switches.json"
    "${WORKSPACE_PATH}.pulse-state.json"
    "${WORKSPACE_PATH}.pulse-config.json"
    "${WORKSPACE_PATH}SOUL.md"
  )

  local file
  for file in "${required_files[@]}"; do
    if [ ! -e "$file" ]; then
      missing+=("$file")
    fi
  done

  if [ "${#missing[@]}" -eq 0 ]; then
    echo "PASS: all critical paths present"
    return 0
  fi

  echo "FAIL: missing critical files: ${missing[*]}"
  return 1
}

preflight_clock_sanity_check() {
  local state_file
  state_file="${WORKSPACE_PATH}.pulse-state.json"

  if [ ! -f "$state_file" ]; then
    echo "PASS: no pulse state present yet; skipping clock sanity check"
    return 0
  fi

  if python3 -c "import json, datetime, time; s=json.load(open('$state_file', 'r', encoding='utf-8')); v=s.get('last_started_at');\
if not v: raise SystemExit(0);\
dt=datetime.datetime.fromisoformat(v.replace('Z','+00:00')); now=time.time();\
raise SystemExit(1 if now < dt.timestamp()-300 else 0)"; then
    echo "PASS: clock sanity check ok"
    return 0
  fi

  echo "FAIL: clock sanity check failed (system time appears >300s before last_started_at)"
  return 1
}

preflight_service_user_check() {
  local expected_user current_user
  expected_user="${1:-}"
  current_user="$(whoami)"

  if [ -z "$expected_user" ]; then
    echo "FAIL: expected username not provided"
    return 1
  fi

  if [ "$current_user" = "$expected_user" ]; then
    echo "PASS: service user check ok (${current_user})"
    return 0
  fi

  echo "WARN: running as ${current_user}, expected ${expected_user}"
  return 1
}
