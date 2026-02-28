#!/usr/bin/env bash
set -euo pipefail

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

pass_count=0
fail_count=0

run_case() {
  local expected_status="$1"
  local expected_text="$2"
  local name="$3"
  local baseline_mode="$4"
  local baseline_content="$5"
  local current_content="$6"
  local expect_in_details="${7:-}"

  local cfg="$tmpdir/current.json"
  local base="$tmpdir/baseline.json"

  printf '%s\n' "$current_content" > "$cfg"

  case "$baseline_mode" in
    missing) rm -f "$base" ;;
    invalid) printf '%s\n' 'not-json' > "$base" ;;
    empty) printf '%s\n' '{}' > "$base" ;;
    present) printf '%s\n' "$baseline_content" > "$base" ;;
  esac

  local result
  result=$(CONFIG_FILE="$cfg" BASELINE_FILE="$base" node -e "
    const fs = require('fs');
    const configFile = process.env.CONFIG_FILE;
    const baselineFile = process.env.BASELINE_FILE;

    const stringify = (value) => {
      if (value === null) return 'null';
      if (typeof value === 'string') return JSON.stringify(value);
      if (typeof value === 'number' || typeof value === 'boolean') return String(value);
      return JSON.stringify(value);
    };

    const flatten = (input) => {
      const out = {};
      const walk = (value, path) => {
        if (Array.isArray(value)) {
          if (value.length > 10) {
            out[path] = JSON.stringify(value);
            return;
          }
          if (value.length === 0) {
            out[path] = JSON.stringify([]);
            return;
          }
          value.forEach((entry, i) => walk(entry, path ? (path + '.' + i) : String(i)));
          return;
        }
        if (value && typeof value === 'object') {
          const keys = Object.keys(value);
          if (keys.length === 0) {
            out[path] = JSON.stringify({});
            return;
          }
          keys.forEach((key) => walk(value[key], path ? (path + '.' + key) : key));
          return;
        }
        out[path] = value;
      };
      walk(input, '');
      if (Object.prototype.hasOwnProperty.call(out, '')) delete out[''];
      return out;
    };

    const isCritical = (key) => {
      if (key === 'sandbox.mode') return true;
      if (key === 'sandbox.docker.network') return true;
      if (key === 'tools.deny' || key.startsWith('tools.deny.')) return true;
      if (/^channels\\.[^.]+\\.configWrites$/.test(key)) return true;
      if (/^channels\\.[^.]+\\.allowFrom(\\.|$)/.test(key)) return true;
      return false;
    };

    try {
      const current = JSON.parse(fs.readFileSync(configFile, 'utf8'));
      const currentFlat = flatten(current);

      let baselineRaw;
      try {
        baselineRaw = fs.readFileSync(baselineFile, 'utf8');
      } catch {
        fs.writeFileSync(baselineFile, JSON.stringify(currentFlat, null, 2));
        process.stdout.write(JSON.stringify({status: 'green', message: 'Baseline established', details: ''}));
        process.exit(0);
      }

      let baseline;
      try {
        baseline = JSON.parse(baselineRaw);
        if (!baseline || typeof baseline !== 'object' || Array.isArray(baseline)) throw new Error();
      } catch {
        fs.writeFileSync(baselineFile, JSON.stringify(currentFlat, null, 2));
        process.stdout.write(JSON.stringify({status: 'green', message: 'Baseline established', details: ''}));
        process.exit(0);
      }

      const changes = [];
      for (const key of Object.keys(currentFlat)) {
        if (!(key in baseline)) changes.push({type: 'added', key, value: currentFlat[key]});
        else if (JSON.stringify(currentFlat[key]) !== JSON.stringify(baseline[key])) changes.push({type: 'changed', key, from: baseline[key], to: currentFlat[key]});
      }
      for (const key of Object.keys(baseline)) {
        if (!(key in currentFlat)) changes.push({type: 'removed', key, value: baseline[key]});
      }

      if (changes.length === 0) {
        process.stdout.write(JSON.stringify({status: 'green', message: 'No config drift detected.', details: ''}));
        process.exit(0);
      }

      const critical = changes.filter(c => isCritical(c.key));
      const details = changes.map((item) => {
        if (item.type === 'changed') return 'changed ' + item.key + ': ' + stringify(item.from) + ' -> ' + stringify(item.to);
        if (item.type === 'added') return 'added ' + item.key + ': ' + stringify(item.value);
        return 'removed ' + item.key + ': ' + stringify(item.value);
      }).join('; ');

      process.stdout.write(JSON.stringify({
        status: critical.length > 0 ? 'red' : 'yellow',
        message: critical.length > 0 ? 'Critical config drift detected' : 'Config drift detected',
        details
      }));
    } catch (e) {
      process.stdout.write(JSON.stringify({status: 'red', message: 'Cannot read config file.', details: String(e.message || e)}));
    }
  ")

  local status message details
  status=$(echo "$result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(d.status)")
  message=$(echo "$result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(d.message)")
  details=$(echo "$result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(d.details||'')")

  if [ "$status" = "$expected_status" ] && [[ "$message" == *"$expected_text"* ]] && { [ -z "$expect_in_details" ] || [[ "$details" == *"$expect_in_details"* ]]; }; then
    printf 'PASS [%s] %s\n' "${status^^}" "$name"
    pass_count=$((pass_count + 1))
  else
    printf 'FAIL [%s] %s (got status=%s message=%s details=%s)\n' "${expected_status^^}" "$name" "$status" "$message" "$details"
    fail_count=$((fail_count + 1))
  fi
}

baseline='{"sandbox.mode":"all","sandbox.docker.network":"none","tools.deny.0":"exec","tools.deny.1":"write","channels.telegram.configWrites":false,"channels.telegram.allowFrom.0":"u1","plugins.entries.0.name":"a","models.default":"gpt-5"}'

run_case green 'No config drift detected' 'Test 1: Identical configs' present "$baseline" "$baseline"
run_case red 'Critical config drift detected' 'Test 2: sandbox.mode changed' present "$baseline" '{"sandbox":{"mode":"none","docker":{"network":"none"}},"tools":{"deny":["exec","write"]},"channels":{"telegram":{"configWrites":false,"allowFrom":["u1"]}},"plugins":{"entries":[{"name":"a"}]},"models":{"default":"gpt-5"}}' 'sandbox.mode'
run_case red 'Critical config drift detected' 'Test 3: sandbox.docker.network changed' present "$baseline" '{"sandbox":{"mode":"all","docker":{"network":"bridge"}},"tools":{"deny":["exec","write"]},"channels":{"telegram":{"configWrites":false,"allowFrom":["u1"]}},"plugins":{"entries":[{"name":"a"}]},"models":{"default":"gpt-5"}}' 'sandbox.docker.network'
run_case red 'Critical config drift detected' 'Test 4: tools.deny modified' present "$baseline" '{"sandbox":{"mode":"all","docker":{"network":"none"}},"tools":{"deny":["exec"]},"channels":{"telegram":{"configWrites":false,"allowFrom":["u1"]}},"plugins":{"entries":[{"name":"a"}]},"models":{"default":"gpt-5"}}' 'tools.deny.1'
run_case red 'Critical config drift detected' 'Test 5: channels.*.configWrites changed' present "$baseline" '{"sandbox":{"mode":"all","docker":{"network":"none"}},"tools":{"deny":["exec","write"]},"channels":{"telegram":{"configWrites":true,"allowFrom":["u1"]}},"plugins":{"entries":[{"name":"a"}]},"models":{"default":"gpt-5"}}' 'channels.telegram.configWrites'
run_case yellow 'Config drift detected' 'Test 6: plugin added' present "$baseline" '{"sandbox":{"mode":"all","docker":{"network":"none"}},"tools":{"deny":["exec","write"]},"channels":{"telegram":{"configWrites":false,"allowFrom":["u1"]}},"plugins":{"entries":[{"name":"a"},{"name":"b"}]},"models":{"default":"gpt-5"}}' 'plugins.entries.1.name'
run_case yellow 'Config drift detected' 'Test 7: model changed' present "$baseline" '{"sandbox":{"mode":"all","docker":{"network":"none"}},"tools":{"deny":["exec","write"]},"channels":{"telegram":{"configWrites":false,"allowFrom":["u1"]}},"plugins":{"entries":[{"name":"a"}]},"models":{"default":"gpt-4"}}' 'models.default'
run_case yellow 'Config drift detected' 'Test 8: non-critical key removed' present "$baseline" '{"sandbox":{"mode":"all","docker":{"network":"none"}},"tools":{"deny":["exec","write"]},"channels":{"telegram":{"configWrites":false,"allowFrom":["u1"]}},"plugins":{"entries":[{"name":"a"}]}}' 'models.default'
run_case red 'Critical config drift detected' 'Test 9: critical + non-critical' present "$baseline" '{"sandbox":{"mode":"none","docker":{"network":"none"}},"tools":{"deny":["exec","write"]},"channels":{"telegram":{"configWrites":false,"allowFrom":["u1"]}},"plugins":{"entries":[{"name":"a"}]},"models":{"default":"gpt-4"}}' 'sandbox.mode'
run_case green 'Baseline established' 'Test 10: empty baseline first run' missing '' "$baseline"
run_case green 'Baseline established' 'Test 11: corrupted baseline re-established' invalid '' "$baseline"
run_case red 'Cannot read config file' 'Test 12: unreadable current config' present "$baseline" '{bad-json}'

printf '\nResults: %d/12 passed, %d failed\n' "$pass_count" "$fail_count"

if [ "$fail_count" -ne 0 ]; then
  exit 1
fi
