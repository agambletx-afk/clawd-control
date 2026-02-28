#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE='/home/openclaw/.openclaw/openclaw.json'
BASELINE_FILE='/tmp/config-drift-baseline.json'

if [ ! -r "$CONFIG_FILE" ]; then
  echo "ERROR: cannot read config file: $CONFIG_FILE" >&2
  exit 1
fi

result=$(CONFIG_FILE="$CONFIG_FILE" BASELINE_FILE="$BASELINE_FILE" node -e "
  const fs = require('fs');

  const configFile = process.env.CONFIG_FILE;
  const baselineFile = process.env.BASELINE_FILE;

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
    if (Object.prototype.hasOwnProperty.call(out, '')) {
      delete out[''];
    }
    return out;
  };

  const cfg = JSON.parse(fs.readFileSync(configFile, 'utf8'));
  const flat = flatten(cfg);
  fs.writeFileSync(baselineFile, JSON.stringify(flat, null, 2));
  process.stdout.write(JSON.stringify({ timestamp: new Date().toISOString(), keyCount: Object.keys(flat).length }));
")

ts=$(echo "$result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(d.timestamp)")
count=$(echo "$result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(String(d.keyCount))")

chmod 644 "$BASELINE_FILE" 2>/dev/null || true

echo "Baseline reset at ${ts}; keys=${count}"
