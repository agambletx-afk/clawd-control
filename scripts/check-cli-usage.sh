#!/usr/bin/env bash
set -u

OUT_PATH="/tmp/cli-usage.json"
NOW_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

json_escape() {
  jq -Rn --arg v "$1" '$v'
}

empty_provider_json() {
  local name="$1"
  jq -n --arg name "$name" '{
    name: $name,
    session_pct: null,
    session_reset: null,
    weekly_pct: null,
    weekly_reset: null,
    credits: null,
    status: "error",
    error: "Unknown error"
  }'
}

mk_provider_json() {
  local name="$1"
  local session_pct="$2"
  local session_reset="$3"
  local weekly_pct="$4"
  local weekly_reset="$5"
  local credits="$6"
  local status="$7"
  local error="$8"

  jq -n \
    --arg name "$name" \
    --argjson session_pct "$session_pct" \
    --arg session_reset "$session_reset" \
    --argjson weekly_pct "$weekly_pct" \
    --arg weekly_reset "$weekly_reset" \
    --argjson credits "$credits" \
    --arg status "$status" \
    --arg error "$error" \
    '{
      name: $name,
      session_pct: $session_pct,
      session_reset: (if $session_reset == "" then null else $session_reset end),
      weekly_pct: $weekly_pct,
      weekly_reset: (if $weekly_reset == "" then null else $weekly_reset end),
      credits: $credits,
      status: $status,
      error: (if $error == "" then null else $error end)
    }'
}

normalize_pct() {
  local val="$1"
  if [[ -z "$val" || "$val" == "null" ]]; then
    printf 'null'
    return
  fi
  if [[ "$val" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    awk -v v="$val" 'BEGIN { if (v < 0) v = 0; if (v > 100) v = 100; printf "%d", v + 0.5 }'
    return
  fi
  printf 'null'
}

normalize_money() {
  local val="$1"
  if [[ -z "$val" || "$val" == "null" ]]; then
    printf 'null'
    return
  fi
  if [[ "$val" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    awk -v v="$val" 'BEGIN { printf "%.2f", v + 0 }'
    return
  fi
  printf 'null'
}

codex_appserver_read() {
  local codex_bin="$1"
  local app_args="$2"
  CODEX_BIN="$codex_bin" APP_SERVER_ARGS="$app_args" node - <<'NODE'
const { spawn } = require('node:child_process');

const codexBin = process.env.CODEX_BIN || 'codex';
const extraArgs = (process.env.APP_SERVER_ARGS || '')
  .split('\n')
  .map((s) => s.trim())
  .filter(Boolean);
const proc = spawn(codexBin, ['app-server', ...extraArgs], {
  stdio: ['pipe', 'pipe', 'pipe'],
});

let stdoutBuf = Buffer.alloc(0);
let stderrBuf = '';
let initialized = false;
let done = false;

const timeout = setTimeout(() => {
  finish({ ok: false, error: 'Timed out waiting for codex app-server response' }, 1);
}, 6000);

function sendRpc(payload) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  const header = Buffer.from(`Content-Length: ${body.length}\r\n\r\n`, 'utf8');
  proc.stdin.write(Buffer.concat([header, body]));
}

function tryParseMessages() {
  let progressed = true;
  while (progressed) {
    progressed = false;

    const marker = Buffer.from('\r\n\r\n');
    const headerEnd = stdoutBuf.indexOf(marker);
    if (headerEnd !== -1) {
      const headerText = stdoutBuf.slice(0, headerEnd).toString('utf8');
      const m = headerText.match(/Content-Length:\s*(\d+)/i);
      if (m) {
        const len = Number(m[1]);
        const needed = headerEnd + marker.length + len;
        if (stdoutBuf.length < needed) return;
        const body = stdoutBuf.slice(headerEnd + marker.length, needed);
        stdoutBuf = stdoutBuf.slice(needed);
        progressed = true;
        handleMessage(body.toString('utf8'));
        continue;
      }
    }

    const nl = stdoutBuf.indexOf(0x0a);
    if (nl !== -1) {
      const line = stdoutBuf.slice(0, nl).toString('utf8').trim();
      stdoutBuf = stdoutBuf.slice(nl + 1);
      progressed = true;
      if (line.startsWith('{')) handleMessage(line);
    }
  }
}

function handleMessage(raw) {
  let msg;
  try {
    msg = JSON.parse(raw);
  } catch {
    return;
  }

  if (msg && msg.id === 1 && !initialized) {
    initialized = true;
    sendRpc({ jsonrpc: '2.0', method: 'initialized', params: {} });
    sendRpc({ jsonrpc: '2.0', id: 2, method: 'account/read', params: {} });
    return;
  }

  if (msg && msg.id === 2) {
    if (msg.error) {
      finish({ ok: false, error: msg.error.message || 'account/read failed' }, 1);
      return;
    }
    finish({ ok: true, data: msg.result || {} }, 0);
  }
}

function finish(payload, code) {
  if (done) return;
  done = true;
  clearTimeout(timeout);
  try { proc.kill('SIGTERM'); } catch {}
  process.stdout.write(JSON.stringify(payload));
  process.exit(code);
}

proc.stderr.on('data', (chunk) => {
  stderrBuf += chunk.toString('utf8');
});

proc.on('error', (err) => {
  finish({ ok: false, error: err.message || 'Failed to start codex app-server' }, 1);
});

proc.on('exit', (code) => {
  if (done) return;
  const err = stderrBuf.trim() || `codex app-server exited (${code ?? 'unknown'})`;
  finish({ ok: false, error: err }, 1);
});

sendRpc({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
proc.stdout.on('data', (chunk) => {
  stdoutBuf = Buffer.concat([stdoutBuf, chunk]);
  tryParseMessages();
});
NODE
}

parse_codex_from_json() {
  local raw="$1"
  jq -n --argjson src "$raw" '
    def num_or_null(v): if v == null then null elif (v|type) == "number" then v else null end;
    def to_pct(used; limit; pct):
      if pct != null then pct
      elif used != null and limit != null and limit > 0 then ((used / limit) * 100)
      else null
      end;
    def first_num(paths):
      reduce paths[] as $p (null; if . != null then . else (num_or_null($src | getpath($p))) end);
    def first_str(paths):
      reduce paths[] as $p (null; if . != null then . else (($src | getpath($p)) | if type == "string" then . else null end) end);

    {
      session_used: first_num([["rateLimits","session","used"], ["rateLimits","fiveHour","used"], ["limits","session","used"], ["usage","session","used"]]),
      session_limit: first_num([["rateLimits","session","limit"], ["rateLimits","fiveHour","limit"], ["limits","session","limit"], ["usage","session","limit"]]),
      session_pct_direct: first_num([["rateLimits","session","pct"], ["rateLimits","session","percent"], ["rateLimits","fiveHour","pct"], ["rateLimits","fiveHour","percent"], ["usage","session_pct"]]),
      session_reset: first_str([["rateLimits","session","resetAt"], ["rateLimits","fiveHour","resetAt"], ["limits","session","resetAt"], ["usage","session_reset"]]),

      weekly_used: first_num([["rateLimits","weekly","used"], ["limits","weekly","used"], ["usage","weekly","used"]]),
      weekly_limit: first_num([["rateLimits","weekly","limit"], ["limits","weekly","limit"], ["usage","weekly","limit"]]),
      weekly_pct_direct: first_num([["rateLimits","weekly","pct"], ["rateLimits","weekly","percent"], ["usage","weekly_pct"]]),
      weekly_reset: first_str([["rateLimits","weekly","resetAt"], ["limits","weekly","resetAt"], ["usage","weekly_reset"]]),

      credits: first_num([["credits","remaining"], ["account","credits","remaining"], ["balance","credits"], ["plan","credits_remaining"]]),
      plan: first_str([["plan","type"], ["account","plan","type"]])
    }
    | .session_pct = to_pct(.session_used; .session_limit; .session_pct_direct)
    | .weekly_pct = to_pct(.weekly_used; .weekly_limit; .weekly_pct_direct)
  '
}

collect_codex_usage() {
  local codex_bin
  codex_bin="$(command -v codex 2>/dev/null || true)"

  if [[ -z "$codex_bin" ]]; then
    mk_provider_json "Codex CLI" "null" "" "null" "" "null" "not_connected" "Codex CLI not installed"
    return
  fi

  local app_out
  app_out="$(codex_appserver_read "$codex_bin" $'-s\nread-only\n-a\nuntrusted' 2>/dev/null || true)"
  if [[ -z "$app_out" ]] || ! jq -e '.ok == true and .data' >/dev/null 2>&1 <<< "$app_out"; then
    local app_out_legacy
    app_out_legacy="$(codex_appserver_read "$codex_bin" '' 2>/dev/null || true)"
    if [[ -n "$app_out_legacy" ]]; then
      app_out="$app_out_legacy"
    fi
  fi

  if [[ -n "$app_out" ]] && jq -e '.ok == true and .data' >/dev/null 2>&1 <<< "$app_out"; then
    local parsed
    parsed="$(parse_codex_from_json "$(jq -c '.data' <<< "$app_out")")"

    local session_pct_raw weekly_pct_raw session_reset weekly_reset credits_raw
    session_pct_raw="$(jq -r '.session_pct // "null"' <<< "$parsed")"
    weekly_pct_raw="$(jq -r '.weekly_pct // "null"' <<< "$parsed")"
    session_reset="$(jq -r '.session_reset // ""' <<< "$parsed")"
    weekly_reset="$(jq -r '.weekly_reset // ""' <<< "$parsed")"
    credits_raw="$(jq -r '.credits // "null"' <<< "$parsed")"

    local session_pct weekly_pct credits status
    session_pct="$(normalize_pct "$session_pct_raw")"
    weekly_pct="$(normalize_pct "$weekly_pct_raw")"
    credits="$(normalize_money "$credits_raw")"
    status="ok"

    if [[ "$session_pct" != "null" && "$session_pct" -ge 100 ]]; then
      status="rate_limited"
    fi

    mk_provider_json "Codex CLI" "$session_pct" "$session_reset" "$weekly_pct" "$weekly_reset" "$credits" "$status" ""
    return
  fi

  local app_err
  app_err="$(jq -r '.error // empty' <<< "$app_out" 2>/dev/null || true)"

  local scrape=""
  if have_cmd script; then
    scrape="$(script -q -c "${codex_bin} /status" /dev/null 2>/dev/null || true)"
  else
    scrape="$("$codex_bin" /status 2>/dev/null || true)"
  fi

  local pcts
  pcts="$(grep -Eo '[0-9]{1,3}%' <<< "$scrape" | tr -d '%' | head -n 2 || true)"
  local session_pct="null"
  local weekly_pct="null"
  local n=0
  while IFS= read -r pct; do
    [[ -z "$pct" ]] && continue
    if [[ $n -eq 0 ]]; then session_pct="$(normalize_pct "$pct")"; fi
    if [[ $n -eq 1 ]]; then weekly_pct="$(normalize_pct "$pct")"; fi
    n=$((n + 1))
  done <<< "$pcts"

  if [[ "$session_pct" != "null" || "$weekly_pct" != "null" ]]; then
    local status="ok"
    if [[ "$session_pct" != "null" && "$session_pct" -ge 100 ]]; then
      status="rate_limited"
    fi
    mk_provider_json "Codex CLI" "$session_pct" "" "$weekly_pct" "" "null" "$status" ""
    return
  fi

  if grep -qiE 'login|auth|authenticate|not logged' <<< "${app_err}\n${scrape}"; then
    mk_provider_json "Codex CLI" "null" "" "null" "" "null" "not_connected" "Codex CLI not authenticated. Run: codex login"
    return
  fi

  local err="${app_err:-Failed to query Codex CLI usage}"
  mk_provider_json "Codex CLI" "null" "" "null" "" "null" "error" "$err"
}

parse_claude_codexbar() {
  local raw="$1"
  jq -n --argjson src "$raw" '
    def num_or_null(v): if v == null then null elif (v|type) == "number" then v else null end;
    def first_num(paths):
      reduce paths[] as $p (null; if . != null then . else (num_or_null($src | getpath($p))) end);
    def first_str(paths):
      reduce paths[] as $p (null; if . != null then . else (($src | getpath($p)) | if type == "string" then . else null end) end);

    {
      session_pct: first_num([["session_pct"], ["session","percent"], ["limits","session","pct"], ["usage","session_pct"]]),
      session_reset: first_str([["session_reset"], ["session","reset_at"], ["limits","session","resetAt"]]),
      weekly_pct: first_num([["weekly_pct"], ["weekly","percent"], ["limits","weekly","pct"], ["usage","weekly_pct"]]),
      weekly_reset: first_str([["weekly_reset"], ["weekly","reset_at"], ["limits","weekly","resetAt"]])
    }
  '
}

collect_claude_usage() {
  if have_cmd codexbar; then
    local out
    out="$(codexbar --provider claude --format json --pretty 2>/dev/null || true)"
    if [[ -n "$out" ]] && jq -e . >/dev/null 2>&1 <<< "$out"; then
      local parsed
      parsed="$(parse_claude_codexbar "$out")"
      local session_pct_raw weekly_pct_raw session_reset weekly_reset
      session_pct_raw="$(jq -r '.session_pct // "null"' <<< "$parsed")"
      weekly_pct_raw="$(jq -r '.weekly_pct // "null"' <<< "$parsed")"
      session_reset="$(jq -r '.session_reset // ""' <<< "$parsed")"
      weekly_reset="$(jq -r '.weekly_reset // ""' <<< "$parsed")"

      local session_pct weekly_pct status
      session_pct="$(normalize_pct "$session_pct_raw")"
      weekly_pct="$(normalize_pct "$weekly_pct_raw")"
      status="ok"
      if [[ "$session_pct" != "null" && "$session_pct" -ge 100 ]]; then
        status="rate_limited"
      fi

      mk_provider_json "Claude Code" "$session_pct" "$session_reset" "$weekly_pct" "$weekly_reset" "null" "$status" ""
      return
    fi
  fi

  local claude_bin
  claude_bin="$(command -v claude 2>/dev/null || true)"
  if [[ -z "$claude_bin" ]]; then
    mk_provider_json "Claude Code" "null" "" "null" "" "null" "not_connected" "Claude Code not authenticated. Run: claude login"
    return
  fi

  local scrape=""
  if have_cmd script; then
    scrape="$(script -q -c "${claude_bin} /usage" /dev/null 2>/dev/null || true)"
  else
    scrape="$("$claude_bin" /usage 2>/dev/null || true)"
  fi

  if grep -qiE 'login|auth|authenticate|not logged|not authenticated' <<< "$scrape"; then
    mk_provider_json "Claude Code" "null" "" "null" "" "null" "not_connected" "Claude Code not authenticated. Run: claude login"
    return
  fi

  local pcts
  pcts="$(grep -Eo '[0-9]{1,3}%' <<< "$scrape" | tr -d '%' | head -n 2 || true)"
  local session_pct="null"
  local weekly_pct="null"
  local n=0
  while IFS= read -r pct; do
    [[ -z "$pct" ]] && continue
    if [[ $n -eq 0 ]]; then session_pct="$(normalize_pct "$pct")"; fi
    if [[ $n -eq 1 ]]; then weekly_pct="$(normalize_pct "$pct")"; fi
    n=$((n + 1))
  done <<< "$pcts"

  if [[ "$session_pct" != "null" || "$weekly_pct" != "null" ]]; then
    local status="ok"
    if [[ "$session_pct" != "null" && "$session_pct" -ge 100 ]]; then
      status="rate_limited"
    fi
    mk_provider_json "Claude Code" "$session_pct" "" "$weekly_pct" "" "null" "$status" ""
    return
  fi

  mk_provider_json "Claude Code" "null" "" "null" "" "null" "not_connected" "Claude Code not authenticated. Run: claude login"
}

if ! have_cmd jq; then
  cat > "$OUT_PATH" <<JSON
{"checked_at":"${NOW_UTC}","providers":{"codex":{"name":"Codex CLI","session_pct":null,"session_reset":null,"weekly_pct":null,"weekly_reset":null,"credits":null,"status":"error","error":"jq not installed"},"claude":{"name":"Claude Code","session_pct":null,"session_reset":null,"weekly_pct":null,"weekly_reset":null,"credits":null,"status":"error","error":"jq not installed"}}}
JSON
  exit 0
fi

codex_json="$(collect_codex_usage)"
claude_json="$(collect_claude_usage)"

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
