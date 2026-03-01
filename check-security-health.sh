#!/usr/bin/env bash
# check-security-health.sh — Security health checks for Jarvis/OpenClaw
# Runs 14 checks.
# Runs as openclaw user via cron. Writes JSON to /tmp/security-health-results.json.

set +e

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
CHECKS='[]'
OVERALL='green'

json_escape() {
  node -e "console.log(JSON.stringify(process.argv[1] ?? ''))" "$1"
}

add_check() {
  local check_json="$1"
  CHECKS=$(node -e "
    const checks = JSON.parse(process.argv[1]);
    const check = JSON.parse(process.argv[2]);
    checks.push(check);
    process.stdout.write(JSON.stringify(checks));
  " "$CHECKS" "$check_json" 2>/dev/null)
  if [ -z "$CHECKS" ]; then
    CHECKS='[]'
  fi
}

update_overall() {
  local status="$1"
  if [ "$status" = "red" ]; then
    OVERALL='red'
  elif [ "$status" = "yellow" ] && [ "$OVERALL" != "red" ]; then
    OVERALL='yellow'
  fi
}

make_check_json() {
  local layer="$1"
  local name="$2"
  local status="$3"
  local message="$4"
  local details="$5"
  local remediation="$6"
  local metadata_json="$7"

  local remediation_expr="null"
  if [ "$status" != "green" ]; then
    remediation_expr=$(json_escape "$remediation")
  fi

  local metadata_expr='{}'
  if [ -n "$metadata_json" ]; then
    if echo "$metadata_json" | node -e "try{const m=JSON.parse(require('fs').readFileSync(0,'utf8'));if(m&&typeof m==='object'){process.exit(0)}process.exit(1)}catch(e){process.exit(1)}" >/dev/null 2>&1; then
      metadata_expr="$metadata_json"
    fi
  fi

  printf '{"layer":%s,"name":%s,"status":%s,"message":%s,"details":%s,"remediation":%s,"metadata":%s,"checked_at":%s}' \
    "$(json_escape "$layer")" \
    "$(json_escape "$name")" \
    "$(json_escape "$status")" \
    "$(json_escape "$message")" \
    "$(json_escape "$details")" \
    "$remediation_expr" \
    "$metadata_expr" \
    "$(json_escape "$TIMESTAMP")"
}

# Check 1: UFW Firewall
ufw_output=$(sudo ufw status 2>&1)
ufw_status='red'
ufw_message='UFW is inactive or unreachable.'
ufw_remediation='Run: sudo ufw enable'
ufw_details=$(echo "$ufw_output" | tr '\n' '; ' | sed 's/; $//')

if echo "$ufw_output" | grep -qi '^Status: active'; then
  ufw_rules=$(echo "$ufw_output" | awk 'NR>4 && NF {print}')
  ufw_rule_count=$(echo "$ufw_rules" | sed '/^$/d' | wc -l | tr -d ' ')
  has_22=$(echo "$ufw_rules" | grep -E '22/tcp' | grep -c '100\.64\.0\.0/10')
  has_18789=$(echo "$ufw_rules" | grep -E '18789/tcp' | grep -c '100\.64\.0\.0/10')
  extra_scope=$(echo "$ufw_rules" | grep -v '100\.64\.0\.0/10' | sed '/^$/d' | wc -l | tr -d ' ')
  if [ "$ufw_rule_count" = "2" ] && [ "$has_22" -gt 0 ] && [ "$has_18789" -gt 0 ] && [ "$extra_scope" = "0" ]; then
    ufw_status='green'
    ufw_message='Default-deny active. 2 rules (Tailscale-scoped).'
    ufw_remediation=''
  else
    ufw_status='yellow'
    ufw_message="Active but ${ufw_rule_count} rules detected (expected 2). Review extra rules."
    ufw_remediation='Unexpected UFW rules detected. Run: sudo ufw status numbered — review and delete extras with: sudo ufw delete <number>'
  fi
fi

add_check "$(make_check_json 'network_firewall' 'UFW Firewall' "$ufw_status" "$ufw_message" "$ufw_details" "$ufw_remediation")"
update_overall "$ufw_status"

# Check 2: fail2ban
f2b_active=$(systemctl is-active fail2ban 2>&1)
f2b_enabled=$(systemctl is-enabled fail2ban 2>&1)
f2b_status='red'
f2b_message='fail2ban is not running.'
f2b_details="active=${f2b_active}; enabled=${f2b_enabled}"
f2b_remediation='fail2ban is not running. Run: sudo systemctl enable --now fail2ban'

if [ "$f2b_active" = "active" ]; then
  f2b_jails=$(sudo fail2ban-client status 2>&1)
  sshd_jail=$(sudo fail2ban-client status sshd 2>&1)
  if [ "$f2b_enabled" != "enabled" ]; then
    f2b_status='yellow'
    f2b_message='Running but not enabled at boot.'
    f2b_details="active=${f2b_active}; enabled=${f2b_enabled}"
    f2b_remediation='fail2ban running but not enabled at boot. Run: sudo systemctl enable fail2ban'
  elif echo "$sshd_jail" | grep -q 'Status for the jail: sshd'; then
    currently_banned=$(echo "$sshd_jail" | grep 'Currently banned' | awk '{print $NF}')
    total_banned=$(echo "$sshd_jail" | grep 'Total banned' | awk '{print $NF}')
    currently_failed=$(echo "$sshd_jail" | grep 'Currently failed' | awk '{print $NF}')
    [ -z "$currently_banned" ] && currently_banned='0'
    [ -z "$total_banned" ] && total_banned='0'
    [ -z "$currently_failed" ] && currently_failed='0'
    f2b_status='green'
    f2b_message="Active. sshd jail running. ${currently_banned} currently banned, ${total_banned} total banned."
    f2b_details="sshd jail: ${currently_failed} currently failed, ${currently_banned} currently banned, ${total_banned} total banned"
    if [ "$currently_banned" -gt 0 ] 2>/dev/null; then
      banned_ips=$(echo "$sshd_jail" | grep 'Banned IP list' | sed 's/.*Banned IP list:\s*//')
      f2b_details="${f2b_details}. Banned IPs: ${banned_ips}"
    fi
    f2b_remediation=''
  else
    f2b_status='yellow'
    f2b_message='Running but sshd jail not active.'
    f2b_details=$(echo "$f2b_jails" | tr '\n' '; ' | sed 's/; $//')
    f2b_remediation='fail2ban running but sshd jail not active. Check: sudo fail2ban-client status — If sshd missing, verify /etc/fail2ban/jail.local or jail.d/ has sshd enabled.'
  fi
fi

add_check "$(make_check_json 'network_brute_force' 'fail2ban' "$f2b_status" "$f2b_message" "$f2b_details" "$f2b_remediation")"
update_overall "$f2b_status"

# Check 3: Tailscale (FIX 1: single node call instead of 5)
ts_output=$(tailscale status --json 2>&1)
ts_status='red'
ts_message='Tailscale is not running.'
ts_details=$(echo "$ts_output" | tr '\n' '; ' | sed 's/; $//')
ts_remediation='Run: sudo tailscale up'

if echo "$ts_output" | node -e "try{const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.exit(0)}catch(e){process.exit(1)}" >/dev/null 2>&1; then
  ts_fields=$(echo "$ts_output" | node -e "
    const d = JSON.parse(require('fs').readFileSync(0,'utf8'));
    const b = d.BackendState || 'UNKNOWN';
    const o = !!(d.Self && d.Self.Online);
    const h = d.Self?.HostName || d.Self?.DNSName || 'unknown';
    const i = (d.TailscaleIPs || []).join(',') || 'none';
    process.stdout.write([b, o, h, i].join('|'));
  " 2>/dev/null)
  IFS='|' read -r ts_backend ts_online ts_host ts_ips <<< "$ts_fields"
  ts_details="hostname=${ts_host}; ip=${ts_ips}; BackendState=${ts_backend}; Online=${ts_online}"

  if [ "$ts_backend" = "Running" ] && [ "$ts_online" = "true" ]; then
    ts_status='green'
    ts_message='Tailscale running and online.'
    ts_remediation=''
  elif [ "$ts_backend" = "Running" ] && [ "$ts_online" = "false" ]; then
    ts_status='yellow'
    ts_message='Tailscale connected but not reachable.'
    ts_remediation='Tailscale connected but not reachable. Check: tailscale status'
  fi
fi

add_check "$(make_check_json 'access' 'Tailscale' "$ts_status" "$ts_message" "$ts_details" "$ts_remediation")"
update_overall "$ts_status"

# Check 4: Cloudflare Access
cf_results=''
cf_failures=0
cf_total=3
cf_failed_hosts=''
for host in openclaw.agctl.com clawmetry.agctl.com control.agctl.com; do
  http_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "https://${host}/" 2>&1)
  if [ "$http_code" != '302' ] && [ "$http_code" != '303' ]; then
    cf_failures=$((cf_failures + 1))
    cf_failed_hosts="${cf_failed_hosts} ${host}(${http_code})"
  fi
  cf_results="${cf_results} ${host}:${http_code}"
done

cf_status='green'
cf_message='All 3 hostnames protected by Cloudflare Access.'
cf_details=$(echo "$cf_results" | sed 's/^ *//')
cf_remediation=''
if [ "$cf_failures" -ge 1 ] && [ "$cf_failures" -le 2 ]; then
  cf_status='yellow'
  cf_message="${cf_failures} of ${cf_total} hostnames may be unprotected."
  cf_remediation="Cloudflare Access may be misconfigured. Check Zero Trust dashboard > Access > Applications for missing policies on:${cf_failed_hosts}"
elif [ "$cf_failures" -eq 3 ]; then
  cf_status='red'
  cf_message='Cloudflare Access check failed on all hostnames.'
  cf_remediation="Cloudflare Access may be misconfigured. Check Zero Trust dashboard > Access > Applications for missing policies on:${cf_failed_hosts}"
fi

add_check "$(make_check_json 'public' 'Cloudflare Access' "$cf_status" "$cf_message" "$cf_details" "$cf_remediation")"
update_overall "$cf_status"

# Check 5: Gateway Bind
config_file='/home/openclaw/.openclaw/openclaw.json'
gw_result=$(node -e "
  const fs = require('fs');
  try {
    const cfg = JSON.parse(fs.readFileSync('${config_file}', 'utf8'));
    const bind = cfg.gateway?.bind || 'MISSING';
    const channels = cfg.channels || {};
    const cwChannels = [];
    for (const [name, ch] of Object.entries(channels)) {
      if (ch.configWrites === true) cwChannels.push(name);
    }
    console.log(JSON.stringify({ bind, configWritesChannels: cwChannels }));
  } catch(e) {
    console.log(JSON.stringify({ error: e.message }));
  }
" 2>&1)

gw_status='green'
gw_message='Gateway bound to loopback. configWrites disabled on all channels.'
gw_details=''
gw_remediation=''
if echo "$gw_result" | grep -q '"error"'; then
  gw_status='red'
  gw_message='Cannot read openclaw.json.'
  gw_details="$gw_result"
  gw_remediation='CRITICAL: Gateway exposed to all interfaces. Run: openclaw config set gateway.bind loopback && openclaw gateway restart'
else
  gw_bind=$(echo "$gw_result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(String(d.bind));" 2>/dev/null)
  gw_channels=$(echo "$gw_result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write((d.configWritesChannels||[]).join(','));" 2>/dev/null)
  gw_details="bind=${gw_bind}; configWritesEnabled=${gw_channels:-none}"
  if [ "$gw_bind" = '0.0.0.0' ] || [ "$gw_bind" = 'MISSING' ]; then
    gw_status='red'
    gw_message='CRITICAL: Gateway exposed to all interfaces.'
    gw_remediation='CRITICAL: Gateway exposed to all interfaces. Run: openclaw config set gateway.bind loopback && openclaw gateway restart'
  elif [ "$gw_bind" = '127.0.0.1' ] || [ "$gw_bind" = 'loopback' ]; then
    if [ -n "$gw_channels" ]; then
      gw_status='yellow'
      gw_message="Gateway bound to loopback but configWrites enabled on: ${gw_channels}."
      gw_remediation='configWrites enabled on channel(s). Run: openclaw config set channels.<n>.configWrites false for each channel'
    fi
  else
    gw_status='red'
    gw_message='CRITICAL: Gateway exposed to all interfaces.'
    gw_remediation='CRITICAL: Gateway exposed to all interfaces. Run: openclaw config set gateway.bind loopback && openclaw gateway restart'
  fi
fi

add_check "$(make_check_json 'gateway' 'Gateway Bind' "$gw_status" "$gw_message" "$gw_details" "$gw_remediation")"
update_overall "$gw_status"

# Check 6: Channel Allowlist (FIX 2: empty allowlist is yellow/misconfigured, not red/open)
ch_result=$(node -e "
  const fs = require('fs');
  try {
    const cfg = JSON.parse(fs.readFileSync('${config_file}', 'utf8'));
    const channels = cfg.channels || {};
    const results = [];
    for (const [name, ch] of Object.entries(channels)) {
      results.push({ name, dmPolicy: ch.dmPolicy || 'MISSING', hasAllowedUsers: ((ch.allowedUsers?.length > 0) || (ch.allowFrom?.length > 0)) });
    }
    console.log(JSON.stringify(results));
  } catch(e) {
    console.log(JSON.stringify({ error: e.message }));
  }
" 2>&1)

ch_status='green'
ch_message='All channels use allowlist policy.'
ch_remediation=''
ch_details=''
if echo "$ch_result" | grep -q '"error"'; then
  ch_status='red'
  ch_message='CRITICAL: Open DM policy detected on unknown channels.'
  ch_details="$ch_result"
  ch_remediation='CRITICAL: Open DM policy detected. Run: openclaw config set channels.<n>.dmPolicy allowlist'
else
  ch_details=$(echo "$ch_result" | node -e "const arr=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(arr.map(c=>c.name+':'+c.dmPolicy).join(', '));" 2>/dev/null)
  red_channels=$(echo "$ch_result" | node -e "const arr=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(arr.filter(c=>c.dmPolicy==='open'||c.dmPolicy==='MISSING').map(c=>c.name).join(','));" 2>/dev/null)
  yellow_channels=$(echo "$ch_result" | node -e "const arr=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(arr.filter(c=>c.dmPolicy==='pairing').map(c=>c.name).join(','));" 2>/dev/null)
  bad_allowlist=$(echo "$ch_result" | node -e "const arr=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(arr.filter(c=>c.dmPolicy==='allowlist'&&!c.hasAllowedUsers).map(c=>c.name).join(','));" 2>/dev/null)

  if [ -n "$red_channels" ]; then
    ch_status='red'
    ch_message="CRITICAL: Open DM policy detected on ${red_channels}."
    ch_remediation='CRITICAL: Open DM policy detected. Run: openclaw config set channels.<n>.dmPolicy allowlist'
  elif [ -n "$yellow_channels" ]; then
    ch_status='yellow'
    ch_message="Pairing mode active on ${yellow_channels}. Less restrictive than allowlist."
    ch_remediation='Pairing mode active on channel(s). Switch to allowlist when onboarding is complete.'
  elif [ -n "$bad_allowlist" ]; then
    ch_status='yellow'
    ch_message="Allowlist on ${bad_allowlist} has no authorized users. All messages blocked."
    ch_remediation='Allowlist has no entries. Add authorized users: openclaw config set channels.<n>.allowFrom <user_id>'
  fi
fi

add_check "$(make_check_json 'channel' 'Channel Allowlist' "$ch_status" "$ch_message" "$ch_details" "$ch_remediation")"
update_overall "$ch_status"

# Check 7: SOUL.md Integrity
soul_path='/home/openclaw/.openclaw/workspace/SOUL.md'
expected_hash_file='/home/openclaw/.openclaw/.soul-hash'
current_hash=$(sha256sum "$soul_path" 2>&1 | awk '{print $1}')
soul_status='green'
soul_message='SOUL.md integrity verified. Hash matches baseline.'
soul_remediation=''

if [ ! -f "$soul_path" ]; then
  soul_status='red'
  soul_message='SOUL.md has been modified since last approved change.'
  soul_details="current=missing; expected=unknown"
  soul_remediation="SOUL.md has been modified since last approved change. Verify changes with: diff <backup> SOUL.md — If changes are approved, update baseline: sha256sum SOUL.md | awk '{print \$1}' > ~/.openclaw/.soul-hash"
else
  hash_dir=$(dirname "$expected_hash_file")
  if [ ! -f "$expected_hash_file" ] && [ -d "$hash_dir" ]; then
    echo "$current_hash" > "$expected_hash_file" 2>/dev/null
    soul_message='Baseline hash recorded.'
  fi

  expected_hash=''
  if [ -f "$expected_hash_file" ]; then
    expected_hash=$(cat "$expected_hash_file" 2>/dev/null)
  fi
  if [ -z "$expected_hash" ]; then
    expected_hash='missing'
  fi
  acip_present=$(grep -c 'Security Anchor\|Content Trust Policy\|Prompt Injection Defense' "$soul_path" 2>/dev/null)
  soul_details="current=${current_hash:0:12}; expected=${expected_hash:0:12}"

  if [ "$current_hash" != "$expected_hash" ]; then
    soul_status='red'
    soul_message='SOUL.md has been modified since last approved change.'
    soul_details="${soul_details}; mismatch=true"
    soul_remediation="SOUL.md has been modified since last approved change. Verify changes with: diff <backup> SOUL.md — If changes are approved, update baseline: sha256sum SOUL.md | awk '{print \$1}' > ~/.openclaw/.soul-hash"
  elif [ "$acip_present" = '0' ]; then
    soul_status='yellow'
    soul_message='ACIP injection defense section missing from SOUL.md.'
    soul_remediation='ACIP injection defense section missing from SOUL.md. Restore from backup.'
  fi
fi

add_check "$(make_check_json 'reasoning' 'SOUL.md Integrity' "$soul_status" "$soul_message" "$soul_details" "$soul_remediation")"
update_overall "$soul_status"

# Check 8: Tool Policy (FIX 3: sandbox-only is green, tools.deny not in config schema)
tool_result=$(node -e "
  const fs = require('fs');
  try {
    const cfg = JSON.parse(fs.readFileSync('${config_file}', 'utf8'));
    const defaults = cfg.agents?.defaults || {};
    const deny = defaults.tools?.deny || [];
    const sandboxMode = defaults.sandbox?.mode || 'MISSING';
    const dockerNetwork = defaults.sandbox?.docker?.network || 'MISSING';
    const expectedDeny = ['browser','exec','process','apply_patch','write','edit'];
    const missingDeny = expectedDeny.filter(t => !deny.includes(t));
    console.log(JSON.stringify({ deny, missingDeny, sandboxMode, dockerNetwork }));
  } catch(e) {
    console.log(JSON.stringify({ error: e.message }));
  }
" 2>&1)

tool_status='green'
tool_message='Sandbox fully isolated. Tool deny list complete.'
tool_details=''
tool_remediation=''
if echo "$tool_result" | grep -q '"error"'; then
  tool_status='red'
  tool_message='Sandbox not fully isolated.'
  tool_details="$tool_result"
  tool_remediation='Sandbox not fully isolated. Run: openclaw config set agents.defaults.sandbox.mode all && openclaw config set agents.defaults.sandbox.docker.network none'
else
  tool_mode=$(echo "$tool_result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(d.sandboxMode);" 2>/dev/null)
  tool_net=$(echo "$tool_result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(d.dockerNetwork);" 2>/dev/null)
  tool_missing=$(echo "$tool_result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write((d.missingDeny||[]).join(','));" 2>/dev/null)
  tool_deny=$(echo "$tool_result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write((d.deny||[]).join(','));" 2>/dev/null)
  tool_details="sandbox.mode=${tool_mode}; sandbox.docker.network=${tool_net}; tools.deny=${tool_deny:-not_in_schema}"

  if [ "$tool_mode" != 'all' ] || [ "$tool_net" != 'none' ]; then
    tool_status='red'
    tool_message='Sandbox not fully isolated.'
    tool_remediation='Sandbox not fully isolated. Run: openclaw config set agents.defaults.sandbox.mode all && openclaw config set agents.defaults.sandbox.docker.network none'
  elif [ -n "$tool_missing" ]; then
    tool_status='green'
    tool_message="Sandbox isolated. tools.deny not in config schema (enforced via AGENTS.md)."
    tool_remediation=''
  fi
fi

add_check "$(make_check_json 'operational' 'Tool Policy' "$tool_status" "$tool_message" "$tool_details" "$tool_remediation")"
update_overall "$tool_status"

# Check 9: Memory Security
facts_db='/home/openclaw/.openclaw/memory/facts.db'
mem_status='green'
mem_message='facts.db permissions correct. No credentials detected.'
mem_details=''
mem_remediation=''

if [ ! -f "$facts_db" ]; then
  mem_status='yellow'
  mem_message='facts.db not found at expected path.'
  mem_details="path=${facts_db}; permissions=missing; owner=missing; credential_count=N/A"
  mem_remediation='File permissions incorrect on facts.db. Run: chmod 660 /home/openclaw/.openclaw/memory/facts.db && chown openclaw:openclaw /home/openclaw/.openclaw/memory/facts.db'
else
  perms=$(stat -c '%a' "$facts_db" 2>&1)
  owner=$(stat -c '%U:%G' "$facts_db" 2>&1)
  cred_count=$(sqlite3 "$facts_db" "SELECT count(*) FROM facts WHERE value LIKE '%sk-%' OR value LIKE '%ghp_%' OR lower(key) LIKE '%password%' OR lower(key) LIKE '%api_key%' OR lower(key) LIKE '%token%' OR lower(key) LIKE '%secret%';" 2>&1)
  [ -z "$cred_count" ] && cred_count='0'
  mem_details="permissions=${perms}; owner=${owner}; credential_count=${cred_count}"

  if [ "$cred_count" -gt 0 ] 2>/dev/null; then
    mem_status='red'
    mem_message="Credentials detected in memory database. ${cred_count} entries matching sensitive patterns."
    mem_remediation="Credentials detected in memory database. Run HEARTBEAT credential scrub immediately. Found ${cred_count} entries matching sensitive patterns."
  elif [ "$perms" != '660' ] || [ "$owner" != 'openclaw:openclaw' ]; then
    mem_status='yellow'
    mem_message="facts.db permissions incorrect (found: ${perms}, expected: 660)."
    mem_remediation='File permissions incorrect on facts.db. Run: chmod 660 /home/openclaw/.openclaw/memory/facts.db && chown openclaw:openclaw /home/openclaw/.openclaw/memory/facts.db'
  fi
fi

add_check "$(make_check_json 'memory' 'Memory Security' "$mem_status" "$mem_message" "$mem_details" "$mem_remediation")"
update_overall "$mem_status"

# ---- Check 10: OpenClaw Version Currency ----
VERSION_CACHE_FILE='/tmp/security-version-cache.json'
VERSION_CACHE_MAX_AGE=86400  # 24 hours in seconds
FORCE_VERSION_CHECK="${FORCE_VERSION_CHECK:-false}"

use_cache=false
if [ "$FORCE_VERSION_CHECK" != "true" ] && [ -f "$VERSION_CACHE_FILE" ]; then
  cache_age=$(( $(date +%s) - $(stat -c %Y "$VERSION_CACHE_FILE" 2>/dev/null || echo 0) ))
  if [ "$cache_age" -lt "$VERSION_CACHE_MAX_AGE" ]; then
    use_cache=true
  fi
fi

if [ "$use_cache" = "true" ]; then
  version_check_json=$(cat "$VERSION_CACHE_FILE")
  add_check "$version_check_json"
  version_status=$(echo "$version_check_json" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.status)" 2>/dev/null)
  overall_version_status="$version_status"
  if [ "$overall_version_status" = 'unknown' ]; then
    overall_version_status='yellow'
  fi
  update_overall "$overall_version_status"
else
  current_version=$(openclaw --version 2>&1 | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1)

  registry_json=$(timeout 15 npm view openclaw versions --json 2>&1)
  npm_exit=$?

  if [ $npm_exit -ne 0 ] || [ -z "$registry_json" ]; then
    version_layer='version'
    version_name='OpenClaw Version'
    version_status='unknown'
    version_message='Could not reach npm registry. Check network connectivity.'
    version_details=''
    version_remediation=''
    version_metadata='{}'
  else
    versions_behind=$(node -e "
      const versions = JSON.parse(process.argv[1]);
      const stable = versions.filter(v => !v.includes('-'));
      const currentIdx = stable.indexOf(process.argv[2]);
      const latestIdx = stable.length - 1;
      if (currentIdx === -1) {
        console.log(JSON.stringify({ count: -1, current: process.argv[2], latest: stable[latestIdx] }));
      } else {
        console.log(JSON.stringify({
          count: latestIdx - currentIdx,
          current: process.argv[2],
          latest: stable[latestIdx],
          missed: stable.slice(currentIdx + 1).reverse().slice(0, 5)
        }));
      }
    " "$registry_json" "$current_version" 2>/dev/null)

    behind_count=$(echo "$versions_behind" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.count)")
    latest=$(echo "$versions_behind" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.latest || '')")
    missed_versions=$(echo "$versions_behind" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log((d.missed||[]).join(', '))")

    latest_release_body=$(timeout 15 curl -sf "https://api.github.com/repos/openclaw/openclaw/releases/tags/v${latest}" 2>/dev/null | node -e "
      try {
        const d = JSON.parse(require('fs').readFileSync(0, 'utf8'));
        console.log(d.body || '');
      } catch { console.log(''); }
    ")

    latest_stats=$(node -e "
      const body = process.argv[1] || '';
      let inChanges = false, inFixes = false;
      let features = 0, fixes = 0, securityFixes = 0;

      for (const raw of body.split('\n')) {
        const line = raw.trim();
        if (line.match(/^###\s*Changes/i)) { inChanges = true; inFixes = false; continue; }
        if (line.match(/^###\s*Fixes/i)) { inFixes = true; inChanges = false; continue; }
        if (line.match(/^###\s/) && !line.match(/Changes|Fixes/i)) { inChanges = false; inFixes = false; continue; }

        if (!line.startsWith('- ')) continue;

        if (inChanges) features++;
        if (inFixes) {
          fixes++;
          if (line.match(/^- Security\//i)) securityFixes++;
        }
      }

      console.log(JSON.stringify({ features, fixes, securityFixes }));
    " "$latest_release_body" 2>/dev/null)

    latest_features=$(echo "$latest_stats" | node -e "try { const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.features ?? 0); } catch { console.log(0); }")
    latest_fixes=$(echo "$latest_stats" | node -e "try { const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.fixes ?? 0); } catch { console.log(0); }")
    latest_security=$(echo "$latest_stats" | node -e "try { const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.securityFixes ?? 0); } catch { console.log(0); }")

    total_security_fixes=0
    if [ "$behind_count" -gt 0 ] 2>/dev/null; then
      missed_array=$(echo "$versions_behind" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8')); (d.missed||[]).slice(0,5).forEach(v=>console.log(v))")

      while IFS= read -r ver; do
        [ -z "$ver" ] && continue
        ver_body=$(timeout 10 curl -sf "https://api.github.com/repos/openclaw/openclaw/releases/tags/v${ver}" 2>/dev/null | node -e "
          try { const d=JSON.parse(require('fs').readFileSync(0,'utf8')); console.log(d.body||''); } catch { console.log(''); }
        ")
        ver_sec=$(echo "$ver_body" | grep -ciE '^\s*-\s*Security/' || echo 0)
        total_security_fixes=$((total_security_fixes + ver_sec))
      done <<< "$missed_array"
    fi

    security_flag='false'
    if [ "$total_security_fixes" -gt 0 ]; then
      security_flag='true'
    fi

    latest_release_preview=$(echo "$latest_release_body" | head -c 15000)

    version_layer='version'
    version_name='OpenClaw Version'

    if [ "$behind_count" -eq 0 ] 2>/dev/null; then
      version_status='green'
      version_message="Running latest stable: v${current_version}"
      version_details="Latest release analyzed from GitHub notes."
      version_remediation=''
    elif [ "$behind_count" -eq 1 ] 2>/dev/null && [ "$total_security_fixes" -eq 0 ] 2>/dev/null; then
      version_status='yellow'
      version_message="1 version behind. Current: v${current_version}. Latest: v${latest}."
      version_details="Missed: ${missed_versions}"
      version_remediation='New release available. Review changelog before updating: https://github.com/openclaw/openclaw/releases'
    elif [ "$behind_count" -ge 2 ] 2>/dev/null || [ "$total_security_fixes" -gt 0 ] 2>/dev/null; then
      version_status='red'
      version_message="${behind_count} versions behind. Current: v${current_version}. Latest: v${latest}."
      version_details="Missed: ${missed_versions}. Security fixes across missed versions: ${total_security_fixes}."
      if [ "$total_security_fixes" -gt 0 ] 2>/dev/null; then
        version_remediation='Security-related fixes missed. Apply within 48 hours. Safe update: cp ~/.openclaw/openclaw.json ~/.openclaw/openclaw.json.bak && npm update -g openclaw@latest && openclaw doctor'
      else
        version_remediation="Multiple versions behind (${behind_count}). Missed: ${missed_versions}. Review changelog and update: https://github.com/openclaw/openclaw/releases"
      fi
    elif [ "$behind_count" -eq -1 ] 2>/dev/null; then
      version_status='yellow'
      version_message="Current version v${current_version} not found in npm registry. Custom or pre-release build."
      version_details=''
      version_remediation='Verify installation: openclaw --version. If intentional (pinned version), this is expected.'
    else
      version_status='unknown'
      version_message='Unable to determine OpenClaw version status.'
      version_details='Version comparison returned unexpected output.'
      version_remediation=''
    fi

    version_metadata=$(node -e "
      console.log(JSON.stringify({
        current_version: process.argv[1],
        latest_version: process.argv[2],
        versions_behind: parseInt(process.argv[3], 10),
        security_flag: process.argv[4] === 'true',
        total_security_fixes: parseInt(process.argv[5], 10),
        latest_features: parseInt(process.argv[6], 10),
        latest_fixes: parseInt(process.argv[7], 10),
        latest_security_fixes: parseInt(process.argv[8], 10),
        latest_release_preview: process.argv[9],
        release_notes_url: 'https://github.com/openclaw/openclaw/releases',
        missed_versions: process.argv[10] ? process.argv[10].split(', ') : []
      }));
    " "$current_version" "$latest" "$behind_count" "$security_flag" "$total_security_fixes" "$latest_features" "$latest_fixes" "$latest_security" "$latest_release_preview" "$missed_versions" 2>/dev/null)
  fi

  if [ -z "$version_metadata" ]; then
    version_metadata='{}'
  fi

  version_check_json=$(make_check_json "$version_layer" "$version_name" "$version_status" "$version_message" "$version_details" "$version_remediation" "$version_metadata")
  echo "$version_check_json" > "$VERSION_CACHE_FILE"
  add_check "$version_check_json"

  overall_version_status="$version_status"
  if [ "$overall_version_status" = 'unknown' ]; then
    overall_version_status='yellow'
  fi
  update_overall "$overall_version_status"
fi

# Check 11: Config Drift
config_drift_result=$(CONFIG_FILE='/home/openclaw/.openclaw/openclaw.json' BASELINE_FILE='/var/tmp/config-drift-baseline.json' node -e "
  const fs = require('fs');

  const configFile = process.env.CONFIG_FILE;
  const baselineFile = process.env.BASELINE_FILE;
  const now = new Date().toISOString();

  const make = (status, message, details, remediation, metadata) => {
    process.stdout.write(JSON.stringify({ status, message, details, remediation, metadata, checked_at: now }));
  };

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
    if (Object.prototype.hasOwnProperty.call(out, '')) {
      delete out[''];
    }
    return out;
  };

  const isCritical = (key) => {
    if (key === 'sandbox.mode') return true;
    if (key === 'sandbox.docker.network') return true;
    if (key === 'tools.deny' || key.startsWith('tools.deny.')) return true;
    if (/^channels\.[^.]+\.configWrites$/.test(key)) return true;
    if (/^channels\.[^.]+\.allowFrom(\.|$)/.test(key)) return true;
    return false;
  };

  let config;
  try {
    const raw = fs.readFileSync(configFile, 'utf8');
    config = JSON.parse(raw);
  } catch (error) {
    make('red', 'Cannot read config file.', String(error.message || error), 'Run /usr/local/bin/reset-config-baseline.sh to accept current config as new baseline', {
      changes_count: 0,
      critical_changes: [],
      non_critical_changes: []
    });
    process.exit(0);
  }

  const currentFlat = flatten(config);

  let baselineRaw;
  try {
    baselineRaw = fs.readFileSync(baselineFile, 'utf8');
  } catch (_error) {
    fs.writeFileSync(baselineFile, JSON.stringify(currentFlat, null, 2));
    make('green', 'Baseline established', 'Stored ' + Object.keys(currentFlat).length + ' keys in baseline snapshot.', null, {
      changes_count: 0,
      critical_changes: [],
      non_critical_changes: []
    });
    process.exit(0);
  }

  let baseline;
  try {
    baseline = JSON.parse(baselineRaw);
    if (!baseline || typeof baseline !== 'object' || Array.isArray(baseline)) {
      throw new Error('Baseline snapshot is not an object');
    }
  } catch (_error) {
    fs.writeFileSync(baselineFile, JSON.stringify(currentFlat, null, 2));
    make('green', 'Baseline established', 'Stored ' + Object.keys(currentFlat).length + ' keys in baseline snapshot.', null, {
      changes_count: 0,
      critical_changes: [],
      non_critical_changes: []
    });
    process.exit(0);
  }

  const changed = [];
  const added = [];
  const removed = [];

  for (const key of Object.keys(currentFlat)) {
    if (Object.prototype.hasOwnProperty.call(baseline, key)) {
      if (JSON.stringify(currentFlat[key]) !== JSON.stringify(baseline[key])) {
        changed.push({ key, from: baseline[key], to: currentFlat[key] });
      }
    } else {
      added.push({ key, value: currentFlat[key] });
    }
  }

  for (const key of Object.keys(baseline)) {
    if (!Object.prototype.hasOwnProperty.call(currentFlat, key)) {
      removed.push({ key, value: baseline[key] });
    }
  }

  const allChanges = [
    ...changed.map((item) => ({ type: 'changed', ...item })),
    ...added.map((item) => ({ type: 'added', ...item })),
    ...removed.map((item) => ({ type: 'removed', ...item }))
  ];

  if (allChanges.length === 0) {
    make('green', 'No config drift detected.', 'Current config matches baseline.', null, {
      changes_count: 0,
      critical_changes: [],
      non_critical_changes: []
    });
    process.exit(0);
  }

  const critical = [];
  const nonCritical = [];

  for (const item of allChanges) {
    if (isCritical(item.key)) {
      critical.push(item);
    } else {
      nonCritical.push(item);
    }
  }

  const toLine = (item) => {
    if (item.type === 'changed') {
      return 'changed ' + item.key + ': ' + stringify(item.from) + ' -> ' + stringify(item.to);
    }
    if (item.type === 'added') {
      return 'added ' + item.key + ': ' + stringify(item.value);
    }
    return 'removed ' + item.key + ': ' + stringify(item.value);
  };

  const details = allChanges.map(toLine).join('; ');
  const status = critical.length > 0 ? 'red' : 'yellow';
  const message = status === 'red'
    ? ('Critical config drift detected (' + allChanges.length + ' changes).')
    : ('Config drift detected (' + allChanges.length + ' changes).');

  make(status, message, details, 'Run /usr/local/bin/reset-config-baseline.sh to accept current config as new baseline', {
    changes_count: allChanges.length,
    critical_changes: critical.map(toLine),
    non_critical_changes: nonCritical.map(toLine)
  });
" 2>&1)

config_drift_status=$(echo "$config_drift_result" | node -e "try{const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(String(d.status||'red'));}catch(e){process.stdout.write('red');}" 2>/dev/null)
config_drift_message=$(echo "$config_drift_result" | node -e "try{const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(String(d.message||'Config drift check failed.'));}catch(e){process.stdout.write('Config drift check failed.');}" 2>/dev/null)
config_drift_details=$(echo "$config_drift_result" | node -e "try{const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(String(d.details||''));}catch(e){process.stdout.write('Unable to parse config drift result.');}" 2>/dev/null)
config_drift_remediation=$(echo "$config_drift_result" | node -e "try{const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(d.remediation===null?'':String(d.remediation||''));}catch(e){process.stdout.write('Run /usr/local/bin/reset-config-baseline.sh to accept current config as new baseline');}" 2>/dev/null)
config_drift_metadata=$(echo "$config_drift_result" | node -e "try{const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(JSON.stringify(d.metadata||{}));}catch(e){process.stdout.write('{}');}" 2>/dev/null)

add_check "$(make_check_json 'injection-defense' 'Config Drift' "$config_drift_status" "$config_drift_message" "$config_drift_details" "$config_drift_remediation" "$config_drift_metadata")"
update_overall "$config_drift_status"

# Check 12-13 journal snapshot (bounded to avoid hangs on large logs)
journalctl_safe() {
  if command -v timeout >/dev/null 2>&1; then
    timeout 12s journalctl "$@" 2>/dev/null | tail -n 8000
  else
    journalctl "$@" 2>/dev/null | tail -n 8000
  fi
}

openclaw_boot_logs=$(journalctl_safe -u openclaw --boot -q --no-pager)
openclaw_24h_logs=$(journalctl_safe -u openclaw --since '24 hours ago' -q --no-pager)
BOOT_LOGS="$openclaw_boot_logs"
RECENT_LOGS="$openclaw_24h_logs"

# Check 12: Homoglyph Normalizer
homoglyph_registered='false'
if echo "$openclaw_boot_logs" | grep -q 'homoglyph-normalizer: registered'; then
  homoglyph_registered='true'
fi
homoglyph_critical_count=$(echo "$openclaw_24h_logs" | grep 'homoglyph-normalizer:' | grep -c 'CRITICAL')
homoglyph_warning_count=$(echo "$openclaw_24h_logs" | grep 'homoglyph-normalizer:' | grep -c 'WARNING')

homoglyph_status='red'
homoglyph_message='Homoglyph normalizer plugin not registered in current boot logs.'
homoglyph_details="registered=${homoglyph_registered}; critical=${homoglyph_critical_count}; warning=${homoglyph_warning_count}"
homoglyph_remediation='Verify OpenClaw is running and plugin is installed, then restart OpenClaw and confirm journal contains: homoglyph-normalizer: registered'

if [ "$homoglyph_registered" = 'true' ]; then
  if [ "$homoglyph_critical_count" -gt 0 ] || [ "$homoglyph_warning_count" -gt 0 ]; then
    total_homoglyph=$((homoglyph_critical_count + homoglyph_warning_count))
    homoglyph_status='yellow'
    homoglyph_message="Homoglyph normalizer active with ${total_homoglyph} detection(s) in last 24h."
    homoglyph_details="registered=${homoglyph_registered}; critical=${homoglyph_critical_count}; warning=${homoglyph_warning_count}; window=24h"
    homoglyph_remediation='Review recent homoglyph-normalizer detections in journalctl and confirm intended blocking behavior.'
  else
    homoglyph_status='green'
    homoglyph_message='Homoglyph normalizer registered; no detections in last 24h.'
    homoglyph_details="registered=${homoglyph_registered}; critical=${homoglyph_critical_count}; warning=${homoglyph_warning_count}; window=24h"
    homoglyph_remediation=''
  fi
fi

homoglyph_metadata=$(node -e "
  console.log(JSON.stringify({
    registered: process.argv[1] === 'true',
    critical_count: parseInt(process.argv[2], 10) || 0,
    warning_count: parseInt(process.argv[3], 10) || 0
  }));
" "$homoglyph_registered" "$homoglyph_critical_count" "$homoglyph_warning_count" 2>/dev/null)

add_check "$(make_check_json 'injection-defense' 'Homoglyph Normalizer' "$homoglyph_status" "$homoglyph_message" "$homoglyph_details" "$homoglyph_remediation" "$homoglyph_metadata")"
update_overall "$homoglyph_status"

# Check 13: Credential Scanner
credential_registered='false'
if echo "$openclaw_boot_logs" | grep -q 'credential-scanner: registered'; then
  credential_registered='true'
fi
credential_critical_count=$(echo "$openclaw_24h_logs" | grep 'credential-scanner:' | grep -c 'CRITICAL')
credential_warning_count=$(echo "$openclaw_24h_logs" | grep 'credential-scanner:' | grep -c 'WARNING')

credential_status='red'
credential_message='Credential scanner plugin not registered in current boot logs.'
credential_details="registered=${credential_registered}; critical=${credential_critical_count}; warning=${credential_warning_count}"
credential_remediation='Verify OpenClaw is running and plugin is installed, then restart OpenClaw and confirm journal contains: credential-scanner: registered'

if [ "$credential_registered" = 'true' ]; then
  if [ "$credential_critical_count" -gt 0 ]; then
    credential_status='red'
    credential_message="CRITICAL: Credential scanner found ${credential_critical_count} credential leak detection(s) in last 24h."
    credential_details="registered=${credential_registered}; critical=${credential_critical_count}; warning=${credential_warning_count}; window=24h"
    credential_remediation='Treat as security incident: rotate exposed credentials immediately and audit affected logs/prompts.'
  elif [ "$credential_warning_count" -gt 0 ]; then
    credential_status='yellow'
    credential_message="Credential scanner active with ${credential_warning_count} warning detection(s) in last 24h."
    credential_details="registered=${credential_registered}; critical=${credential_critical_count}; warning=${credential_warning_count}; window=24h"
    credential_remediation='Review entropy-only detections to confirm whether sensitive tokens were present.'
  else
    credential_status='green'
    credential_message='Credential scanner registered; no credential detections in last 24h.'
    credential_details="registered=${credential_registered}; critical=${credential_critical_count}; warning=${credential_warning_count}; window=24h"
    credential_remediation=''
  fi
fi

credential_metadata=$(node -e "
  console.log(JSON.stringify({
    registered: process.argv[1] === 'true',
    critical_count: parseInt(process.argv[2], 10) || 0,
    warning_count: parseInt(process.argv[3], 10) || 0
  }));
" "$credential_registered" "$credential_critical_count" "$credential_warning_count" 2>/dev/null)

add_check "$(make_check_json 'injection-defense' 'Credential Scanner' "$credential_status" "$credential_message" "$credential_details" "$credential_remediation" "$credential_metadata")"
update_overall "$credential_status"

# Check 14: Security Hook
security_hook_registered='false'
if echo "$BOOT_LOGS" | grep -q 'security-hook: registered'; then
  security_hook_registered='true'
fi
security_hook_blocked_count=$(echo "$RECENT_LOGS" | grep -c 'security-hook: blocked')

security_hook_status='red'
security_hook_message='Security hook plugin not registered in current boot logs.'
security_hook_details="registered=${security_hook_registered}; blocked=${security_hook_blocked_count}; window=24h"
security_hook_remediation='Check plugin at ~/.openclaw/extensions/security-hook/. Verify openclaw.json has security-hook in plugins.entries. Restart: sudo systemctl restart openclaw'

if [ "$security_hook_registered" = 'true' ]; then
  if [ "$security_hook_blocked_count" -gt 0 ]; then
    security_hook_status='yellow'
    security_hook_message="Security hook active with ${security_hook_blocked_count} blocked call(s) in last 24h."
  else
    security_hook_status='green'
    security_hook_message='Security hook registered; no blocked calls in last 24h.'
    security_hook_remediation=''
  fi
fi

security_hook_metadata=$(node -e "
  console.log(JSON.stringify({
    registered: process.argv[1] === 'true',
    blocked_count: parseInt(process.argv[2], 10) || 0
  }));
" "$security_hook_registered" "$security_hook_blocked_count" 2>/dev/null)

add_check "$(make_check_json 'injection-defense' 'Security Hook' "$security_hook_status" "$security_hook_message" "$security_hook_details" "$security_hook_remediation" "$security_hook_metadata")"
update_overall "$security_hook_status"

final_json=$(node -e "
  const out = {
    generated_at: process.argv[1],
    overall_status: process.argv[2],
    checks: JSON.parse(process.argv[3])
  };
  process.stdout.write(JSON.stringify(out));
" "$TIMESTAMP" "$OVERALL" "$CHECKS" 2>/dev/null)

if [ -z "$final_json" ]; then
  final_json='{"generated_at":"'"$TIMESTAMP"'","overall_status":"red","checks":[]}'
fi

tmp_file='/tmp/.security-health-results.tmp'
out_file='/tmp/security-health-results.json'
printf '%s\n' "$final_json" > "$tmp_file"
mv "$tmp_file" "$out_file"
