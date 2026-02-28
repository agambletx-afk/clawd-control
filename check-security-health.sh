#!/usr/bin/env bash
# check-security-health.sh — Security health checks for Jarvis/OpenClaw
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

  local remediation_expr="null"
  if [ "$status" != "green" ]; then
    remediation_expr=$(json_escape "$remediation")
  fi

  printf '{"layer":%s,"name":%s,"status":%s,"message":%s,"details":%s,"remediation":%s,"checked_at":%s}' \
    "$(json_escape "$layer")" \
    "$(json_escape "$name")" \
    "$(json_escape "$status")" \
    "$(json_escape "$message")" \
    "$(json_escape "$details")" \
    "$remediation_expr" \
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

# Check 3: Tailscale
ts_output=$(tailscale status --json 2>&1)
ts_status='red'
ts_message='Tailscale is not running.'
ts_details=$(echo "$ts_output" | tr '\n' '; ' | sed 's/; $//')
ts_remediation='Run: sudo tailscale up'

if echo "$ts_output" | node -e "try{const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.exit(0)}catch(e){process.exit(1)}" >/dev/null 2>&1; then
  ts_parsed=$(echo "$ts_output" | node -e "
    const d = JSON.parse(require('fs').readFileSync(0,'utf8'));
    const backend = d.BackendState || 'UNKNOWN';
    const online = !!(d.Self && d.Self.Online);
    const host = d.Self?.HostName || d.Self?.DNSName || 'unknown';
    const ips = (d.TailscaleIPs || []).join(',') || 'none';
    process.stdout.write(JSON.stringify({backend,online,host,ips}));
  " 2>/dev/null)
  ts_backend=$(echo "$ts_parsed" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(d.backend);")
  ts_online=$(echo "$ts_parsed" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(String(d.online));")
  ts_host=$(echo "$ts_parsed" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(d.host);")
  ts_ips=$(echo "$ts_parsed" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(d.ips);")
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

# Check 6: Channel Allowlist
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
    ch_status='red'
    ch_message="CRITICAL: Open DM policy detected on ${bad_allowlist}."
    ch_remediation='CRITICAL: Open DM policy detected. Run: openclaw config set channels.<n>.dmPolicy allowlist'
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
  acip_present=$(grep -c 'Security Anchor\|Content Trust Policy' "$soul_path" 2>/dev/null)
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

# Check 8: Tool Policy
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
  tool_mode=$(echo "$tool_result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(d.sandboxMode);")
  tool_net=$(echo "$tool_result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write(d.dockerNetwork);")
  tool_missing=$(echo "$tool_result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write((d.missingDeny||[]).join(','));")
  tool_deny=$(echo "$tool_result" | node -e "const d=JSON.parse(require('fs').readFileSync(0,'utf8'));process.stdout.write((d.deny||[]).join(','));")
  tool_details="sandbox.mode=${tool_mode}; sandbox.docker.network=${tool_net}; tools.deny=${tool_deny}"

  if [ "$tool_mode" != 'all' ] || [ "$tool_net" != 'none' ]; then
    tool_status='red'
    tool_message='Sandbox not fully isolated.'
    tool_remediation='Sandbox not fully isolated. Run: openclaw config set agents.defaults.sandbox.mode all && openclaw config set agents.defaults.sandbox.docker.network none'
  elif [ -n "$tool_missing" ]; then
    tool_status='yellow'
    tool_message="Sandbox correct but tools.deny missing: ${tool_missing}."
    tool_remediation='tools.deny incomplete. Expected deny list: browser,exec,process,apply_patch,write,edit'
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
