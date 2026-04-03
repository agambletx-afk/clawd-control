# Manual VPS Patch: LLM Proxy Bypass Check

Implements the LLM Proxy Bypass security check in `/usr/local/bin/check-security-health.sh`.
This check verifies that the OpenClaw gateway process does not have proxy environment
variables set, which would silently route LLM API calls through the DataImpulse
residential proxy instead of going direct.

## Prerequisites

- `systemctl` access to query openclaw service PID
- Read access to `/proc/<PID>/environ`
- The gateway env file at `/opt/openclaw.env`

## Patch Instructions

### Insert new Check 23 at line 1161

After the last check (Check 22: Facts DB Permissions) and its `update_overall` call,
there are two blank lines before the final JSON assembly block starting with
`final_json=$(node -e "`.

Insert the following block **between line 1161 and line 1164** (i.e., after
`update_overall "$perm_facts_status"` and before `final_json=$(node -e "`):

```bash
# Check 23: LLM Proxy Bypass
# Verifies the OpenClaw gateway process has no proxy env vars that would
# route LLM API calls (OpenAI, Anthropic, Gemini, Groq, Mistral) through
# the DataImpulse residential proxy instead of going direct.
llm_proxy_status='green'
llm_proxy_message='Gateway process has no proxy env vars. LLM API calls route direct.'
llm_proxy_details=''
llm_proxy_remediation=''
llm_proxy_leaked_vars=()

gw_pid=$(systemctl show openclaw --property=MainPID --value 2>/dev/null)

if [ -z "$gw_pid" ] || [ "$gw_pid" = "0" ]; then
  llm_proxy_status='yellow'
  llm_proxy_message='Gateway not running — cannot verify proxy bypass.'
  llm_proxy_remediation='Start the OpenClaw gateway: sudo systemctl start openclaw'
else
  # Read the gateway process environment from procfs
  if [ -r "/proc/${gw_pid}/environ" ]; then
    gw_environ=$(tr '\0' '\n' < "/proc/${gw_pid}/environ" 2>/dev/null)
    for var_name in HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy; do
      var_value=$(echo "$gw_environ" | grep -m1 "^${var_name}=" | cut -d= -f2-)
      if [ -n "$var_value" ]; then
        llm_proxy_leaked_vars+=("${var_name}=${var_value}")
      fi
    done
  fi

  # Also check the gateway env file for proxy vars
  gw_env_file='/opt/openclaw.env'
  if [ -f "$gw_env_file" ]; then
    for var_name in HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy; do
      env_value=$(grep -m1 "^${var_name}=" "$gw_env_file" 2>/dev/null | cut -d= -f2-)
      if [ -n "$env_value" ]; then
        # Only add if not already found in process env
        already_found=false
        for existing in "${llm_proxy_leaked_vars[@]}"; do
          case "$existing" in "${var_name}="*) already_found=true; break ;; esac
        done
        if [ "$already_found" = false ]; then
          llm_proxy_leaked_vars+=("${var_name}=${env_value} (in ${gw_env_file})")
        fi
      fi
    done
  fi

  if [ "${#llm_proxy_leaked_vars[@]}" -gt 0 ]; then
    llm_proxy_status='red'
    llm_proxy_message="Proxy env var(s) found in gateway process: $(IFS=', '; echo "${llm_proxy_leaked_vars[*]}")"
    llm_proxy_details="LLM API calls to api.openai.com, api.anthropic.com, generativelanguage.googleapis.com, api.groq.com, api.mistral.ai may be routing through the DataImpulse residential proxy instead of going direct. This silently drains the prepaid proxy balance."
    llm_proxy_remediation='Remove proxy env vars from the gateway service environment. Edit /opt/openclaw.env and remove HTTP_PROXY/HTTPS_PROXY lines, then restart: sudo systemctl restart openclaw'
  else
    llm_proxy_details="Checked PID ${gw_pid} procfs environ and /opt/openclaw.env. No proxy env vars found. LLM traffic to api.openai.com, api.anthropic.com, generativelanguage.googleapis.com, api.groq.com, api.mistral.ai routes direct."
  fi
fi

add_check "$(make_check_json 'gateway' 'LLM Proxy Bypass' "$llm_proxy_status" "$llm_proxy_message" "$llm_proxy_details" "$llm_proxy_remediation")"
update_overall "$llm_proxy_status"
```

### Summary of insertion point

```
Line 1159: add_check "$(make_check_json 'os-hardening' 'Facts DB Permissions' ...)"
Line 1160: update_overall "$perm_facts_status"
Line 1161: (blank)
           <<<< INSERT CHECK 23 HERE >>>>
Line 1164: final_json=$(node -e "
```

## Verification

After inserting the check, run:

```bash
# Run the security health check
sudo -u openclaw /usr/local/bin/check-security-health.sh

# Check the LLM Proxy Bypass result
jq '.checks[] | select(.name == "LLM Proxy Bypass") | {name, status, message, details}' /tmp/security-health-results.json
```

### Expected output when PASSING (green)

```json
{
  "name": "LLM Proxy Bypass",
  "status": "green",
  "message": "Gateway process has no proxy env vars. LLM API calls route direct.",
  "details": "Checked PID 12345 procfs environ and /opt/openclaw.env. No proxy env vars found. LLM traffic to api.openai.com, api.anthropic.com, generativelanguage.googleapis.com, api.groq.com, api.mistral.ai routes direct."
}
```

### Expected output when FAILING (red)

```json
{
  "name": "LLM Proxy Bypass",
  "status": "red",
  "message": "Proxy env var(s) found in gateway process: HTTPS_PROXY=http://gw.dataimpulse.com:823",
  "details": "LLM API calls to api.openai.com, api.anthropic.com, generativelanguage.googleapis.com, api.groq.com, api.mistral.ai may be routing through the DataImpulse residential proxy instead of going direct. This silently drains the prepaid proxy balance."
}
```

### Expected output when gateway is NOT RUNNING (yellow)

```json
{
  "name": "LLM Proxy Bypass",
  "status": "yellow",
  "message": "Gateway not running — cannot verify proxy bypass."
}
```

## Quick test (without modifying the script)

To verify the detection logic works before patching, run this standalone:

```bash
gw_pid=$(systemctl show openclaw --property=MainPID --value 2>/dev/null)
echo "Gateway PID: $gw_pid"
if [ -n "$gw_pid" ] && [ "$gw_pid" != "0" ] && [ -r "/proc/${gw_pid}/environ" ]; then
  echo "Proxy vars in gateway process:"
  tr '\0' '\n' < "/proc/${gw_pid}/environ" | grep -iE '^(http_proxy|https_proxy|all_proxy)=' || echo "  (none)"
else
  echo "Gateway not running or environ not readable"
fi
echo "Proxy vars in /opt/openclaw.env:"
grep -iE '^(http_proxy|https_proxy|all_proxy)=' /opt/openclaw.env 2>/dev/null || echo "  (none)"
```

## Follow-up note

The Security dashboard (security.html) currently has a client-side placeholder for
"LLM Proxy Bypass" that reads from the proxy sentinel API (`/api/proxy/sentinel`).
The new server-side check uses layer `gateway` (not `network_brute_force`), so both
will appear in the dashboard. In a follow-up PR, update `security.html` to remove
the sentinel-based placeholder and use the server-side check instead.
