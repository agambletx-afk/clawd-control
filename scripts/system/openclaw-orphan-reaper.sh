#!/usr/bin/env bash
# openclaw-orphan-reaper.sh — Kill orphaned openclaw processes
#
# Detects: openclaw-doctor processes older than 2 minutes (known hang bug #18502)
#          openclaw processes in stopped (T) state
#          Stale run-security-test.sh or check-security-health.sh processes
# Cron: */5 * * * * root /usr/local/bin/openclaw-orphan-reaper.sh
set +e

LOG_FILE="/var/log/openclaw-liveness.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
TELEGRAM_SCRIPT="/usr/local/bin/send-to-telegram.sh"
MAX_AGE_SEC=120  # 2 minutes

killed=0

log() {
  echo "[$TIMESTAMP] [reaper] $1" >> "$LOG_FILE" 2>/dev/null
}

kill_old_process() {
  local pattern="$1"
  local label="$2"
  pgrep -f "$pattern" 2>/dev/null | while read pid; do
    age=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
    if [ -n "$age" ] && [ "$age" -gt "$MAX_AGE_SEC" ]; then
      rss_kb=$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ')
      rss_mb=$(( ${rss_kb:-0} / 1024 ))
      kill -9 "$pid" 2>/dev/null
      if [ $? -eq 0 ]; then
        killed=$((killed + 1))
        log "Killed $label (PID $pid, age ${age}s, RSS ${rss_mb}MB)"
      fi
    fi
  done
}

# Kill orphaned openclaw-doctor processes (358MB each, known bug #18502)
kill_old_process 'openclaw-doctor' 'openclaw-doctor'


# Kill stale health check and security test scripts (>5 min)
for pattern in 'check-security-health\.sh' 'run-security-test\.sh'; do
  pgrep -f "$pattern" 2>/dev/null | while read pid; do
    age=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
    if [ -n "$age" ] && [ "$age" -gt 300 ]; then
      kill -9 "$pid" 2>/dev/null
      if [ $? -eq 0 ]; then
        killed=$((killed + 1))
        log "Killed stale script (PID $pid, pattern $pattern, age ${age}s)"
      fi
    fi
  done
done

# Clean up stale lockfiles
for lockfile in /tmp/security-test.lock; do
  if [ -f "$lockfile" ]; then
    lock_age=$(( $(date +%s) - $(stat -c %Y "$lockfile" 2>/dev/null || echo 0) ))
    if [ "$lock_age" -gt 300 ]; then
      rm -f "$lockfile"
      log "Removed stale lockfile: $lockfile (age ${lock_age}s)"
    fi
  fi
done

# Alert if we killed anything
if [ "$killed" -gt 0 ]; then
  if [ -x "$TELEGRAM_SCRIPT" ]; then
    "$TELEGRAM_SCRIPT" "🧹 Orphan reaper: killed $killed stale process(es). Check /var/log/openclaw-liveness.log for details." 2>/dev/null || true
  fi
fi
