#!/usr/bin/env bash
set -euo pipefail

archive_script() {
  local src="$1"
  local archived="${src}.archived"

  if [[ -f "$src" ]]; then
    mv "$src" "$archived"
    echo "Archived: $src -> $archived"
  else
    echo "Skip archive (missing): $src"
  fi

  if [[ -f "$archived" ]]; then
    chmod 755 "$archived"
  fi
}

remove_cron_file() {
  local path="$1"
  if [[ -f "$path" ]]; then
    rm -f "$path"
    echo "Removed cron file: $path"
  else
    echo "Skip remove (missing): $path"
  fi
}

archive_script "/usr/local/bin/openclaw-healthcheck.sh"
archive_script "/usr/local/bin/openclaw-api-liveness.sh"

remove_cron_file "/etc/cron.d/openclaw-healthcheck"
remove_cron_file "/etc/cron.d/openclaw-liveness"

if [[ -f "/usr/local/bin/openclaw-watchdog.sh" ]]; then
  chmod 755 "/usr/local/bin/openclaw-watchdog.sh"
  echo "Ensured executable: /usr/local/bin/openclaw-watchdog.sh"
else
  echo "Warning: /usr/local/bin/openclaw-watchdog.sh not found"
fi
