#!/usr/bin/env bash
set -euo pipefail
HEARTBEAT_ID="security-health"
source /usr/local/bin/heartbeat-lib.sh

timeout 45 /usr/local/bin/check-security-health.sh

heartbeat_finish
