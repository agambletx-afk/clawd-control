#!/usr/bin/env bash
set -euo pipefail
HEARTBEAT_ID="bootstrap-audit"
source /usr/local/bin/heartbeat-lib.sh

/usr/local/bin/bootstrap-audit.py >> /home/openclaw/.openclaw/workspace/bootstrap-audit.log 2>&1

heartbeat_finish
