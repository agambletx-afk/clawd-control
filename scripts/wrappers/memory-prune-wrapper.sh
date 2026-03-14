#!/usr/bin/env bash
set -euo pipefail
HEARTBEAT_ID="memory-prune"
source /usr/local/bin/heartbeat-lib.sh

. /home/openclaw/.profile && python3 /home/openclaw/.openclaw/scripts/graph-prune-facts.py >> /home/openclaw/.openclaw/memory/prune.log 2>&1

heartbeat_finish
