#!/usr/bin/env bash
set -euo pipefail
HEARTBEAT_ID="memory-ingest"
source /usr/local/bin/heartbeat-lib.sh

. /home/openclaw/.profile && python3 /home/openclaw/.openclaw/scripts/graph-ingest-daily.py --days 1 >> /home/openclaw/.openclaw/memory/ingest.log 2>&1

heartbeat_finish
