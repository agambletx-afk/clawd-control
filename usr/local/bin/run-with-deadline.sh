#!/bin/bash
# Usage: run-with-deadline.sh <timeout_seconds> <command> [args...]
# Exits with 124 if the deadline is reached (same as GNU timeout)
set -euo pipefail

TIMEOUT=$1
shift

set +e
timeout --signal=TERM --kill-after=10 "$TIMEOUT" "$@"
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -eq 124 ]; then
  echo "DEADLINE: Process killed after ${TIMEOUT}s" >&2
fi

exit $EXIT_CODE
