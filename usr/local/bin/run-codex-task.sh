#!/bin/bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <task_file> <repo_dir> <branch> [task_log]" >&2
  exit 2
fi

TASK_FILE="$1"
REPO_DIR="$2"
BRANCH="$3"
TASK_LOG="${4:-/tmp/codex-task.log}"

DEADLINE=${CODEX_DEADLINE:-3600}

set +e
/usr/local/bin/run-with-deadline.sh "$DEADLINE" codex --task "$TASK_FILE" --repo "$REPO_DIR" --branch "$BRANCH" >>"$TASK_LOG" 2>&1
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 124 ]]; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) DEADLINE: Codex task exceeded ${DEADLINE}s" >>"$TASK_LOG"
fi

exit $EXIT_CODE
