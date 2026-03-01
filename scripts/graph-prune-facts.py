#!/usr/bin/env python3
"""
graph-prune-facts.py - Prune expired and low-confidence facts.

Run hourly via cron. Performs three operations:
  1. Delete expired facts (expires_at < now)
  2. Halve confidence for facts past 50% of their TTL window
  3. Delete facts with confidence < 0.1

Manual-seed facts are never deleted regardless of decay rules.

Usage:
    python3 graph-prune-facts.py           # Execute pruning
    python3 graph-prune-facts.py --dry-run # Report only, no changes
"""

import os
import sys
import sqlite3
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------
WORKSPACE = os.environ.get("OPENCLAW_WORKSPACE", os.path.expanduser("~/.openclaw"))
FACTS_DB = os.environ.get("FACTS_DB", os.path.join(WORKSPACE, "memory", "facts.db"))


def main():
    dry_run = "--dry-run" in sys.argv

    if not os.path.exists(FACTS_DB):
        print(f"ERROR: facts.db not found at {FACTS_DB}")
        sys.exit(1)

    conn = sqlite3.connect(FACTS_DB)
    cursor = conn.cursor()
    now_sec = int(time.time())
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ----- Check that decay columns exist -----
    cursor.execute("PRAGMA table_info(facts)")
    columns = {row[1] for row in cursor.fetchall()}
    if "decay_class" not in columns:
        print(f"[{ts}] ERROR: decay columns not found. Run graph-migrate-decay.py first.")
        conn.close()
        sys.exit(1)

    # ----- Step 1: Count/delete expired facts -----
    # Exclude manual-seed facts from deletion
    cursor.execute(
        "SELECT count(*) FROM facts "
        "WHERE expires_at IS NOT NULL AND expires_at < ? "
        "AND (source IS NULL OR source != 'manual-seed')",
        (now_sec,),
    )
    expired_count = cursor.fetchone()[0]

    if not dry_run and expired_count > 0:
        cursor.execute(
            "DELETE FROM facts "
            "WHERE expires_at IS NOT NULL AND expires_at < ? "
            "AND (source IS NULL OR source != 'manual-seed')",
            (now_sec,),
        )

    # ----- Step 2: Apply confidence decay -----
    # Halve confidence for facts past 50% of their TTL window
    # Formula: (now - last_confirmed_at) > (expires_at - last_confirmed_at) * 0.5
    # Only for facts that still have confidence > 0.1 and haven't expired yet
    # Exclude manual-seed from confidence decay
    cursor.execute(
        "SELECT count(*) FROM facts "
        "WHERE expires_at IS NOT NULL "
        "AND expires_at > ? "
        "AND last_confirmed_at IS NOT NULL "
        "AND (? - last_confirmed_at) > (expires_at - last_confirmed_at) * 0.5 "
        "AND confidence > 0.1 "
        "AND (source IS NULL OR source != 'manual-seed')",
        (now_sec, now_sec),
    )
    decay_count = cursor.fetchone()[0]

    if not dry_run and decay_count > 0:
        cursor.execute(
            "UPDATE facts SET confidence = confidence * 0.5 "
            "WHERE expires_at IS NOT NULL "
            "AND expires_at > ? "
            "AND last_confirmed_at IS NOT NULL "
            "AND (? - last_confirmed_at) > (expires_at - last_confirmed_at) * 0.5 "
            "AND confidence > 0.1 "
            "AND (source IS NULL OR source != 'manual-seed')",
            (now_sec, now_sec),
        )

    # ----- Step 3: Count/delete sub-threshold facts -----
    # Delete facts where confidence dropped below 0.1
    # Exclude manual-seed from deletion
    cursor.execute(
        "SELECT count(*) FROM facts "
        "WHERE confidence < 0.1 "
        "AND (source IS NULL OR source != 'manual-seed')",
    )
    subthreshold_count = cursor.fetchone()[0]

    if not dry_run and subthreshold_count > 0:
        cursor.execute(
            "DELETE FROM facts "
            "WHERE confidence < 0.1 "
            "AND (source IS NULL OR source != 'manual-seed')",
        )

    if not dry_run:
        conn.commit()

    # ----- Summary -----
    mode = "DRY RUN" if dry_run else "PRUNED"
    total_deleted = expired_count + subthreshold_count
    print(
        f"[{ts}] {mode}: "
        f"expired_deleted={expired_count}, "
        f"confidence_decayed={decay_count}, "
        f"subthreshold_deleted={subthreshold_count}, "
        f"total_removed={total_deleted}"
    )

    conn.close()


if __name__ == "__main__":
    main()
