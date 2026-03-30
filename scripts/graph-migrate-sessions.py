#!/usr/bin/env python3
"""
graph-migrate-sessions.py - One-time schema migration for agent/session scoping.

Adds agent_id and session_id columns to facts table and associated indexes.
Idempotent: safe to run multiple times.

Usage:
    python3 graph-migrate-sessions.py
"""

import os
import sys
import sqlite3

WORKSPACE = os.environ.get("OPENCLAW_WORKSPACE", os.path.expanduser("~/.openclaw"))
FACTS_DB = os.environ.get("FACTS_DB", os.path.join(WORKSPACE, "memory", "facts.db"))


def main():
    if not os.path.exists(FACTS_DB):
        print(f"ERROR: facts.db not found at {FACTS_DB}")
        sys.exit(1)

    conn = sqlite3.connect(FACTS_DB)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("PRAGMA table_info(facts)")
    columns = {row["name"] for row in cur.fetchall()}

    changed = False
    if "agent_id" not in columns:
        cur.execute("ALTER TABLE facts ADD COLUMN agent_id TEXT DEFAULT NULL")
        changed = True

    if "session_id" not in columns:
        cur.execute("ALTER TABLE facts ADD COLUMN session_id TEXT DEFAULT NULL")
        changed = True

    cur.execute("CREATE INDEX IF NOT EXISTS idx_facts_agent ON facts(agent_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_facts_session ON facts(session_id)")

    conn.commit()
    conn.close()

    if changed:
        print("Migration complete: added missing session-scope columns/indexes.")
    else:
        print("Already migrated: agent_id/session_id columns exist. Indexes ensured.")


if __name__ == "__main__":
    main()
