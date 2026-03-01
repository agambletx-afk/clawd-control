#!/usr/bin/env python3
"""
graph-migrate-decay.py - One-time schema migration for decay classification.

Adds decay_class, expires_at, last_confirmed_at, confidence columns to facts table.
Backfills decay_class based on content classification rules.
Idempotent: safe to run multiple times.

Usage:
    python3 graph-migrate-decay.py
"""

import os
import sys
import sqlite3
import time
import re

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------
WORKSPACE = os.environ.get("OPENCLAW_WORKSPACE", os.path.expanduser("~/.openclaw"))
FACTS_DB = os.environ.get("FACTS_DB", os.path.join(WORKSPACE, "memory", "facts.db"))

# ---------------------------------------------------------------------------
# TTL values (seconds)
# ---------------------------------------------------------------------------
TTL = {
    "permanent":  None,
    "stable":     90 * 24 * 3600,   # 7,776,000
    "active":     14 * 24 * 3600,   # 1,209,600
    "session":    24 * 3600,        # 86,400
    "checkpoint": 4  * 3600,        # 14,400
}

# Core system entities that are always permanent
CORE_ENTITIES = {"adam", "jarvis", "computacenter", "digitalocean", "telegram"}

# Keys that signal permanent facts
PERMANENT_KEYS = {"role", "employer", "location", "full_name"}

# Keys that signal stable facts
STABLE_KEYS = {"phone", "email", "address", "birthday", "url"}

# Patterns that signal active facts (in key or value)
ACTIVE_PATTERNS = re.compile(
    r"\b(working on|sprint|blocker|todo|wip|branch)\b", re.IGNORECASE
)


def classify_fact(row):
    """Classify a fact row into a decay class.

    Args:
        row: dict with entity, key, value, category, source

    Returns:
        str: one of permanent, stable, active, session, checkpoint
    """
    entity   = (row.get("entity") or "").strip()
    key      = (row.get("key") or "").strip()
    value    = (row.get("value") or "").strip()
    category = (row.get("category") or "").strip().lower()
    source   = (row.get("source") or "").strip().lower()

    key_lower    = key.lower()
    entity_lower = entity.lower()

    # --- Manual seeds: always permanent or stable, never session/checkpoint ---
    if source == "manual-seed":
        if category == "identity" or entity_lower in CORE_ENTITIES:
            return "permanent"
        if key_lower in PERMANENT_KEYS:
            return "permanent"
        return "stable"

    # --- Checkpoint ---
    if category == "checkpoint" or "preflight" in key_lower:
        return "checkpoint"

    # --- Permanent ---
    if category == "identity":
        return "permanent"
    if key_lower in PERMANENT_KEYS:
        return "permanent"
    if entity_lower in CORE_ENTITIES:
        return "permanent"

    # --- Session ---
    if source == "conversation" and not entity and not key:
        return "session"

    # --- Active ---
    if "daily-ingest" in source:
        return "active"
    if ACTIVE_PATTERNS.search(key) or ACTIVE_PATTERNS.search(value):
        return "active"

    # --- Stable ---
    if category in ("preference", "relationship"):
        return "stable"
    if key_lower in STABLE_KEYS:
        return "stable"

    # --- Default ---
    return "stable"


def calculate_expiry(decay_class, from_ts):
    """Calculate expires_at timestamp for a given class.

    Returns None for permanent facts.
    """
    ttl = TTL.get(decay_class)
    if ttl is None:
        return None
    return from_ts + ttl


def main():
    if not os.path.exists(FACTS_DB):
        print(f"ERROR: facts.db not found at {FACTS_DB}")
        sys.exit(1)

    conn = sqlite3.connect(FACTS_DB)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # ----- Idempotency check -----
    cursor.execute("PRAGMA table_info(facts)")
    columns = {row["name"] for row in cursor.fetchall()}

    if "decay_class" in columns:
        print("Already migrated: decay_class column exists. Nothing to do.")
        conn.close()
        sys.exit(0)

    print(f"Migrating {FACTS_DB} ...")
    start = time.time()

    # ----- Add columns (ALTER TABLE only, no DROP/RECREATE) -----
    cursor.execute(
        "ALTER TABLE facts ADD COLUMN decay_class TEXT NOT NULL DEFAULT 'stable'"
    )
    cursor.execute("ALTER TABLE facts ADD COLUMN expires_at INTEGER")
    cursor.execute("ALTER TABLE facts ADD COLUMN last_confirmed_at INTEGER")
    cursor.execute(
        "ALTER TABLE facts ADD COLUMN confidence REAL NOT NULL DEFAULT 1.0"
    )

    # ----- Create indexes -----
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_facts_expires "
        "ON facts(expires_at) WHERE expires_at IS NOT NULL"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_facts_decay ON facts(decay_class)"
    )

    # ----- Backfill last_confirmed_at from created_at -----
    # created_at may be stored as milliseconds (Date.now() from Node.js) or
    # as Unix seconds. Values > 10 billion are milliseconds and need division.
    cursor.execute("""
        UPDATE facts SET last_confirmed_at = CASE
            WHEN created_at > 10000000000 THEN CAST(created_at / 1000 AS INTEGER)
            ELSE CAST(created_at AS INTEGER)
        END
        WHERE last_confirmed_at IS NULL
    """)

    # ----- Backfill decay_class for existing facts -----
    cursor.execute(
        "SELECT rowid AS rowid, entity, key, value, category, source FROM facts"
    )
    rows = cursor.fetchall()

    now_sec = int(time.time())
    counts = {}

    for row in rows:
        dc = classify_fact(dict(row))
        exp = calculate_expiry(dc, now_sec)
        cursor.execute(
            "UPDATE facts SET decay_class = ?, expires_at = ? WHERE rowid = ?",
            (dc, exp, row["rowid"]),
        )
        counts[dc] = counts.get(dc, 0) + 1

    conn.commit()

    elapsed = time.time() - start

    # ----- Summary -----
    print(f"Migration complete in {elapsed:.2f}s")
    print(f"Classified {len(rows)} facts:")
    for dc in ("permanent", "stable", "active", "session", "checkpoint"):
        print(f"  {dc}: {counts.get(dc, 0)}")

    # ----- Verify FTS5 triggers still exist -----
    cursor.execute(
        "SELECT count(*) FROM sqlite_master "
        "WHERE type='trigger' AND tbl_name='facts'"
    )
    trigger_count = cursor.fetchone()[0]
    if trigger_count > 0:
        print(f"FTS5 triggers intact: {trigger_count} trigger(s) found")
    else:
        print("WARNING: No FTS5 triggers found on facts table. Check FTS integrity.")

    conn.close()


if __name__ == "__main__":
    main()
