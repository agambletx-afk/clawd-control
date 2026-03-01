#!/usr/bin/env python3
"""Extract facts from daily markdown logs into the graph facts database."""

import argparse
import os
import re
import sqlite3
import sys
import time
import uuid
from datetime import date, timedelta

WORKSPACE = os.environ.get("OPENCLAW_WORKSPACE", os.path.expanduser("~/.openclaw"))
FACTS_DB = os.environ.get("FACTS_DB", os.path.join(WORKSPACE, "memory", "facts.db"))
MEMORY_DIR = os.path.join(WORKSPACE, "memory")

SENSITIVE_RE = re.compile(
    r"password|passwd|api.?key|secret|token|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|\\b\\d{3}-\\d{2}-\\d{4}\\b|\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b",
    re.IGNORECASE,
)
EMOJI_RE = re.compile(
    "["
    "\\U0001F300-\\U0001F5FF"
    "\\U0001F600-\\U0001F64F"
    "\\U0001F680-\\U0001F6FF"
    "\\U0001F700-\\U0001F77F"
    "\\U0001F900-\\U0001F9FF"
    "\\U0001FA70-\\U0001FAFF"
    "]"
)
INSERT_SQL = """
INSERT INTO facts (
    id, text, category, importance, entity, key, value,
    source, created_at, decay_class, expires_at, last_confirmed_at, confidence
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""".strip()


def parse_args():
    parser = argparse.ArgumentParser(description="Ingest facts from daily markdown logs.")
    parser.add_argument("--days", type=int, default=1, help="How many days back to scan (default: 1)")
    parser.add_argument("--dry-run", action="store_true", help="Preview facts without writing")
    return parser.parse_args()


def normalize_line(raw_line):
    stripped = raw_line.strip()
    if not stripped:
        return None
    if stripped.startswith("#"):
        return None
    normalized = re.sub(r"^\s*[-*>]\s*", "", raw_line).strip()
    return normalized or None


def is_noisy_line(line):
    emoji_count = len(EMOJI_RE.findall(line))
    if emoji_count > 3:
        return True

    if re.fullmatch(r"[\W_]+", line):
        return True

    without_tags = re.sub(r"<[^>]+>", "", line).strip()
    if without_tags and len(without_tags) < len(line) * 0.3:
        return True

    non_alnum = sum(1 for c in line if not c.isalnum() and not c.isspace())
    if line and non_alnum / len(line) > 0.75:
        return True

    return False


def detect_category(line):
    lower = line.lower()
    if any(term in lower for term in ("decided", "chose", "picked", "decision")):
        return "decision"
    if any(term in lower for term in ("prefer", "preference", "like to", "use ")) and " over " in lower:
        return "preference"
    if any(term in lower for term in ("server", "system", "deploy", "database", "config", "cron", "plugin", "api", "endpoint")):
        return "system"
    if any(term in lower for term in ("team", "with ", "met ", "relationship", "partner", "manager", "collabor")):
        return "relationship"
    if any(term in lower for term in ("task", "project", "work", "ticket", "deadline", "deliver")):
        return "work"
    if any(term in lower for term in ("i am", "i'm", "my name", "adam", "we are", "identity")):
        return "identity"
    return "work"


def extract_structured(line):
    s = line.strip()

    poss_match = re.match(r"^([A-Za-z][A-Za-z0-9_\-\s]{0,80})'s\s+([A-Za-z][A-Za-z0-9_\-\s]{0,80})\s+is\s+(.+)$", s)
    if poss_match:
        entity = poss_match.group(1).strip()
        key = poss_match.group(2).strip().lower().replace(" ", "_")
        return entity, key, poss_match.group(3).strip()

    decision_match = re.search(r"\b(?:decided|chose|picked)\s+(.+?)\s+because\s+(.+)$", s, re.IGNORECASE)
    if decision_match:
        return "decision", decision_match.group(1).strip(), decision_match.group(2).strip()

    pref_match = re.search(r"\b(?:prefer|use)\s+(.+?)\s+over\s+(.+)$", s, re.IGNORECASE)
    if pref_match:
        return "user", "preference", f"{pref_match.group(1).strip()} over {pref_match.group(2).strip()}"

    actor_match = re.match(
        r"^(I|We|Adam)\s+(updated|changed|migrated|switched|configured|deployed|fixed|implemented|documented|added|removed)\s+(.+)$",
        s,
        re.IGNORECASE,
    )
    if actor_match:
        verb = actor_match.group(2).lower()
        key_map = {
            "updated": "update",
            "changed": "change",
            "migrated": "migration",
            "switched": "switch",
            "configured": "configuration",
            "deployed": "deployment",
            "fixed": "fix",
            "implemented": "implementation",
            "documented": "documentation",
            "added": "addition",
            "removed": "removal",
        }
        return "Adam", key_map.get(verb, verb), actor_match.group(3).strip()

    return None, None, s


def validate_schema(cursor):
    cursor.execute("PRAGMA table_info(facts)")
    cols = {row[1] for row in cursor.fetchall()}
    required = {
        "id",
        "text",
        "category",
        "importance",
        "entity",
        "key",
        "value",
        "source",
        "created_at",
        "decay_class",
        "expires_at",
        "last_confirmed_at",
        "confidence",
    }
    missing = sorted(required - cols)
    return missing


def iter_dates(days):
    today = date.today()
    for offset in range(max(days, 0)):
        yield today - timedelta(days=offset)


def main():
    args = parse_args()
    if args.days < 1:
        print("ERROR: --days must be >= 1")
        return 1

    if not os.path.exists(FACTS_DB):
        print(f"ERROR: facts.db not found at {FACTS_DB}")
        return 1

    conn = sqlite3.connect(FACTS_DB)
    cur = conn.cursor()

    missing = validate_schema(cur)
    if missing:
        print(f"ERROR: facts table missing required columns: {', '.join(missing)}")
        conn.close()
        return 1

    files_scanned = 0
    candidates = 0
    inserted = 0
    duplicates = 0

    for day in iter_dates(args.days):
        day_str = day.strftime("%Y-%m-%d")
        path = os.path.join(MEMORY_DIR, f"{day_str}.md")
        if not os.path.exists(path):
            continue

        files_scanned += 1
        source = f"daily-ingest:{day_str}"

        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = normalize_line(raw_line)
                if not line:
                    continue
                if len(line) < 15 or len(line) > 500:
                    continue
                if SENSITIVE_RE.search(line):
                    continue
                if is_noisy_line(line):
                    continue

                candidates += 1
                category = detect_category(line)
                entity, key, value = extract_structured(line)

                cur.execute("SELECT 1 FROM facts WHERE text = ? LIMIT 1", (line,))
                if cur.fetchone() is not None:
                    duplicates += 1
                    continue

                created_at = int(time.time())
                expires_at = created_at + 1_209_600
                row = (
                    str(uuid.uuid4()),
                    line,
                    category,
                    0.7,
                    entity,
                    key,
                    value,
                    source,
                    created_at,
                    "active",
                    expires_at,
                    created_at,
                    1.0,
                )

                if args.dry_run:
                    print(
                        f"[DRY-RUN] source={source} category={category} "
                        f"entity={entity!r} key={key!r} value={value!r} text={line!r}"
                    )
                else:
                    cur.execute(INSERT_SQL, row)
                    inserted += 1

    if not args.dry_run:
        conn.commit()

    print(
        "SUMMARY "
        f"files_scanned={files_scanned} "
        f"candidates={candidates} "
        f"new_facts_stored={inserted if not args.dry_run else 0} "
        f"duplicates_skipped={duplicates}"
    )

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
