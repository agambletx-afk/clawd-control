#!/usr/bin/env python3
"""graph-mem-cli.py - Memory graph maintenance toolkit."""

import argparse
import csv
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime

DEFAULT_WORKSPACE = os.path.expanduser("~/.openclaw")
DEFAULT_DB = "/home/openclaw/.openclaw/memory/facts.db"
CHECKPOINT_KEEP = 10
EXPORT_COLUMNS = [
    "id",
    "entity",
    "key",
    "value",
    "category",
    "source",
    "created_at",
    "last_accessed",
    "access_count",
    "permanent",
    "decay_score",
    "activation",
    "importance",
    "decay_class",
    "expires_at",
    "last_confirmed_at",
    "confidence",
]

PERMANENT_KEYS = {
    "name",
    "email",
    "api_key",
    "api_endpoint",
    "architecture",
    "decision",
    "birthday",
    "born",
    "phone",
    "language",
    "location",
}
PERMANENT_PATTERNS = ["decided", "architecture", "always use", "never use"]
PERMANENT_ENTITIES = {"decision", "convention"}
SESSION_KEYS = {"current_file", "temp", "debug", "working_on_right_now"}
SESSION_PATTERNS = ["currently debugging", "right now", "this session"]
ACTIVE_KEYS = {
    "task",
    "todo",
    "wip",
    "branch",
    "sprint",
    "blocker",
    "working on",
    "milestone",
    "deadline",
    "project status",
}
ACTIVE_PATTERNS = ["working on", "in progress", "blocked by", "planning to"]
CHECKPOINT_KEYS = {"error", "traceback", "stack_trace", "log_entry", "last_error"}
TTL_SECONDS = {
    "permanent": None,
    "stable": 7776000,
    "active": 1209600,
    "session": 21600,
    "checkpoint": 3600,
}


def resolve_db_path(cli_db_path=None):
    if cli_db_path:
        return cli_db_path
    if os.environ.get("FACTS_DB"):
        return os.environ["FACTS_DB"]
    workspace = os.environ.get("OPENCLAW_WORKSPACE", DEFAULT_WORKSPACE)
    if workspace:
        return os.path.join(workspace, "memory", "facts.db")
    return DEFAULT_DB


def connect_db(db_path):
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"facts.db not found at {db_path}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def human_size(num_bytes):
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.2f} KB"
    return f"{num_bytes / (1024 * 1024):.2f} MB"


def table_exists(conn, table_name):
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table_name,)
    ).fetchone()
    return row is not None


def cmd_stats(args):
    db_path = resolve_db_path(args.db_path)
    with connect_db(db_path) as conn:
        total_facts = conn.execute("SELECT COUNT(*) FROM facts").fetchone()[0]
        by_category = conn.execute(
            "SELECT COALESCE(category, '(null)') AS label, COUNT(*) AS c "
            "FROM facts GROUP BY COALESCE(category, '(null)') ORDER BY c DESC, label"
        ).fetchall()
        by_source = conn.execute(
            "SELECT COALESCE(source, '(null)') AS label, COUNT(*) AS c "
            "FROM facts GROUP BY COALESCE(source, '(null)') ORDER BY c DESC, label"
        ).fetchall()
        by_decay = conn.execute(
            "SELECT COALESCE(decay_class, '(null)') AS label, COUNT(*) AS c "
            "FROM facts GROUP BY COALESCE(decay_class, '(null)') ORDER BY c DESC, label"
        ).fetchall()
        oldest, newest = conn.execute(
            "SELECT MIN(created_at), MAX(created_at) FROM facts"
        ).fetchone()

        relations = conn.execute("SELECT COUNT(*) FROM relations").fetchone()[0] if table_exists(conn, "relations") else 0
        aliases = conn.execute("SELECT COUNT(*) FROM aliases").fetchone()[0] if table_exists(conn, "aliases") else 0
        co_occ = conn.execute("SELECT COUNT(*) FROM co_occurrences").fetchone()[0] if table_exists(conn, "co_occurrences") else 0

    print(f"Database: {db_path}")
    print(f"Total facts: {total_facts}")
    print("By category:")
    for row in by_category:
        print(f"  {row['label']}: {row['c']}")
    print("By source:")
    for row in by_source:
        print(f"  {row['label']}: {row['c']}")
    print("By decay_class:")
    for row in by_decay:
        print(f"  {row['label']}: {row['c']}")
    print(f"Relations: {relations}")
    print(f"Aliases: {aliases}")
    print(f"Co-occurrences: {co_occ}")
    print(f"Database size: {human_size(os.path.getsize(db_path))}")
    print(f"Oldest created_at: {oldest}")
    print(f"Newest created_at: {newest}")
    return 0


def cmd_search(args):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    search_script = os.path.join(script_dir, "graph-search.py")
    if not os.path.exists(search_script):
        print(f"ERROR: graph-search.py not found at {search_script}", file=sys.stderr)
        return 1

    cmd = [sys.executable, search_script, args.query, "--top-k", str(args.limit)]
    if args.json:
        cmd.append("--json")
    if args.db_path:
        cmd.extend(["--db-path", args.db_path])

    result = subprocess.run(cmd)
    return result.returncode


def checkpoint_dir_for_db(db_path):
    return os.path.join(os.path.dirname(os.path.abspath(db_path)), "checkpoints")


def parse_checkpoint_timestamp(filename):
    try:
        stem = filename.replace("facts-", "").replace(".db", "")
        return datetime.strptime(stem, "%Y%m%d-%H%M%S")
    except ValueError:
        return None


def list_checkpoints(cp_dir):
    if not os.path.isdir(cp_dir):
        return []
    files = [f for f in os.listdir(cp_dir) if f.startswith("facts-") and f.endswith(".db")]
    files.sort(reverse=True)
    return files


def cmd_checkpoint_save(args):
    db_path = resolve_db_path(args.db_path)
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"facts.db not found at {db_path}")
    cp_dir = checkpoint_dir_for_db(db_path)
    os.makedirs(cp_dir, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(cp_dir, f"facts-{ts}.db")
    shutil.copy2(db_path, dest)

    checkpoints = list_checkpoints(cp_dir)
    while len(checkpoints) > CHECKPOINT_KEEP:
        oldest = checkpoints.pop()
        os.remove(os.path.join(cp_dir, oldest))

    print(f"Saved checkpoint: {dest}")
    print(f"Size: {human_size(os.path.getsize(dest))}")
    return 0


def cmd_checkpoint_list(args):
    db_path = resolve_db_path(args.db_path)
    cp_dir = checkpoint_dir_for_db(db_path)
    checkpoints = list_checkpoints(cp_dir)

    if not checkpoints:
        print("No checkpoints found.")
        return 0

    for name in checkpoints:
        full = os.path.join(cp_dir, name)
        dt = parse_checkpoint_timestamp(name)
        date_str = dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "unknown"
        print(f"{name}\t{date_str}\t{human_size(os.path.getsize(full))}")
    return 0


def cmd_checkpoint_restore(args):
    db_path = resolve_db_path(args.db_path)
    cp_dir = checkpoint_dir_for_db(db_path)

    if os.path.sep in args.filename or (os.path.altsep and os.path.altsep in args.filename):
        print("ERROR: provide checkpoint filename only, not a path", file=sys.stderr)
        return 1

    cp_path = os.path.join(cp_dir, args.filename)
    if not os.path.exists(cp_path):
        print(f"ERROR: checkpoint not found: {cp_path}", file=sys.stderr)
        return 1

    if not args.confirm:
        print("WARNING: restore requires --confirm; no changes made")
        return 0

    before_count = 0
    if os.path.exists(db_path):
        with connect_db(db_path) as conn:
            before_count = conn.execute("SELECT COUNT(*) FROM facts").fetchone()[0]

    print("Restoring checkpoint. OpenClaw service will be restarted after copy.")
    shutil.copy2(cp_path, db_path)

    with connect_db(db_path) as conn:
        after_count = conn.execute("SELECT COUNT(*) FROM facts").fetchone()[0]

    restart = subprocess.run(["sudo", "/usr/bin/systemctl", "restart", "openclaw"])
    if restart.returncode != 0:
        print("ERROR: failed to restart openclaw", file=sys.stderr)
        return restart.returncode

    print(f"Fact count before restore: {before_count}")
    print(f"Fact count after restore: {after_count}")
    return 0


def classify_fact(row):
    entity = (row["entity"] or "").strip().lower()
    key = (row["key"] or "").strip().lower()
    value = (row["value"] or "").strip().lower()
    text = f"{key} {value}"

    if key in CHECKPOINT_KEYS:
        return "checkpoint"
    if key in SESSION_KEYS or any(p in text for p in SESSION_PATTERNS):
        return "session"
    if key in PERMANENT_KEYS or entity in PERMANENT_ENTITIES or any(p in text for p in PERMANENT_PATTERNS):
        return "permanent"
    if key in ACTIVE_KEYS or any(p in text for p in ACTIVE_PATTERNS):
        return "active"
    return "stable"


def cmd_backfill_decay(args):
    db_path = resolve_db_path(args.db_path)
    now_sec = int(time.time())

    with connect_db(db_path) as conn:
        rows = conn.execute(
            "SELECT rowid AS rid, entity, key, value, source, decay_class FROM facts"
        ).fetchall()

        updates = []
        counts = {}
        for row in rows:
            source = (row["source"] or "").strip().lower()
            current_class = (row["decay_class"] or "").strip().lower()
            if source == "manual-seed" and current_class == "permanent":
                continue

            new_class = classify_fact(row)
            if new_class == current_class:
                continue

            expires_at = None if TTL_SECONDS[new_class] is None else now_sec + TTL_SECONDS[new_class]
            updates.append((new_class, expires_at, now_sec, row["rid"]))
            counts[new_class] = counts.get(new_class, 0) + 1

        if args.dry_run:
            print(f"Dry run: would reclassify {len(updates)} facts")
            for dc in ("permanent", "stable", "active", "session", "checkpoint"):
                print(f"  {dc}: {counts.get(dc, 0)}")
            return 0

        with conn:
            conn.executemany(
                "UPDATE facts SET decay_class=?, expires_at=?, last_confirmed_at=? WHERE rowid=?",
                updates,
            )

    print(f"Reclassified {len(updates)} facts")
    for dc in ("permanent", "stable", "active", "session", "checkpoint"):
        print(f"  {dc}: {counts.get(dc, 0)}")
    return 0


def cmd_dedupe(args):
    db_path = resolve_db_path(args.db_path)

    with connect_db(db_path) as conn:
        groups = conn.execute(
            "SELECT LOWER(COALESCE(entity,'')) AS e, LOWER(COALESCE(key,'')) AS k, "
            "LOWER(COALESCE(value,'')) AS v, COUNT(*) AS c "
            "FROM facts GROUP BY e, k, v HAVING COUNT(*) > 1"
        ).fetchall()

        to_delete = []
        for group in groups:
            dupes = conn.execute(
                "SELECT rowid AS rid FROM facts WHERE LOWER(COALESCE(entity,''))=? "
                "AND LOWER(COALESCE(key,''))=? AND LOWER(COALESCE(value,''))=? "
                "ORDER BY rowid ASC",
                (group["e"], group["k"], group["v"]),
            ).fetchall()
            to_delete.extend([r["rid"] for r in dupes[1:]])

        print(f"Duplicates found: {len(to_delete)}")
        if args.dry_run:
            print("Dry run: no changes made")
            return 0

        if to_delete:
            with conn:
                conn.executemany("DELETE FROM facts WHERE rowid=?", [(rid,) for rid in to_delete])
        print(f"Duplicates removed: {len(to_delete)}")
    return 0


def cmd_export(args):
    db_path = resolve_db_path(args.db_path)

    with connect_db(db_path) as conn:
        sql = "SELECT " + ", ".join(EXPORT_COLUMNS) + " FROM facts ORDER BY id ASC"
        rows = [dict(r) for r in conn.execute(sql).fetchall()]

    if args.format == "json":
        json.dump(rows, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=EXPORT_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description="Memory graph CLI toolkit")
    parser.add_argument("--db-path", help="Path to facts.db")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("stats", help="Show database statistics").set_defaults(func=cmd_stats)

    p_search = subparsers.add_parser("search", help="Delegate search to graph-search.py")
    p_search.add_argument("query")
    p_search.add_argument("--json", action="store_true")
    p_search.add_argument("--limit", type=int, default=10)
    p_search.set_defaults(func=cmd_search)

    p_checkpoint = subparsers.add_parser("checkpoint", help="Checkpoint operations")
    cp_sub = p_checkpoint.add_subparsers(dest="checkpoint_command", required=True)

    cp_sub.add_parser("save", help="Save a checkpoint").set_defaults(func=cmd_checkpoint_save)
    cp_sub.add_parser("list", help="List checkpoints").set_defaults(func=cmd_checkpoint_list)
    cp_restore = cp_sub.add_parser("restore", help="Restore checkpoint")
    cp_restore.add_argument("filename")
    cp_restore.add_argument("--confirm", action="store_true")
    cp_restore.set_defaults(func=cmd_checkpoint_restore)

    p_backfill = subparsers.add_parser("backfill-decay", help="Backfill decay classes")
    p_backfill.add_argument("--dry-run", action="store_true")
    p_backfill.set_defaults(func=cmd_backfill_decay)

    p_dedupe = subparsers.add_parser("dedupe", help="Remove duplicate facts")
    p_dedupe.add_argument("--dry-run", action="store_true")
    p_dedupe.set_defaults(func=cmd_dedupe)

    p_export = subparsers.add_parser("export", help="Export all facts")
    p_export.add_argument("--format", choices=["json", "csv"], default="json")
    p_export.set_defaults(func=cmd_export)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except FileNotFoundError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 1
    except sqlite3.Error as err:
        print(f"ERROR: sqlite failure: {err}", file=sys.stderr)
        return 1
    except Exception as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
