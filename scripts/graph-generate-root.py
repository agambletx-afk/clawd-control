#!/usr/bin/env python3
"""Generate ROOT.md bootstrap index from facts.db."""

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

DEFAULT_WORKSPACE = os.path.expanduser("~/.openclaw")
DEFAULT_DB = "/home/openclaw/.openclaw/memory/facts.db"
MINIMAL_ROOT = "# Session Bootstrap Index\n\nNo facts in database.\n"


def resolve_db_path(cli_db_path=None):
    if cli_db_path:
        return cli_db_path
    env_db = os.environ.get("FACTS_DB")
    if env_db:
        return env_db
    workspace = os.environ.get("OPENCLAW_WORKSPACE")
    if workspace:
        return os.path.join(workspace, "memory", "facts.db")
    return DEFAULT_DB


def parse_args():
    parser = argparse.ArgumentParser(description="Generate ROOT.md session bootstrap index.")
    parser.add_argument("--db-path", help="Override facts.db location")
    parser.add_argument("--output", help="Override ROOT.md output path")
    parser.add_argument("--dry-run", action="store_true", help="Print output only")
    parser.add_argument("--days", type=int, default=7, help="Active topics lookback window (default: 7)")
    return parser.parse_args()


def connect_read_only(db_path):
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def format_date(epoch_sec):
    if not epoch_sec:
        return "unknown"
    return datetime.fromtimestamp(int(epoch_sec), timezone.utc).strftime("%Y-%m-%d")


def format_age(seconds):
    seconds = max(0, int(seconds))
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    if days > 0:
        return f"{days}d {hours}h" if hours else f"{days}d"
    if hours > 0:
        return f"{hours}h {minutes}m" if minutes else f"{hours}h"
    return f"{minutes}m"


def truncate_text(text, max_len=120):
    if text is None:
        return ""
    text = " ".join(str(text).split())
    if len(text) <= max_len:
        return text
    return text[: max_len - 1].rstrip() + "…"


def write_output(content, output_path, dry_run):
    if dry_run:
        sys.stdout.write(content)
        return
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)


def append_log_line(log_path, facts_count, section_count, byte_count):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} - ROOT.md generated: {facts_count} facts, {section_count} sections, {byte_count} bytes\n"
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line)


def query_fact_count(cur):
    row = cur.execute("SELECT COUNT(*) AS c FROM facts").fetchone()
    return int(row["c"]) if row else 0


def facts_table_exists(cur):
    row = cur.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='facts' LIMIT 1"
    ).fetchone()
    return row is not None


def generate_root(cur, now_sec, active_days):
    total_facts = query_fact_count(cur)
    if total_facts == 0:
        return MINIMAL_ROOT, total_facts, 0, 0

    coverage_rows = cur.execute(
        """
        SELECT COALESCE(category, 'uncategorized') AS category, COUNT(*) AS fact_count
        FROM facts
        WHERE expires_at IS NULL OR expires_at > ?
        GROUP BY COALESCE(category, 'uncategorized')
        ORDER BY fact_count DESC, category ASC
        LIMIT 10
        """,
        (now_sec,),
    ).fetchall()
    coverage_total = len(coverage_rows)

    cst_now = datetime.now(timezone.utc) - timedelta(hours=6)
    header = (
        "# Session Bootstrap Index\n"
        f"Generated: {cst_now.strftime('%Y-%m-%d %H:%M')} CST | "
        f"Facts: {total_facts} | Coverage: {coverage_total} categories\n"
    )

    sections = []

    active_cutoff = now_sec - (max(1, active_days) * 86400)
    active_rows = cur.execute(
        """
        SELECT
            COALESCE(NULLIF(entity, ''), 'unknown') AS entity,
            COUNT(*) AS fact_count,
            MAX(CASE
                WHEN COALESCE(last_confirmed_at, 0) > COALESCE(created_at, 0)
                    THEN last_confirmed_at
                ELSE created_at
            END) AS recent_ts
        FROM facts
        WHERE
            (COALESCE(created_at, 0) >= ? OR COALESCE(last_confirmed_at, 0) >= ?)
            AND COALESCE(decay_class, '') != 'checkpoint'
            AND COALESCE(source, '') NOT LIKE 'compaction-capture%'
        GROUP BY COALESCE(NULLIF(entity, ''), 'unknown')
        ORDER BY recent_ts DESC, fact_count DESC, entity ASC
        LIMIT 10
        """,
        (active_cutoff, active_cutoff),
    ).fetchall()
    if active_rows:
        lines = [f"## Active Topics (last {max(1, active_days)} days)"]
        for row in active_rows:
            lines.append(
                f"- **{row['entity']}** ({row['fact_count']} facts, last: {format_date(row['recent_ts'])})"
            )
        sections.append("\n".join(lines))

    checkpoint_cutoff = now_sec - 48 * 3600
    checkpoint_rows = cur.execute(
        """
        SELECT
            SUBSTR(COALESCE(source, ''), 12) AS label,
            COALESCE(NULLIF(entity, ''), 'unknown') AS entity,
            COUNT(*) AS fact_count,
            MAX(CASE
                WHEN COALESCE(last_confirmed_at, 0) > COALESCE(created_at, 0)
                    THEN last_confirmed_at
                ELSE created_at
            END) AS recent_ts
        FROM facts
        WHERE
            COALESCE(source, '') LIKE 'checkpoint:%'
            AND (COALESCE(created_at, 0) >= ? OR COALESCE(last_confirmed_at, 0) >= ?)
        GROUP BY SUBSTR(COALESCE(source, ''), 12), COALESCE(NULLIF(entity, ''), 'unknown')
        ORDER BY recent_ts DESC, fact_count DESC, label ASC, entity ASC
        LIMIT 5
        """,
        (checkpoint_cutoff, checkpoint_cutoff),
    ).fetchall()
    if checkpoint_rows:
        lines = ["## Recent Checkpoints"]
        for row in checkpoint_rows:
            age = format_age(now_sec - int(row["recent_ts"] or now_sec))
            lines.append(
                f"- **{row['label'] or 'unnamed'}** | Entity: {row['entity']} | {row['fact_count']} facts | {age} ago"
            )
        sections.append("\n".join(lines))

    decisions_cutoff = now_sec - 14 * 86400
    decision_rows = cur.execute(
        """
        SELECT
            COALESCE(NULLIF(entity, ''), 'unknown') AS entity,
            value,
            CASE
                WHEN COALESCE(last_confirmed_at, 0) > COALESCE(created_at, 0)
                    THEN last_confirmed_at
                ELSE created_at
            END AS decision_ts
        FROM facts
        WHERE
            COALESCE(category, '') = 'decision'
            AND COALESCE(source, '') NOT LIKE 'checkpoint:%'
            AND (COALESCE(created_at, 0) >= ? OR COALESCE(last_confirmed_at, 0) >= ?)
        ORDER BY decision_ts DESC, entity ASC
        LIMIT 8
        """,
        (decisions_cutoff, decisions_cutoff),
    ).fetchall()
    if decision_rows:
        lines = ["## Recent Decisions (last 14 days)"]
        for row in decision_rows:
            lines.append(
                f"- {format_date(row['decision_ts'])}: {row['entity']} -- {truncate_text(row['value'], 120)}"
            )
        sections.append("\n".join(lines))

    if coverage_total >= 3:
        lines = ["## Knowledge Coverage"]
        for row in coverage_rows:
            lines.append(f"- {row['category']}: {row['fact_count']} facts")
        sections.append("\n".join(lines))

    stale_cutoff = now_sec - 21 * 86400
    stale_rows = cur.execute(
        """
        SELECT
            COALESCE(NULLIF(entity, ''), 'unknown') AS entity,
            COUNT(*) AS fact_count,
            MAX(CASE
                WHEN COALESCE(last_confirmed_at, 0) > COALESCE(created_at, 0)
                    THEN last_confirmed_at
                ELSE created_at
            END) AS recent_ts
        FROM facts
        GROUP BY COALESCE(NULLIF(entity, ''), 'unknown')
        HAVING COUNT(*) > 5 AND recent_ts < ?
        ORDER BY recent_ts ASC, fact_count DESC, entity ASC
        LIMIT 5
        """,
        (stale_cutoff,),
    ).fetchall()
    if stale_rows:
        lines = ["## Stale Zones"]
        for row in stale_rows:
            lines.append(
                f"- **{row['entity']}** ({row['fact_count']} facts, last updated: {format_date(row['recent_ts'])} -- may need verification)"
            )
        sections.append("\n".join(lines))

    content = header
    if sections:
        content += "\n" + "\n\n".join(sections) + "\n"

    return content, total_facts, len(sections), coverage_total


def main():
    args = parse_args()
    db_path = resolve_db_path(args.db_path)
    output_path = args.output or os.path.join(os.path.dirname(os.path.abspath(db_path)), "ROOT.md")
    log_path = os.path.join(os.path.dirname(os.path.abspath(output_path)), "root-gen.log")

    if not os.path.exists(db_path):
        write_output(MINIMAL_ROOT, output_path, args.dry_run)
        return 0

    try:
        conn = connect_read_only(db_path)
    except sqlite3.Error as exc:
        print(f"ERROR: failed to open database '{db_path}': {exc}", file=sys.stderr)
        return 1

    try:
        cur = conn.cursor()
        if not facts_table_exists(cur):
            write_output(MINIMAL_ROOT, output_path, args.dry_run)
            return 0

        now_sec = int(datetime.now(timezone.utc).timestamp())
        content, fact_count, section_count, _ = generate_root(cur, now_sec, args.days)
        write_output(content, output_path, args.dry_run)
        if not args.dry_run:
            append_log_line(log_path, fact_count, section_count, len(content.encode("utf-8")))
        return 0
    except sqlite3.Error as exc:
        print(f"ERROR: SQL failure while generating ROOT.md: {exc}", file=sys.stderr)
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
