#!/usr/bin/env python3
"""Patch graph-search.py with freshness-weighted recall.

Designed for VPS path: /home/openclaw/.openclaw/scripts/graph-search.py
"""

from __future__ import annotations

from pathlib import Path
import re
import shutil
import time

TARGET = Path('/home/openclaw/.openclaw/scripts/graph-search.py')

FRESHNESS_BLOCK = '''
# --- Freshness weighting (added 2026-03-17) ---
FRESHNESS_WEIGHT = 0.30  # max 30% boost/penalty from recency
FRESHNESS_DECAY_DAYS = 90  # facts older than this get no freshness boost

def apply_freshness(db, results):
    """Apply freshness multiplier to search results based on last_confirmed_at."""
    import time
    now = int(time.time())
    for r in results:
        # Look up last_confirmed_at for this fact
        try:
            row = db.execute(
                "SELECT last_confirmed_at FROM facts WHERE entity = ? AND key = ? LIMIT 1",
                (r.get("entity", ""), r.get("answer", "").split(".")[1].split(" = ")[0] if "." in r.get("answer", "") else "")
            ).fetchone()
            if row and row[0]:
                age_days = (now - int(row[0])) / 86400
                freshness = max(0.0, 1.0 - (age_days / FRESHNESS_DECAY_DAYS))
                r["score"] = r["score"] * (1.0 - FRESHNESS_WEIGHT + FRESHNESS_WEIGHT * freshness)
                r["score"] = round(r["score"], 1)
        except Exception:
            pass  # If lookup fails, keep original score
    # Re-sort after applying freshness
    results.sort(key=lambda r: r["score"], reverse=True)
    return results

'''


def main() -> int:
    if not TARGET.exists():
        print(f"ERROR: target file not found: {TARGET}")
        return 1

    backup = TARGET.with_suffix(TARGET.suffix + f'.bak.{time.strftime("%Y%m%d")}')
    shutil.copy2(TARGET, backup)
    print(f'Backup created: {backup}')

    content = TARGET.read_text()

    if 'def apply_freshness(db, results):' not in content:
        content, n = re.subn(
            r'(^def graph_search\(query: str,)',
            FRESHNESS_BLOCK + r'\1',
            content,
            count=1,
            flags=re.MULTILINE,
        )
        if n != 1:
            print('ERROR: could not locate graph_search() for freshness insertion')
            return 2

    pattern = (
        '    # Sort by score, return top-K\n'
        '    results.sort(key=lambda r: r["score"], reverse=True)\n'
        '    return results[:top_k]'
    )
    replacement = (
        '    # Sort by score, return top-K\n'
        '    results.sort(key=lambda r: r["score"], reverse=True)\n'
        '    # Apply freshness weighting\n'
        '    results = apply_freshness(db, results[:top_k * 2])\n'
        '    return results[:top_k]'
    )

    if replacement not in content:
        if pattern not in content:
            print('ERROR: could not locate return-sorting block to patch')
            return 3
        content = content.replace(pattern, replacement, 1)

    TARGET.write_text(content)
    print('Patched graph-search.py with freshness weighting')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
