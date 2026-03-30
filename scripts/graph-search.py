#!/usr/bin/env python3
"""
Graph-augmented memory search.
Combines: alias resolution → facts.db → relations → FTS → source file mapping

Usage:
  python3 scripts/graph-search.py "When is someone's birthday?"
  python3 scripts/graph-search.py "What runs on aiserver?" --json
  python3 scripts/graph-search.py "Mama's phone number"
"""

import sqlite3
import json
import re
import sys
import argparse
import os
from pathlib import Path

from fts_helper import build_or_match_query

DEBUG = False
DEFAULT_LEGACY_DB_PATH = Path("/home/openclaw/.openclaw/memory/facts.db")
DB_PATH = DEFAULT_LEGACY_DB_PATH


def resolve_db_path(cli_db_path: str | None = None) -> Path:
    """Resolve facts.db path using CLI arg, workspace env, then legacy fallback."""
    if cli_db_path:
        return Path(cli_db_path).expanduser()

    workspace = os.environ.get("OPENCLAW_WORKSPACE")
    if workspace:
        return Path(workspace).expanduser() / "memory" / "facts.db"

    cwd_candidate = Path.cwd() / "memory" / "facts.db"
    if cwd_candidate.exists():
        return cwd_candidate

    print(
        f"[graph-search] warning: using legacy facts.db path {DEFAULT_LEGACY_DB_PATH}. "
        "Set OPENCLAW_WORKSPACE or --db-path for portability.",
        file=sys.stderr,
    )
    return DEFAULT_LEGACY_DB_PATH


def set_db_path(db_path: Path):
    global DB_PATH
    DB_PATH = db_path


def resolve_entity(db: sqlite3.Connection, name: str) -> str | None:
    """Resolve alias to canonical entity name"""
    try:
        row = db.execute("SELECT entity FROM aliases WHERE alias = ? COLLATE NOCASE", (name,)).fetchone()
        if row:
            return row[0]
    except sqlite3.OperationalError:
        pass  # aliases table may not exist
    row = db.execute("SELECT DISTINCT entity FROM facts WHERE entity = ? COLLATE NOCASE", (name,)).fetchone()
    if row:
        return row[0]
    return None


def extract_entity_candidates(query: str) -> list[str]:
    """Extract potential entity names from a natural language query"""
    # Known entity patterns (capitalize words, check 1-3 word combos)
    words = query.split()
    candidates = []
    
    # Single capitalized words
    for w in words:
        clean = re.sub(r'[^\w]', '', w)
        if clean and clean[0].isupper() and len(clean) > 1:
            candidates.append(clean)
    
    # Two-word combos (e.g., "Jim Gardner", "Home Assistant")
    for i in range(len(words) - 1):
        w1 = re.sub(r'[^\w]', '', words[i])
        w2 = re.sub(r'[^\w]', '', words[i + 1])
        if w1 and w2 and w1[0].isupper():
            candidates.append(f"{w1} {w2}")
    
    # Three-word combos (e.g., "Dan Verakis", "Adult in Training", "Microdose Tracker")
    for i in range(len(words) - 2):
        w1 = re.sub(r'[^\w]', '', words[i])
        w2 = re.sub(r'[^\w]', '', words[i + 1])
        w3 = re.sub(r'[^\w]', '', words[i + 2])
        if w1 and w2 and w3:
            candidates.append(f"{w1} {w2} {w3}")
    
    # Also try common lowercase aliases (word-boundary matching to avoid "flo" in "overflow")
    lower_aliases = ["mama", "jojo", "flo", "aiserver", "homelab", "n8n", "keystone",
                     "clawsmith", "postiz", "komodo", "ghost", "ollama", "mdt", "ait",
                     "the server", "ha"]
    query_lower = query.lower()
    for alias in lower_aliases:
        if " " in alias:
            if alias in query_lower:
                candidates.append(alias)
        else:
            pattern = r'\b' + re.escape(alias) + r'\b'
            if re.search(pattern, query_lower):
                candidates.append(alias)
    
    # Possessive patterns: "someone's" → extract the entity name
    # BUT skip common contractions like "who's", "what's", "where's", "when's", "how's"
    CONTRACTION_SKIP = {"who", "what", "where", "when", "how", "it", "that", "there", "here"}
    for match in re.finditer(r"(\w+)'s\b", query):
        word = match.group(1).lower()
        if word not in CONTRACTION_SKIP:
            candidates.append(match.group(1))
    
    # Self-reference queries
    query_lower = query.lower()
    if any(p in query_lower for p in ["who am i", "my name", "what am i", "my principles",
                                       "what do i care", "how should i communicate"]):
        candidates.append("Gandalf")
    
    # Multi-word phrase matching against known aliases
    # Only match aliases with 2+ words OR single words that are proper nouns (capitalized in query)
    # Skip very short/generic aliases to avoid false matches
    SKIP_ALIASES = {"i", "me", "my name", "who am i", "ha", "the server"}
    try:
        db_path = DB_PATH
        if db_path.exists():
            _db = sqlite3.connect(str(db_path))
            # aliases table may not exist yet
            _has_aliases = _db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='aliases'").fetchone()
            if _has_aliases:
                all_aliases = [r[0] for r in _db.execute("SELECT DISTINCT alias FROM aliases").fetchall()]
            else:
                all_aliases = []
            _db.close()
            for alias in all_aliases:
                if alias.lower() in SKIP_ALIASES:
                    continue
                alias_lower = alias.lower()
                # Multi-word aliases: match if the full phrase appears
                if " " in alias and alias_lower in query_lower and alias not in candidates:
                    candidates.append(alias)
                # Single-word aliases (3+ chars): only match on word boundaries
                elif " " not in alias and len(alias) >= 3:
                    pattern = r'\b' + re.escape(alias_lower) + r'\b'
                    if re.search(pattern, query_lower) and alias not in candidates:
                        candidates.append(alias)
    except (sqlite3.Error, OSError) as exc:
        if DEBUG:
            print(f"[graph-search] alias scan failed: {exc}", file=sys.stderr)
    
    return candidates


def extract_intent(query: str) -> list[str]:
    """Extract likely fact keys from query intent"""
    query_lower = query.lower()
    intents = []
    
    patterns = {
        "birthday": ["birthday", "born", "birth", "birthdate", "when was .* born"],
        "phone": ["phone", "number", "call", "contact", "reach"],
        "email": ["email", "mail", "address.*@", "contact"],
        "address": ["address", "live", "lives", "where does .* live", "location"],
        "birthplace": ["birthplace", "born in", "where was .* born", "from", "origin"],
        "relationship": ["who is", "relationship", "partner", "wife", "husband", "girlfriend"],
        "url": ["url", "website", "domain", "site"],
        "stack": ["stack", "tech", "built with", "uses", "framework"],
        "runs_on": ["port", "runs on", "hosted", "server"],
        "role": ["role", "what does .* do", "job"],
        "full_name": ["full name", "real name", "name"],
    }
    
    for intent, keywords in patterns.items():
        for kw in keywords:
            if re.search(kw, query_lower):
                intents.append(intent)
                break
    
    return intents



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


def build_scope_filters(agent_id: str | None = None, session_id: str | None = None) -> tuple[list[str], list]:
    """Build optional scope filter SQL for facts metadata.

    Fail-open: on any construction error, return no filters.
    """
    try:
        clauses = []
        params = []
        if agent_id:
            clauses.append("(agent_id = ? OR agent_id IS NULL)")
            params.append(agent_id)
        if session_id:
            clauses.append("(session_id = ? OR session_id IS NULL)")
            params.append(session_id)
        return clauses, params
    except Exception as exc:
        if DEBUG:
            print(f"[graph-search] scope filter fallback (fail-open): {exc}", file=sys.stderr)
        return [], []


def scoped_relations_exists_sql(base_alias: str, scope_clauses: list[str]) -> str:
    if not scope_clauses:
        return ""
    scoped = " AND ".join(scope_clauses)
    return (
        " AND EXISTS (SELECT 1 FROM facts f_scope "
        f"WHERE f_scope.entity = {base_alias}.subject AND {scoped})"
    )


def db_has_scope_columns(db: sqlite3.Connection) -> bool:
    try:
        cols = {r[1] for r in db.execute("PRAGMA table_info(facts)").fetchall()}
        return "agent_id" in cols and "session_id" in cols
    except sqlite3.Error as exc:
        if DEBUG:
            print(f"[graph-search] scope column check failed (fail-open): {exc}", file=sys.stderr)
        return False

def graph_search(
    query: str,
    db: sqlite3.Connection,
    top_k: int = 6,
    agent_id: str | None = None,
    session_id: str | None = None,
) -> list[dict]:
    """
    Search the knowledge graph for answers.
    Returns list of {path, score, answer, entity, method} dicts.
    """
    results = []
    seen = set()
    
    candidates = extract_entity_candidates(query)
    intents = extract_intent(query)
    scope_clauses, scope_params = build_scope_filters(agent_id=agent_id, session_id=session_id)
    if scope_clauses and not db_has_scope_columns(db):
        scope_clauses, scope_params = [], []
    facts_scope_where = f" AND {' AND '.join(scope_clauses)}" if scope_clauses else ""
    relations_scope_exists = scoped_relations_exists_sql("relations", scope_clauses)
    
    # Phase 1: Entity + Intent matching (highest confidence)
    for candidate in candidates:
        entity = resolve_entity(db, candidate)
        if not entity:
            continue
        
        if intents:
            for intent in intents:
                # Search facts
                rows = db.execute(
                    f"SELECT key, value, source FROM facts WHERE entity = ? AND key LIKE ?{facts_scope_where}",
                    (entity, f"%{intent}%", *scope_params)
                ).fetchall()
                for key, value, source in rows:
                    result_key = f"{entity}:{key}"
                    if result_key not in seen:
                        seen.add(result_key)
                        results.append({
                            "path": source or "facts.db",
                            "score": 95,
                            "answer": f"{entity}.{key} = {value}",
                            "entity": entity,
                            "method": "entity+intent"
                        })
                
                # Search relations
                rows = db.execute(
                    f"SELECT predicate, object, source FROM relations WHERE subject = ? AND predicate LIKE ?{relations_scope_exists}",
                    (entity, f"%{intent}%", *scope_params)
                ).fetchall()
                for pred, obj, source in rows:
                    result_key = f"{entity}:{pred}:{obj}"
                    if result_key not in seen:
                        seen.add(result_key)
                        results.append({
                            "path": source or "facts.db",
                            "score": 90,
                            "answer": f"{entity} → {pred} → {obj}",
                            "entity": entity,
                            "method": "entity+intent+rel"
                        })
        
        # Phase 2: All facts for resolved entity (medium confidence)
        rows = db.execute(
            f"SELECT key, value, source FROM facts WHERE entity = ?{facts_scope_where}",
            (entity, *scope_params)
        ).fetchall()
        for key, value, source in rows:
            result_key = f"{entity}:{key}"
            if result_key not in seen:
                seen.add(result_key)
                results.append({
                    "path": source or "facts.db",
                    "score": 70,
                    "answer": f"{entity}.{key} = {value}",
                    "entity": entity,
                    "method": "entity"
                })
        
        # Phase 2b: All relations for entity
        rows = db.execute(
            f"SELECT predicate, object, source FROM relations WHERE subject = ?{relations_scope_exists}",
            (entity, *scope_params)
        ).fetchall()
        for pred, obj, source in rows:
            result_key = f"{entity}:{pred}:{obj}"
            if result_key not in seen:
                seen.add(result_key)
                results.append({
                    "path": source or "facts.db",
                    "score": 65,
                    "answer": f"{entity} → {pred} → {obj}",
                    "entity": entity,
                    "method": "entity+rel"
                })
    
    # Phase 3: FTS on facts (lower confidence — no entity resolved)
    if not results:
        # Build FTS query from significant words
        stop_words = {"what", "is", "the", "a", "an", "of", "in", "on", "at", "to", "for",
                      "how", "when", "where", "who", "which", "does", "do", "did", "has",
                      "have", "about", "with", "my", "your", "this", "that", "are", "was"}
        fts_query = build_or_match_query(query, stop_words=stop_words, min_len=2)
        if fts_query:
            try:
                rows = db.execute(
                    (
                        "SELECT fts.entity, fts.key, fts.value "
                        "FROM facts_fts fts JOIN facts f ON f.id = fts.rowid "
                        f"WHERE fts MATCH ?{facts_scope_where}"
                    ),
                    (fts_query, *scope_params)
                ).fetchall()
                for entity, key, value in rows[:top_k]:
                    result_key = f"{entity}:{key}"
                    if result_key not in seen:
                        seen.add(result_key)
                        source = db.execute(
                            f"SELECT source FROM facts WHERE entity = ? AND key = ?{facts_scope_where}",
                            (entity, key, *scope_params)
                        ).fetchone()
                        results.append({
                            "path": (source[0] if source else "facts.db"),
                            "score": 50,
                            "answer": f"{entity}.{key} = {value}",
                            "entity": entity,
                            "method": "fts"
                        })
            except sqlite3.Error as exc:
                if DEBUG:
                    print(f"[graph-search] facts FTS failed: {exc}", file=sys.stderr)
    
    # Phase 4: FTS on relations
    if len(results) < top_k:
        fts_query = build_or_match_query(
            query,
            stop_words={"what", "is", "the", "a", "an", "of", "in", "on", "at", "to", "for",
                        "how", "when", "where", "who", "which", "does", "do"},
            min_len=2,
        )
        if fts_query:
            try:
                rows = db.execute(
                    (
                        "SELECT r.subject, r.predicate, r.object "
                        "FROM relations_fts r JOIN relations rel ON rel.rowid = r.rowid "
                        f"WHERE r MATCH ?{scoped_relations_exists_sql('rel', scope_clauses)}"
                    ),
                    (fts_query, *scope_params)
                ).fetchall()
                for subj, pred, obj in rows[:top_k]:
                    result_key = f"rel:{subj}:{pred}:{obj}"
                    if result_key not in seen:
                        seen.add(result_key)
                        source = db.execute(
                            f"SELECT source FROM relations WHERE subject = ? AND predicate = ? AND object = ?{relations_scope_exists}",
                            (subj, pred, obj, *scope_params)
                        ).fetchone()
                        results.append({
                            "path": (source[0] if source else "facts.db"),
                            "score": 40,
                            "answer": f"{subj} → {pred} → {obj}",
                            "entity": subj,
                            "method": "fts_rel"
                        })
            except sqlite3.Error as exc:
                if DEBUG:
                    print(f"[graph-search] relations FTS failed: {exc}", file=sys.stderr)
    
    # Sort by score, return top-K
    results.sort(key=lambda r: r["score"], reverse=True)
    # Apply freshness weighting
    results = apply_freshness(db, results[:top_k * 2])
    return results[:top_k]


def main():
    parser = argparse.ArgumentParser(description="Graph-augmented memory search")
    parser.add_argument("query", help="Search query")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--top-k", "-k", type=int, default=6)
    parser.add_argument("--debug", action="store_true", help="Show backend/database errors")
    parser.add_argument("--db-path", help="Path to facts.db (overrides OPENCLAW_WORKSPACE)")
    parser.add_argument("--agent", help="Agent ID scope filter (includes shared facts)")
    parser.add_argument("--session", help="Session ID scope filter (includes shared facts)")
    args = parser.parse_args()

    global DEBUG
    DEBUG = args.debug

    db_path = resolve_db_path(args.db_path)
    set_db_path(db_path)
    if not db_path.exists():
        print(f"[graph-search] error: facts.db not found at {db_path}", file=sys.stderr)
        sys.exit(2)

    db = sqlite3.connect(str(db_path))
    results = graph_search(args.query, db, args.top_k, agent_id=args.agent, session_id=args.session)
    db.close()
    
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        if not results:
            print("No results found.")
        else:
            for r in results:
                print(f"  [{r['score']:5.1f}] [{r['method']:18s}] {r['answer']}")
                print(f"        source: {r['path']}")


if __name__ == "__main__":
    main()
