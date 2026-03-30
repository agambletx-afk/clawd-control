#!/usr/bin/env python3
"""Helpers for safely turning user input into FTS5 MATCH expressions."""

from __future__ import annotations

import re
from typing import Iterable

TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


def tokenize_for_fts(text: str, *, stop_words: Iterable[str] | None = None, min_len: int = 1) -> list[str]:
    """Extract lowercase word tokens suitable for FTS lookup.

    Non-word syntax (quotes, operators, wildcards, parentheses) is ignored so
    user input cannot accidentally form an FTS expression.
    """
    stop = {w.lower() for w in stop_words} if stop_words else set()
    tokens = []
    for token in TOKEN_RE.findall(text.lower()):
        if len(token) < min_len:
            continue
        if token in stop:
            continue
        tokens.append(token)
    return tokens


def escape_fts_term(term: str) -> str:
    """Escape a single FTS term as a quoted literal string."""
    return '"' + term.replace('"', '""') + '"'


def build_or_match_query(text: str, *, stop_words: Iterable[str] | None = None, min_len: int = 1) -> str:
    """Build an OR-based MATCH query from user text using escaped tokens."""
    tokens = tokenize_for_fts(text, stop_words=stop_words, min_len=min_len)
    return " OR ".join(escape_fts_term(token) for token in tokens)
