"""Scanning orchestration for ctxprobe."""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import List, Optional

from . import heuristics
from .parsers import parse, Chunk


@dataclass
class Finding:
    file: str
    line: int
    column: int
    family: str
    severity: str
    source: str
    match: str

    def to_dict(self) -> dict:
        return asdict(self)


# Severity ordering for sorting / summary.
SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}


def _line_col(text: str, pos: int) -> tuple[int, int]:
    """Convert a string offset into (1-based line, 1-based column)."""
    before = text[:pos]
    line = before.count("\n") + 1
    col = pos - before.rfind("\n")
    return line, col


def scan_chunk(chunk: Chunk, file_label: str) -> List[Finding]:
    findings: List[Finding] = []
    for family in heuristics.ALL_FAMILIES:
        for start, end, matched in heuristics.family_matches(family, chunk.text, chunk.source):
            line, col = _line_col(chunk.text, start)
            findings.append(
                Finding(
                    file=file_label,
                    line=line,
                    column=col,
                    family=family.name,
                    severity=family.severity,
                    source=chunk.source,
                    match=matched[:120],
                )
            )
    # De-duplicate exact (line, family, match) within a chunk.
    seen = set()
    unique: List[Finding] = []
    for f in findings:
        key = (f.line, f.family, f.match)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def scan_text(raw: str, fmt: str = "auto", file_label: str = "<stdin>") -> List[Finding]:
    chunks = parse(raw, fmt)
    out: List[Finding] = []
    for chunk in chunks:
        out.extend(scan_chunk(chunk, file_label))
    return out


def scan_file(path: str, fmt: str = "auto") -> List[Finding]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError:
        return []
    # Auto-detect format from extension if not forced.
    if fmt == "auto":
        if path.lower().endswith((".html", ".htm")):
            fmt = "html"
        elif path.lower().endswith((".md", ".markdown")):
            fmt = "markdown"
    return scan_text(raw, fmt, file_label=path)


def scan_path(path: str, fmt: str = "auto") -> List[Finding]:
    """Scan a file or recursively a directory. Returns all findings."""
    from pathlib import Path

    p = Path(path)
    if p.is_file():
        return scan_file(str(p), fmt)
    if p.is_dir():
        out: List[Finding] = []
        for item in sorted(p.rglob("*")):
            if item.is_file():
                # Skip obviously binary / generated paths.
                if item.suffix.lower() in {
                    ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip",
                    ".pyc", ".exe", ".bin", ".ico", ".woff", ".woff2",
                }:
                    continue
                out.extend(scan_file(str(item), fmt))
        return out
    return []
