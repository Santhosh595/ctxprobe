"""Content parsers for ctxprobe.

Each parser turns raw bytes/text into a list of (text, source_label) chunks.
The scanner runs heuristics over every chunk's text; source_label records
*where* in the document the text came from (e.g. ``html:comment``,
``md:html_block``) so findings can be triaged by location — embedded
instructions in an HTML comment are more suspicious than the same words in
visible prose.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import List


@dataclass
class Chunk:
    text: str
    source: str  # where the text came from inside the document


# ---------------------------------------------------------------------------
# HTML parsing (regex-based, stdlib only — no external deps)
# ---------------------------------------------------------------------------

_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_SCRIPT_RE = re.compile(r"<script\b[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)
_STYLE_RE = re.compile(r"<style\b[^>]*>(.*?)</style>", re.DOTALL | re.IGNORECASE)
_META_RE = re.compile(
    r"<meta\b[^>]*?(?:name|property)\s*=\s*[\"']([^\"']+)[\"'][^>]*?content\s*=\s*[\"']([^\"']*)[\"']",
    re.IGNORECASE,
)
_TAG_TEXT_RE = re.compile(r">([^<]+)<", re.DOTALL)
_ATTR_RE = re.compile(r"""(\w[\w-]*)\s*=\s*["']([^"']*)["']""", re.IGNORECASE)


def parse_html(raw: str) -> List[Chunk]:
    """Extract instruction-relevant regions from an HTML document."""
    chunks: List[Chunk] = []

    # Comments — models reading page source may still honor them.
    for m in _COMMENT_RE.finditer(raw):
        chunks.append(Chunk(m.group(1), "html:comment"))

    # <script>/<style> contents.
    for m in _SCRIPT_RE.finditer(raw):
        chunks.append(Chunk(m.group(1), "html:script"))
    for m in _STYLE_RE.finditer(raw):
        chunks.append(Chunk(m.group(1), "html:style"))

    # <meta> content attributes (e.g. og:description, description).
    for m in _META_RE.finditer(raw):
        chunks.append(Chunk(m.group(2), f"html:meta:{m.group(1).lower()}"))

    # Visible text nodes.
    for m in _TAG_TEXT_RE.finditer(raw):
        text = m.group(1).strip()
        if text:
            chunks.append(Chunk(html.unescape(text), "html:text"))

    # Attributes that commonly carry hidden instructions (alt, title, etc.).
    for m in _ATTR_RE.finditer(raw):
        name = m.group(1).lower()
        value = m.group(2)
        if name in {"alt", "title", "aria-label", "data-text", "value"} and value.strip():
            chunks.append(Chunk(value, f"html:attr:{name}"))

    return chunks


# ---------------------------------------------------------------------------
# Markdown parsing (lightweight — no external deps)
# ---------------------------------------------------------------------------

_HTML_BLOCK_RE = re.compile(r"<[^>]+>.*?</[^>]+>|<[^>]+/>", re.DOTALL)
_CODE_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)
_LINK_RE = re.compile(r"\[([^\]]*)\]\(([^)]*)\)")
_FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)


def parse_markdown(raw: str) -> List[Chunk]:
    """Extract instruction-relevant regions from a Markdown document."""
    chunks: List[Chunk] = []

    # YAML front matter (key: value pairs can carry injected config).
    fm = _FRONTMATTER_RE.match(raw)
    if fm:
        chunks.append(Chunk(fm.group(1), "md:frontmatter"))

    # HTML blocks embedded in markdown.
    for m in _HTML_BLOCK_RE.finditer(raw):
        chunks.extend(parse_html(m.group(0)))

    # Link text + URL (URLs can hide instructions in query strings).
    for m in _LINK_RE.finditer(raw):
        if m.group(1).strip():
            chunks.append(Chunk(m.group(1), "md:link_text"))
        if m.group(2).strip():
            chunks.append(Chunk(m.group(2), "md:link_url"))

    # Code fences — sometimes used to smuggle instructions past prose scanners.
    for m in _CODE_FENCE_RE.finditer(raw):
        chunks.append(Chunk(m.group(0), "md:code"))

    # Everything else is visible markdown prose.
    chunks.append(Chunk(raw, "md:prose"))
    return chunks


# ---------------------------------------------------------------------------
# Plaintext
# ---------------------------------------------------------------------------

def parse_text(raw: str) -> List[Chunk]:
    """A single prose chunk for plain text."""
    return [Chunk(raw, "text:prose")]


def parse(raw: str, fmt: str = "auto") -> List[Chunk]:
    """Dispatch to a parser. ``fmt`` is one of auto|html|markdown|text."""
    if fmt == "auto":
        stripped = raw.lstrip()
        if stripped.startswith("<!DOCTYPE") or stripped.startswith("<html") or "<body" in raw.lower():
            fmt = "html"
        elif _FRONTMATTER_RE.match(raw) or "```" in raw or raw.count("#") > 3:
            fmt = "markdown"
        else:
            fmt = "text"
    if fmt == "html":
        return parse_html(raw)
    if fmt == "markdown":
        return parse_markdown(raw)
    return parse_text(raw)
