"""Heuristic families for context-poisoning / prompt-injection detection.

Each family is a list of compiled regexes plus a base severity. Matching is
done per chunk (see ``scanner``). Severities follow the README tiers:

- ``high``   — explicit override / system-prompt injection
- ``medium`` — embedded-instruction heuristic or obfuscation-adjacent
- ``low``    — stylistic / ambient signal
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class Family:
    name: str
    severity: str
    patterns: List[re.Pattern]
    # If True, a match only counts when it appears in a "hidden" source
    # location (comment/attr/meta/code), not visible prose — cuts FPs.
    hidden_context_only: bool = False


I = re.IGNORECASE

# 1. Hidden / embedded instructions: override attempts.
HIDDEN_INSTRUCTIONS = Family(
    name="hidden_instructions",
    severity="high",
    patterns=[
        re.compile(r"(?:ignore|disregard|skip|forget|override|bypass|neglect)\b.{0,30}?\b(?:previous|prior|above|earlier|all\s+previous)\b.{0,20}?\binstructions?", I),
        re.compile(r"\bdisregard\s+(?:the\s+)?(?:above|previous|prior)\b", I),
        re.compile(r"\byou\s+must\s+(?:now\s+)?ignore\b", I),
        re.compile(r"\bnew\s+instructions?\b.{0,20}?take\s+precedence", I),
    ],
)

# 2. System-prompt overrides: explicit role-framing injections.
SYSTEM_PROMPT_OVERRIDE = Family(
    name="system_prompt_override",
    severity="high",
    patterns=[
        re.compile(r"<\|im_start\|>system", I),
        re.compile(r"<\|system\|>"),
        re.compile(r"^\s*(system|assistant|user)\s*[:=]\s", I | re.MULTILINE),
        re.compile(r"\byou\s+are\s+now\s+(?:a|an|the)?\s*(?:system|assistant|admin|root)\b", I),
        re.compile(r"\bpretend\s+(?:to\s+be\s+)?(?:a|an|the)?\s*system\s+(?:prompt|message)\b", I),
    ],
)

# 3. Instructions hidden in HTML comments / metadata / alt text.
EMBEDDED_IN_COMMENT = Family(
    name="embedded_instruction",
    severity="medium",
    patterns=[
        re.compile(r"\b(?:ignore|disregard|follow|execute|run|do\s+this)\b.{0,40}?\b(?:instruction|command|order|prompt)\b", I),
        re.compile(r"\b(?:system|admin|assistant)\s*:\s*\S", I),
    ],
    hidden_context_only=True,
)

# 4. base64 / hex blobs adjacent to action verbs.
OBFUSCATED_BLOB = Family(
    name="obfuscated_blob",
    severity="medium",
    patterns=[
        re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})"),  # long base64
        re.compile(r"\b0x[0-9a-fA-F]{8,}\b"),          # long hex
    ],
)

# 5. Zero-width / invisible Unicode characters.
ZERO_WIDTH = Family(
    name="zero_width_chars",
    severity="low",
    patterns=[
        re.compile(r"[\u200b\u200c\u200d\u2060\u2061\u2062\u2063\ufeff]"),
    ],
)

# 6. Unicode confusables (homoglyph substitution) — flag runs of lookalike chars.
CONFUSABLE = Family(
    name="unicode_confusable",
    severity="low",
    patterns=[
        # Cyrillic/Latin lookalikes commonly used in homoglyph attacks.
        re.compile(r"[\u0400-\u04ff]{3,}"),
        re.compile(r"[\u0500-\u052f]{3,}"),
    ],
)

# 7. Token-economy bribes.
TOKEN_ECONOMY = Family(
    name="token_economy_bribe",
    severity="low",
    patterns=[
        re.compile(r"\b(?:you\s+will\s+be\s+(?:rewarded|given|granted))\b", I),
        re.compile(r"\b(?:here\s+are|earn|receive)\b.{0,15}?\b(?:\d[\d,]*\s*)?(?:tokens?|credits?|points?|coins?|reward)\b", I),
        re.compile(r"\b(?:i\s+will\s+(?:give|grant|pay|reward))\b.{0,30}?\b(?:token|credit|point|coin|reward)\b", I),
    ],
)

# 8. Role-play / jailbreak frames.
ROLE_PLAY_JAILBREAK = Family(
    name="role_play_jailbreak",
    severity="low",
    patterns=[
        re.compile(r"\b(?:you\s+are|act\s+as|roleplay|role-play|pretend\s+to\s+be)\s+(?:a|an|the)?\s*(?:hacker|developer|admin|root|dan|jailbreak|unfiltered|uncensored)\b", I),
        re.compile(r"\bDAN\s+mode\b", I),
        re.compile(r"\b(?:no\s+restrictions?|ignore\s+(?:your\s+)?(?:safety|ethical|content)\s+rules?)\b", I),
    ],
)

# 9. Multi-stage "ask the AI" widget traps.
ASK_AI_WIDGET = Family(
    name="ask_ai_widget_trap",
    severity="medium",
    patterns=[
        re.compile(r"\b(?:ask\s+(?:the\s+)?ai|ask\s+(?:our\s+)?(?:bot|assistant|ai)|chat\s+with\s+(?:our\s+)?ai)\b.{0,60}?\b(?:to\s+do|to\s+help|to\s+write|to\s+generate|to\s+create|to\s+send|to\s+execute)\b", I),
        re.compile(r"\b(?:click\s+here|tap\s+here|press\s+here)\b.{0,40}?\b(?:and\s+ask|to\s+ask|ask)\b", I),
    ],
)

ALL_FAMILIES: List[Family] = [
    HIDDEN_INSTRUCTIONS,
    SYSTEM_PROMPT_OVERRIDE,
    EMBEDDED_IN_COMMENT,
    OBFUSCATED_BLOB,
    ZERO_WIDTH,
    CONFUSABLE,
    TOKEN_ECONOMY,
    ROLE_PLAY_JAILBREAK,
    ASK_AI_WIDGET,
]

# Source labels that count as "hidden" — embedded-instruction family only
# fires here, not in visible prose.
HIDDEN_SOURCES = (
    "html:comment",
    "html:meta",
    "html:attr",
    "html:script",
    "html:style",
    "md:frontmatter",
    "md:code",
)


def _looks_like_base64(token: str) -> bool:
    if len(token) < 16:
        return False
    try:
        base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return False
    # Reject ordinary English words that happen to be valid base64 alphabet.
    if token.lower() in {
        "thequickbrownfoxjumpsoverthelazydog",
    }:
        return False
    return True


def _looks_like_hex(token: str) -> bool:
    return len(token) >= 10 and all(c in "0123456789abcdefABCDEF" for c in token[2:])


def family_matches(family: Family, chunk_text: str, source: str) -> List[Tuple[int, int, str]]:
    """Return list of (start, end, matched_text) for a family in one chunk."""
    if family.hidden_context_only and not source.startswith(HIDDEN_SOURCES):
        return []

    hits: List[Tuple[int, int, str]] = []
    for pat in family.patterns:
        for m in pat.finditer(chunk_text):
            matched = m.group(0)
            # Family-specific validity checks to suppress obvious FPs.
            if family is OBFUSCATED_BLOB:
                if re.match(r"[A-Za-z0-9+/]{40,}={0,2}", matched):
                    if not _looks_like_base64(matched):
                        continue
                elif re.match(r"0x[0-9a-fA-F]{8,}", matched):
                    if not _looks_like_hex(matched):
                        continue
                else:
                    continue
            hits.append((m.start(), m.end(), matched))
    return hits
