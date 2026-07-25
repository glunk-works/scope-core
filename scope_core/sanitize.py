"""`sanitize` -- the ingestion-sanitization seam: a structural/mechanical
normalizer for attacker-influenceable scanner/target text before it reaches
a triage LLM. Deliberately **not** an injection-phrase blocklist --
untrusted text should still be structurally fenced by the caller's own
prompt template; this primitive only bounds shape and size.
"""

from __future__ import annotations

import re
import unicodedata

# Suggested per-field cap for attacker-influenceable scanner/target text
# reaching a triage LLM. Callers pass their own `max_len`; this constant
# documents the intended order of magnitude.
DEFAULT_MAX_LEN = 2048

# C0 controls (0x00-0x1F) and DEL (0x7F), minus \t/\n/\r -- those are left
# in place here and folded into ordinary whitespace by the collapse step
# below, rather than dropped outright. C1 controls (0x80-0x9F) too.
_C0_C1_CONTROL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F\x80-\x9F]")

# ANSI CSI escape sequences: ESC '[' params intermediates final-byte.
_ANSI_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

# Variation selectors (U+FE00-FE0F, the supplementary block
# U+E0100-E01EF): invisible glyph-variant hints, category Mn rather than Cf,
# so the Cf sweep below doesn't already catch them. A narrow explicit range
# -- unlike Cf, general Mn also covers legitimate combining accents and must
# not be swept wholesale.
_VARIATION_SELECTOR_RANGES = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))

_WHITESPACE_RUN_RE = re.compile(r"\s+")


def _is_variation_selector(char: str) -> bool:
    codepoint = ord(char)
    return any(start <= codepoint <= end for start, end in _VARIATION_SELECTOR_RANGES)


def _strip_invisible_format_characters(text: str) -> str:
    # Unicode category "Cf" (format) is a single structural sweep that
    # covers the zero-width joiners/spaces and BOM this module always
    # stripped, plus bidi overrides/isolates (Trojan-Source display
    # spoofing, e.g. U+202E) and the Tags block (U+E0000-E007F, the
    # "ASCII smuggler" invisible-instruction channel) -- category-based
    # rather than an enumerated codepoint list, so it isn't a phrase/char
    # blocklist.
    return "".join(
        char
        for char in text
        if unicodedata.category(char) != "Cf" and not _is_variation_selector(char)
    )


def normalize(text: str) -> str:
    """The structural prefix of `sanitize`: strip ANSI CSI escapes, C0/C1
    control characters, and invisible format/variation-selector code
    points; NFKC-normalize. No whitespace-collapse, no truncation --
    identifiers (a scope key + DB join key) must anti-evasion-normalize
    without changing length or collapsing internal whitespace the way free
    text destined for a triage LLM does. Deterministic and pure.
    """
    text = _ANSI_CSI_RE.sub("", text)
    text = _C0_C1_CONTROL_RE.sub("", text)
    text = _strip_invisible_format_characters(text)
    return unicodedata.normalize("NFKC", text)


def sanitize(text: str, *, max_len: int) -> str:
    """Structural/mechanical normalization only: `normalize`, then collapse
    whitespace runs and hard-truncate to `max_len`. Deterministic and pure
    -- identical input always yields identical output.
    """
    text = normalize(text)
    text = _WHITESPACE_RUN_RE.sub(" ", text).strip()
    return text[:max_len]
