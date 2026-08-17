"""
Character tables and heuristics for the obfuscation detector.

Unlike prompt_injection (phrase/regex matching on meaning), this detector
works at the character/encoding level -- it doesn't care what the text
says, only how it's encoded. v0.1 baseline: deterministic checks only,
no ML. See docs/threat-model/README.md for documented limitations.
"""

import re
import unicodedata

# -- Invisible / zero-width characters ---------------------------------------
# Used to split trigger words apart so phrase-matching detectors miss them,
# or to hide invisible instructions inside otherwise normal-looking text.
ZERO_WIDTH_CHARS: dict[str, str] = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
}

# -- Bidirectional control characters ----------------------------------------
# Can reorder how text is *displayed* without changing the underlying bytes
# -- the "Trojan Source" technique. A reviewer sees one thing; the model
# processes another.
BIDI_CONTROL_CHARS: dict[str, str] = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}

# -- Unusual whitespace -------------------------------------------------------
# Non-standard space characters, often used the same way as zero-width
# characters: to break up a filtered word without a visible difference.
UNUSUAL_SPACE_CHARS: dict[str, str] = {
    "\u00a0": "NO-BREAK SPACE",
    "\u2000": "EN QUAD",
    "\u2001": "EM QUAD",
    "\u2002": "EN SPACE",
    "\u2003": "EM SPACE",
    "\u2004": "THREE-PER-EM SPACE",
    "\u2005": "FOUR-PER-EM SPACE",
    "\u2006": "SIX-PER-EM SPACE",
    "\u2007": "FIGURE SPACE",
    "\u2008": "PUNCTUATION SPACE",
    "\u2009": "THIN SPACE",
    "\u200a": "HAIR SPACE",
    "\u202f": "NARROW NO-BREAK SPACE",
    "\u205f": "MEDIUM MATHEMATICAL SPACE",
    "\u3000": "IDEOGRAPHIC SPACE",
}

# -- Encoded-payload heuristics ------------------------------------------------
BASE64_BLOB_RE = re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
HTML_ENTITY_RE = re.compile(r"&#x?[0-9a-fA-F]+;|&[a-zA-Z]{2,10};")

# Tracked scripts for the mixed-script homoglyph heuristic. Derived from
# Python's stdlib unicodedata character names (e.g. 'CYRILLIC SMALL LETTER A')
# rather than a full Unicode script-property lookup, which would need an
# extra dependency this project doesn't have yet.
_TRACKED_SCRIPTS = {"LATIN", "CYRILLIC", "GREEK"}


def char_script_hint(char: str) -> str | None:
    try:
        name = unicodedata.name(char)
    except ValueError:
        return None
    first_word = name.split(" ", 1)[0]
    return first_word if first_word in _TRACKED_SCRIPTS else None


def find_mixed_script_runs(text: str) -> list[tuple[str, int, int, set[str]]]:
    """Alphabetic runs that mix 2+ tracked scripts -- a strong homoglyph signal."""
    results: list[tuple[str, int, int, set[str]]] = []
    i, n = 0, len(text)
    while i < n:
        if text[i].isalpha():
            start = i
            scripts_seen: set[str] = set()
            while i < n and text[i].isalpha():
                hint = char_script_hint(text[i])
                if hint:
                    scripts_seen.add(hint)
                i += 1
            if len(scripts_seen) >= 2:
                results.append((text[start:i], start, i, scripts_seen))
        else:
            i += 1
    return results


def find_control_characters(text: str) -> list[tuple[str, int]]:
    """Raw ASCII control characters, excluding common whitespace (\\t \\n \\r)."""
    allowed = {"\t", "\n", "\r"}
    return [(ch, idx) for idx, ch in enumerate(text) if ord(ch) < 0x20 and ch not in allowed]


def find_character_spaced_runs(text: str, min_run: int = 5) -> list[tuple[str, int]]:
    """
    Detects text broken into single characters separated by whitespace
    (e.g. "I g n o r e" or one letter per line) -- a real technique found
    during evaluation (see docs/research/README.md, examples pr1m8-FT-004
    and pr1m8-FT-005) for evading phrase-matching detectors by inserting
    plain whitespace inside every trigger word, the same idea as zero-width
    characters but using ordinary spaces or newlines instead.

    Returns (reconstructed_text, token_count) for each run of >= min_run
    consecutive one-character whitespace-separated tokens.
    """
    tokens = text.split()
    runs: list[tuple[str, int]] = []
    i, n = 0, len(tokens)
    while i < n:
        if len(tokens[i]) == 1:
            start = i
            while i < n and len(tokens[i]) == 1:
                i += 1
            run_len = i - start
            if run_len >= min_run:
                runs.append(("".join(tokens[start:i]), run_len))
        else:
            i += 1
    return runs
