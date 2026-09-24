"""
Pull scannable text out of structured tool arguments.

WHY THIS EXISTS -- A REAL BYPASS, NOT A TIDINESS REFACTOR

Three separate call sites used to hand a SERIALIZED form of the arguments
to the detectors:

    tool_call.py   findings = _scan_text(json.dumps(payload.arguments), ...)
    guard.py       found = cls().detect(json.dumps(arguments))
    proxy.py       arg_findings = _scan_text(str(call["arguments"]), ...)

Both serializations escape characters back into ASCII, and the escaped
form contains none of the characters the obfuscation detector looks for:

    json.dumps({"b": "Ignore\\u200ball"})  ->  '{"b": "Ignore\\\\u200ball"}'
                                                            ^^^^^^ six ASCII
                                                                   characters,
                                                                   not U+200B

So the detector scanned a string in which the zero-width space had already
been turned into a backslash, a 'u', and four hex digits, and correctly
reported nothing. Measured, on identical input:

    /api/v1/scan            zero_width_characters, risk 60, escalated to BLOCK
    /api/v1/scan/tool-call  no findings, risk 0

`json.dumps` escapes ALL non-ASCII, so zero-width, bidi AND homoglyph
attacks were invisible. `str()` on a dict escapes only non-printables, so
the proxy path was blind to zero-width and bidi while still catching
homoglyphs -- a subtler variant of the same bug.

This matters more than it would elsewhere. Tool arguments carry this
project's HIGHEST provenance multiplier (1.8x, against 1.0 for direct
input) precisely because they are the most dangerous origin: content that
reached an agent's tool call has already passed through the model. The
path weighted as most dangerous was the one that could not see
obfuscation at all.

THE FIX, AND WHY IT IS THIS ONE

Not `ensure_ascii=False`, though that would close the immediate hole. A
serialized blob is the wrong input to a text detector regardless of
escaping: it interleaves JSON punctuation and quoting with the values, and
it invites exactly this class of mistake the next time somebody serializes
something before scanning it.

Instead, walk the structure and extract the actual strings -- keys
included, because a key name is attacker-controlled too. Every value
arrives at the detector as the characters the attacker really sent.

Values are joined with newlines rather than concatenated, so a pattern
cannot be manufactured by gluing two innocent fields together, and
character-spacing runs cannot straddle a field boundary.
"""

from typing import Any, Iterator

# Depth and volume are bounded because this runs on attacker-supplied
# structures on a request path. A deeply nested payload should cost a
# truncated scan, never a recursion crash in a security gateway.
MAX_DEPTH = 12
MAX_ITEMS = 5_000


def iter_strings(obj: Any, _depth: int = 0, _budget: list[int] | None = None) -> Iterator[str]:
    """Yield every string in a nested structure, exactly as it was received.

    Dict KEYS are yielded as well as values, because a key name is as
    attacker-controlled as anything else. This PRESERVES existing behaviour
    rather than adding to it -- `json.dumps` put key names in the scanned
    text too, so key injection was already caught, and a values-only
    extractor would have been a silent regression while looking like a
    cleanup.
    """
    if _budget is None:
        _budget = [MAX_ITEMS]
    if _depth > MAX_DEPTH or _budget[0] <= 0:
        return

    if isinstance(obj, str):
        _budget[0] -= 1
        if obj:
            yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and k:
                _budget[0] -= 1
                yield k
            yield from iter_strings(v, _depth + 1, _budget)
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            yield from iter_strings(v, _depth + 1, _budget)
    # Numbers, booleans and None carry no text to scan. Deliberately not
    # str()-ed into the output: it would add noise without adding signal.


def extract_scannable_text(obj: Any) -> str:
    """The text a detector should see for a structured tool argument.

    Newline-joined rather than concatenated, so no pattern can be formed
    across a field boundary that neither field contains on its own.
    """
    return "\n".join(iter_strings(obj))
