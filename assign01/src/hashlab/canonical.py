"""Deterministic ("canonical") JSON serialisation.

Two JSON documents that mean the same thing must produce the same bytes,
otherwise they produce different hashes (and, later in the course, different
signatures and transaction IDs). The rules below are deliberately strict:
anything that could be serialised in more than one way is rejected rather
than silently "fixed".

Canonical rules (also listed in readme.md)
------------------------------------------
R1  Input must be valid UTF-8 without a byte-order mark.
R2  The top-level value must be a JSON object.
R3  Duplicate keys inside any object are rejected.
R4  Numbers must be integers. Fractions/exponents (1.5, 1e3, 1.0) and
    NaN/Infinity are rejected - store amounts in the smallest integer unit.
    "-0" is the integer 0 and is written as 0.
R5  Object keys are sorted by Unicode code point, recursively.
R6  Array order is preserved (order is meaningful in arrays).
R7  No insignificant whitespace: separators are "," and ":"; no trailing newline.
R8  Strings are written as UTF-8 (non-ASCII is NOT \\u-escaped). Only '"', '\\'
    and control characters U+0000-U+001F are escaped, using \\b \\f \\n \\r \\t
    where they exist and \\u00XX otherwise.
R9  Strings are NOT Unicode-normalised: "e" + U+0301 and U+00E9 stay different.
    Lone surrogates (e.g. "\\ud800") are rejected because they are not valid UTF-8.
R10 true, false and null are written in lower case, as in JSON.
"""

from __future__ import annotations

import json
from typing import Any

from .core import Digest, digest_bytes


class CanonicalJSONError(ValueError):
    """Raised when input cannot be canonicalised under the documented rules."""


def _reject_float(s: str) -> Any:
    raise CanonicalJSONError(f"R4: non-integer number {s!r} is not allowed; use integer units")


def _reject_constant(s: str) -> Any:
    raise CanonicalJSONError(f"R4: {s} is not allowed")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise CanonicalJSONError(f"R3: duplicate key {k!r}")
        out[k] = v
    return out


def parse_strict(raw: bytes) -> dict:
    """Parse UTF-8 JSON bytes under rules R1-R4."""
    if raw.startswith(b"\xef\xbb\xbf"):
        raise CanonicalJSONError("R1: UTF-8 byte-order mark is not allowed")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise CanonicalJSONError(f"R1: input is not valid UTF-8 ({e.reason} at byte {e.start})") from None
    try:
        obj = json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as e:
        raise CanonicalJSONError(f"invalid JSON: {e.msg} (line {e.lineno}, column {e.colno})") from None
    if not isinstance(obj, dict):
        raise CanonicalJSONError(f"R2: top-level value must be an object, got {type(obj).__name__}")
    return obj


def canonical_bytes(obj: Any) -> bytes:
    """Serialise an already-parsed value under rules R5-R10."""
    text = json.dumps(
        obj,
        sort_keys=True,          # R5 (Python str ordering == Unicode code-point ordering)
        separators=(",", ":"),   # R7
        ensure_ascii=False,      # R8
        allow_nan=False,         # R4
    )
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        raise CanonicalJSONError("R9: string contains a lone surrogate (not valid UTF-8)") from None


def canonicalize(raw: bytes) -> bytes:
    """Raw JSON bytes -> canonical UTF-8 bytes."""
    return canonical_bytes(parse_strict(raw))


def canonical_digest(raw: bytes) -> tuple[bytes, Digest]:
    canon = canonicalize(raw)
    return canon, digest_bytes(canon)
