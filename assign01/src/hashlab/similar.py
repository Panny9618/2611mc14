"""Pairs of inputs that look alike to a human but are different bytes."""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from .canonical import canonicalize
from .core import Digest, digest_bytes


@dataclass(frozen=True)
class Case:
    title: str
    left_label: str
    left: bytes
    right_label: str
    right: bytes
    lesson: str

    @property
    def left_digest(self) -> Digest:
        return digest_bytes(self.left)

    @property
    def right_digest(self) -> Digest:
        return digest_bytes(self.right)

    @property
    def same(self) -> bool:
        return self.left == self.right


def cases() -> list[Case]:
    nfc = unicodedata.normalize("NFC", "café")   # é = U+00E9 (1 code point)
    nfd = unicodedata.normalize("NFD", "café")   # e + U+0301 (2 code points)
    raw_ab = b'{"from":"Alice","to":"Bob","amount":10}'
    raw_ba = b'{"amount":10,"to":"Bob","from":"Alice"}'
    return [
        Case(
            "1. Trailing newline (echo adds one, printf does not)",
            '"Alice pays Bob 10"', b"Alice pays Bob 10",
            '"Alice pays Bob 10\\n"', b"Alice pays Bob 10\n",
            "One invisible 0x0A byte changes the whole digest.",
        ),
        Case(
            "2. Line endings: Unix LF vs Windows CRLF",
            '"a\\nb"', b"a\nb",
            '"a\\r\\nb"', b"a\r\nb",
            "A file checked out on Windows can hash differently from the same file on Linux.",
        ),
        Case(
            "3. Unicode normalisation: NFC vs NFD 'café'",
            "NFC (U+00E9)", nfc.encode("utf-8"),
            "NFD (e + U+0301)", nfd.encode("utf-8"),
            "Both render as café, but NFC is 5 bytes and NFD is 6 bytes.",
        ),
        Case(
            "4. Integer vs string in JSON",
            '{"amount":10}', b'{"amount":10}',
            '{"amount":"10"}', b'{"amount":"10"}',
            "Type is part of the data: 10 and \"10\" must never be confused.",
        ),
        Case(
            "5a. Key order - raw bytes",
            "keys from,to,amount", raw_ab,
            "keys amount,to,from", raw_ba,
            "Same meaning, different bytes, different hashes.",
        ),
        Case(
            "5b. Key order - after canonical-json",
            "canonical(from,to,amount)", canonicalize(raw_ab),
            "canonical(amount,to,from)", canonicalize(raw_ba),
            "Canonicalisation sorts keys, so the hashes now match.",
        ),
    ]
