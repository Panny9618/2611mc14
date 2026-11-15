"""Byte handling and SHA-256 helpers.

SHA-256 itself comes from Python's standard library (hashlib, backed by
OpenSSL). This module only decides *which bytes* get hashed.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from typing import BinaryIO, Iterable

CHUNK_SIZE = 1024 * 1024  # 1 MiB: memory use stays constant whatever the file size
DIGEST_BITS = 256

_HEX_RE = re.compile(r"[0-9a-fA-F]*")


class HexError(ValueError):
    """Raised when a hexadecimal byte string is malformed."""


@dataclass(frozen=True)
class Digest:
    """SHA-256 result plus the number of input bytes."""

    length: int
    raw: bytes

    @property
    def hex(self) -> str:
        return self.raw.hex()

    @property
    def b64(self) -> str:
        return base64.b64encode(self.raw).decode("ascii")

    def as_dict(self) -> dict:
        return {"bytes": self.length, "sha256": self.hex, "sha256_base64": self.b64}


# --------------------------------------------------------------------------- input -> bytes

def text_to_bytes(text: str) -> bytes:
    """Encode text as UTF-8 exactly as given.

    No newline is added and no Unicode normalisation is applied: the caller
    sees the hash of precisely the characters they supplied.
    """
    return text.encode("utf-8")


def parse_hex(s: str) -> bytes:
    """Strictly parse a hexadecimal byte string.

    Rules (documented in readme.md):
      * an optional leading ``0x`` / ``0X`` prefix is allowed;
      * every remaining character must be 0-9, a-f or A-F (no spaces, no separators);
      * the number of hex digits must be even (whole bytes only);
      * the empty string is valid and means zero bytes.
    """
    body = s[2:] if s[:2] in ("0x", "0X") else s
    if not _HEX_RE.fullmatch(body):
        bad = next(c for c in body if c not in "0123456789abcdefABCDEF")
        raise HexError(f"invalid hex character {bad!r}")
    if len(body) % 2:
        raise HexError(f"odd number of hex digits ({len(body)}); each byte needs two digits")
    return bytes.fromhex(body)


# --------------------------------------------------------------------------- hashing

def digest_bytes(data: bytes) -> Digest:
    return Digest(len(data), hashlib.sha256(data).digest())


def digest_chunks(chunks: Iterable[bytes]) -> Digest:
    h = hashlib.sha256()
    n = 0
    for chunk in chunks:
        h.update(chunk)
        n += len(chunk)
    return Digest(n, h.digest())


def iter_stream(stream: BinaryIO, chunk_size: int = CHUNK_SIZE) -> Iterable[bytes]:
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            return
        yield chunk


def digest_file(path: str, chunk_size: int = CHUNK_SIZE) -> Digest:
    """Hash a file in fixed-size chunks; never loads the whole file."""
    with open(path, "rb") as f:
        return digest_chunks(iter_stream(f, chunk_size))


# --------------------------------------------------------------------------- avalanche

def flip_bit(data: bytes, bit: int) -> bytes:
    """Return a copy of ``data`` with one bit inverted.

    Bit numbering: bit ``i`` lives in byte ``i // 8``; inside a byte bit 0 is
    the most significant bit (MSB-first, the order you read a byte in binary).
    So bit 7 of b"A" (0x41 = 0100_0001) is the last 1, giving 0x40 = "@".
    """
    total = len(data) * 8
    if total == 0:
        raise ValueError("cannot flip a bit of an empty input")
    if not 0 <= bit < total:
        raise ValueError(f"bit {bit} out of range; input has {total} bits (0..{total - 1})")
    buf = bytearray(data)
    buf[bit // 8] ^= 0x80 >> (bit % 8)
    return bytes(buf)


def hamming_distance(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError("Hamming distance needs equal-length inputs")
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


@dataclass(frozen=True)
class AvalancheResult:
    bit: int
    original_bytes: bytes
    flipped_bytes: bytes
    original: Digest
    flipped: Digest

    @property
    def changed_bits(self) -> int:
        return hamming_distance(self.original.raw, self.flipped.raw)


def avalanche(data: bytes, bit: int) -> AvalancheResult:
    flipped = flip_bit(data, bit)
    return AvalancheResult(bit, data, flipped, digest_bytes(data), digest_bytes(flipped))
