"""Base58 and Base58Check (Bitcoin alphabet).

This is a text encoding, not cryptography, so it is implemented here.
Base58 drops 0, O, I and l so addresses are hard to misread.
Base58Check appends the first 4 bytes of SHA-256(SHA-256(payload)) as a
checksum, so a single mistyped character is detected.
"""

from __future__ import annotations

import hashlib

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(ALPHABET)}


class Base58Error(ValueError):
    pass


class ChecksumError(Base58Error):
    pass


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = []
    while n:
        n, r = divmod(n, 58)
        out.append(ALPHABET[r])
    pad = len(data) - len(data.lstrip(b"\x00"))   # each leading 0x00 byte -> '1'
    return "1" * pad + "".join(reversed(out))


def b58decode(s: str) -> bytes:
    n = 0
    for pos, c in enumerate(s):
        if c not in _INDEX:
            raise Base58Error(f"invalid Base58 character {c!r} at position {pos}")
        n = n * 58 + _INDEX[c]
    pad = len(s) - len(s.lstrip("1"))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + body


def checksum(payload: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]


def b58check_encode(payload: bytes) -> str:
    return b58encode(payload + checksum(payload))


def b58check_decode(s: str) -> bytes:
    raw = b58decode(s)
    if len(raw) < 5:
        raise Base58Error("too short to contain a checksum")
    payload, chk = raw[:-4], raw[-4:]
    if checksum(payload) != chk:
        raise ChecksumError(f"checksum mismatch (expected {checksum(payload).hex()}, found {chk.hex()})")
    return payload
