"""Canonical transaction format.

The JSON form is only a convenient container. What is signed is a fixed binary
layout (see docs/transaction_format.md), so key order, whitespace and number
spelling in the JSON cannot change the signed bytes.

    offset  size  field
    0       4     magic          "CTX" 0x00  (domain separation: only transactions use this prefix)
    4       1     version        u8, must be 1
    5       1     network_len    u8, length L of network_id (1..32)
    6       L     network_id     ASCII [a-z0-9-]
    6+L     21    sender         address version byte || 20-byte PKH
    27+L    21    recipient      address version byte || 20-byte PKH
    48+L    8     amount_units   u64 big-endian, 1 .. 2^64-1
    56+L    8     nonce          u64 big-endian, 0 .. 2^64-1
    64+L    32    memo_hash      SHA-256 of the memo (32 raw bytes)
    96+L          end            (110 bytes for "course-testnet")
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .address import NETWORKS, parse_address
from .errors import WalletError

MAGIC = b"CTX\x00"
TX_VERSION = 1
U64_MAX = 2**64 - 1
FIELDS = ("version", "network_id", "sender", "recipient", "amount_units", "nonce", "memo_hash")
_NET_RE = re.compile(r"[a-z0-9-]{1,32}")
_HASH_RE = re.compile(r"[0-9a-f]{64}")


def memo_hash(memo: str) -> str:
    return hashlib.sha256(memo.encode("utf-8")).hexdigest()


def strict_json(raw: str | bytes) -> Any:
    def no_dupes(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise WalletError(WalletError.MALFORMED, f"duplicate JSON key {k!r}")
            d[k] = v
        return d

    def no_float(s):
        raise WalletError(WalletError.MALFORMED, f"non-integer number {s} not allowed")

    def no_const(s):
        raise WalletError(WalletError.MALFORMED, f"{s} not allowed")

    try:
        return json.loads(raw, object_pairs_hook=no_dupes, parse_float=no_float, parse_constant=no_const)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise WalletError(WalletError.MALFORMED, f"invalid JSON: {e}") from None


def _int(obj: dict, name: str, lo: int, hi: int) -> int:
    v = obj[name]
    if not isinstance(v, int) or isinstance(v, bool):
        raise WalletError(WalletError.MALFORMED, f"{name} must be an integer, got {v!r}")
    if not lo <= v <= hi:
        raise WalletError(WalletError.MALFORMED, f"{name}={v} out of range [{lo}, {hi}]")
    return v


@dataclass(frozen=True)
class Transaction:
    version: int
    network_id: str
    sender: str
    recipient: str
    amount_units: int
    nonce: int
    memo_hash: str

    @classmethod
    def from_dict(cls, obj: Any) -> "Transaction":
        """Check JSON types and formats. Address validity is checked by to_bytes()."""
        if not isinstance(obj, dict):
            raise WalletError(WalletError.MALFORMED, "transaction must be a JSON object")
        if set(obj) != set(FIELDS):
            raise WalletError(WalletError.MALFORMED,
                              f"transaction fields must be exactly {list(FIELDS)} "
                              f"(missing={sorted(set(FIELDS) - set(obj))}, unexpected={sorted(set(obj) - set(FIELDS))})")
        version = _int(obj, "version", 0, 255)
        if version != TX_VERSION:
            raise WalletError(WalletError.MALFORMED, f"unsupported version {version}")
        net = obj["network_id"]
        if not isinstance(net, str) or not _NET_RE.fullmatch(net):
            raise WalletError(WalletError.MALFORMED, "network_id must be 1-32 chars of [a-z0-9-]")
        for f in ("sender", "recipient"):
            if not isinstance(obj[f], str):
                raise WalletError(WalletError.MALFORMED_ADDRESS, f"{f} must be a string")
        mh = obj["memo_hash"]
        if not isinstance(mh, str) or not _HASH_RE.fullmatch(mh):
            raise WalletError(WalletError.MALFORMED, "memo_hash must be 64 lowercase hex characters")
        return cls(version, net, obj["sender"], obj["recipient"],
                   _int(obj, "amount_units", 1, U64_MAX), _int(obj, "nonce", 0, U64_MAX), mh)

    @classmethod
    def from_json(cls, raw: str | bytes) -> "Transaction":
        return cls.from_dict(strict_json(raw))

    def to_dict(self) -> dict:
        return {f: getattr(self, f) for f in FIELDS}

    def canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def check_addresses(self) -> tuple:
        if self.network_id not in NETWORKS:
            raise WalletError(WalletError.WRONG_NETWORK, f"unknown network_id {self.network_id!r}")
        s = parse_address(self.sender, "sender")
        r = parse_address(self.recipient, "recipient")
        for name, a in (("sender", s), ("recipient", r)):
            if a.network != self.network_id:
                raise WalletError(WalletError.WRONG_NETWORK,
                                  f"{name} is a {a.network} address but network_id is {self.network_id}")
        return s, r

    def to_bytes(self) -> bytes:
        s, r = self.check_addresses()
        net = self.network_id.encode("ascii")
        return b"".join([
            MAGIC, bytes([self.version]), bytes([len(net)]), net, s.raw, r.raw,
            self.amount_units.to_bytes(8, "big"), self.nonce.to_bytes(8, "big"), bytes.fromhex(self.memo_hash),
        ])

    def txid(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    def layout(self) -> list[tuple[int, str, bytes, str]]:
        """(offset, field, bytes, meaning) rows for a byte-level dump."""
        b = self.to_bytes()
        L = len(self.network_id)
        spec = [("magic", 4, '"CTX\\0"'), ("version", 1, str(self.version)), ("network_len", 1, str(L)),
                ("network_id", L, self.network_id), ("sender", 21, self.sender), ("recipient", 21, self.recipient),
                ("amount_units", 8, f"{self.amount_units:,}"), ("nonce", 8, str(self.nonce)), ("memo_hash", 32, "SHA-256 of memo")]
        rows, off = [], 0
        for name, size, meaning in spec:
            rows.append((off, name, b[off:off + size], meaning))
            off += size
        return rows
