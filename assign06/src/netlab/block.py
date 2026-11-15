"""Block headers, blocks, Merkle roots and toy proof of work.

Header (116 bytes, big-endian), hashed with double SHA-256:

    offset size field
         0    4 version          u32 = 1
         4   32 prev_hash        hash of the parent header
        36   32 merkle_root      root over the block's txids (Assignment 2 tree)
        68    8 timestamp        u64 seconds since the Unix epoch
        76   32 target           full 256-bit target (no compact "bits" encoding)
       108    8 nonce            u64, varied by the miner

A header is valid proof of work when  int(block_hash) <= target.
Expected attempts = 2^256 / (target + 1);  block work = floor(2^256 / (target + 1)).

Toy rule: each block declares its own target, which must be in [1, POW_LIMIT].
A real chain fixes the target with a retargeting rule; letting the miner choose
(within the limit) lets us build "fewer but harder blocks" cheaply. Work is
credited from the declared target, so the fork choice is still most-work.

Merkle tree (same as Assignment 2 / RFC 6962): leaf = SHA256(0x00 || txid),
node = SHA256(0x01 || left || right), an unpaired node is promoted.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Callable

from .tx import Transaction, TxFormatError

VERSION = 1
HEADER_LEN = 116
POW_LIMIT = (1 << 248) - 1            # easiest allowed target: at least 8 leading zero bits
NULL_HASH = bytes(32)
MAX_BLOCK_TXS = 1000


def target_for_bits(zero_bits: int) -> int:
    """Target whose hashes need `zero_bits` leading zero bits (expected 2^zero_bits attempts)."""
    if not 8 <= zero_bits <= 255:
        raise ValueError("zero_bits must be between 8 and 255")
    return (1 << (256 - zero_bits)) - 1


def bits_of(target: int) -> float:
    import math
    return 256 - math.log2(target + 1)


def work_of(target: int) -> int:
    return (1 << 256) // (target + 1)


def dsha(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


# --------------------------------------------------------------------------- Merkle

def merkle_root(txids: list[bytes]) -> bytes:
    if not txids:
        return hashlib.sha256(b"").digest()
    level = [hashlib.sha256(b"\x00" + t).digest() for t in txids]
    while len(level) > 1:
        nxt = [hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest() for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


# --------------------------------------------------------------------------- header

@dataclass(frozen=True)
class Header:
    version: int
    prev_hash: bytes
    merkle_root: bytes
    timestamp: int
    target: int
    nonce: int

    def prefix(self) -> bytes:
        """Everything except the nonce (lets the miner reuse a hash state)."""
        return (self.version.to_bytes(4, "big") + self.prev_hash + self.merkle_root
                + self.timestamp.to_bytes(8, "big") + self.target.to_bytes(32, "big"))

    def to_bytes(self) -> bytes:
        return self.prefix() + self.nonce.to_bytes(8, "big")

    @property
    def hash(self) -> bytes:
        return dsha(self.to_bytes())

    @property
    def hash_hex(self) -> str:
        return self.hash.hex()

    def meets_target(self) -> bool:
        return int.from_bytes(self.hash, "big") <= self.target

    @property
    def work(self) -> int:
        return work_of(self.target)

    def to_dict(self) -> dict:
        return {"version": self.version, "prev_hash": self.prev_hash.hex(), "merkle_root": self.merkle_root.hex(),
                "timestamp": self.timestamp, "target": f"{self.target:064x}", "nonce": self.nonce}

    def dump(self) -> str:
        """Annotated hex dump of the 116 header bytes."""
        b = self.to_bytes()
        rows = [(0, 4, "version", str(self.version)), (4, 32, "prev_hash", ""), (36, 32, "merkle_root", ""),
                (68, 8, "timestamp", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.timestamp))),
                (76, 32, "target", f"{bits_of(self.target):.1f} leading zero bits"), (108, 8, "nonce", f"{self.nonce:,}")]
        out = [f"{'off':>4} {'len':>3}  {'field':<12} hex"]
        for off, ln, name, note in rows:
            hx = b[off:off + ln].hex()
            out.append(f"{off:>4} {ln:>3}  {name:<12} {hx}" + (f"   ({note})" if note else ""))
        out.append(f"\nheader bytes ({len(b)}): {b.hex()}")
        out.append(f"block hash = SHA256(SHA256(header)) = {self.hash_hex}")
        out.append(f"hash <= target ? {self.meets_target()}   work = {self.work:,}")
        return "\n".join(out)


@dataclass(frozen=True)
class Block:
    header: Header
    txs: tuple[Transaction, ...]

    @property
    def hash(self) -> str:
        return self.header.hash_hex

    def computed_merkle_root(self) -> bytes:
        return merkle_root([bytes.fromhex(t.txid) for t in self.txs])

    def to_dict(self) -> dict:
        return {"hash": self.hash, "header": self.header.to_dict(), "transactions": [t.to_dict() for t in self.txs]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, d: Any) -> "Block":
        try:
            h = d["header"]
            if set(h) != {"version", "prev_hash", "merkle_root", "timestamp", "target", "nonce"}:
                raise ValueError("header fields")
            header = Header(int(h["version"]), bytes.fromhex(h["prev_hash"]), bytes.fromhex(h["merkle_root"]),
                            int(h["timestamp"]), int(h["target"], 16), int(h["nonce"]))
            if len(header.prev_hash) != 32 or len(header.merkle_root) != 32:
                raise ValueError("hash length")
            txs = tuple(Transaction.from_dict(t) for t in d["transactions"])
        except (KeyError, TypeError, ValueError, TxFormatError) as e:
            raise ValueError(f"malformed block: {e}") from None
        return cls(header, txs)

    @classmethod
    def from_json(cls, raw: str | bytes) -> "Block":
        return cls.from_dict(json.loads(raw))


# --------------------------------------------------------------------------- mining

@dataclass(frozen=True)
class MineResult:
    block: Block
    attempts: int
    seconds: float

    @property
    def hashrate(self) -> float:
        return self.attempts / self.seconds if self.seconds > 0 else float("inf")


def mine(prev_hash: bytes, txs: list[Transaction], target: int, timestamp: int,
         start_nonce: int = 0, max_attempts: int | None = None,
         progress: Callable[[int], None] | None = None) -> MineResult:
    """Vary the nonce until double-SHA256(header) <= target."""
    if not 1 <= target <= POW_LIMIT:
        raise ValueError("target out of range")
    root = merkle_root([bytes.fromhex(t.txid) for t in txs])
    base = Header(VERSION, prev_hash, root, timestamp, target, 0)
    state = hashlib.sha256(base.prefix())
    t0 = time.perf_counter()
    nonce = start_nonce
    limit = 2**64 if max_attempts is None else start_nonce + max_attempts
    sha = hashlib.sha256
    while nonce < limit:
        s = state.copy()
        s.update(nonce.to_bytes(8, "big"))
        if int.from_bytes(sha(s.digest()).digest(), "big") <= target:
            hdr = Header(VERSION, prev_hash, root, timestamp, target, nonce)
            return MineResult(Block(hdr, tuple(txs)), nonce - start_nonce + 1, time.perf_counter() - t0)
        nonce += 1
        if progress and nonce % 1_000_000 == 0:
            progress(nonce - start_nonce)
    raise RuntimeError("nonce space exhausted")
