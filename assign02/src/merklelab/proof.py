"""Inclusion proofs: strict JSON (de)serialisation and verification.

JSON format (exactly these keys, nothing else):

    {
      "leaf_index": 2,
      "tree_size": 5,
      "siblings": [
        {"side": "right", "hash": "<64 lowercase hex>"},
        {"side": "left",  "hash": "<64 lowercase hex>"}
      ]
    }

"side" says where the sibling sits relative to the running hash:
    left  -> running = H(0x01 || sibling || running)
    right -> running = H(0x01 || running || sibling)
Siblings are ordered from the leaf level up to the root.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .tree import HASH_LEN, expected_sides, leaf_hash, node_hash

_HASH_RE = re.compile(r"[0-9a-f]{64}")
SIDES = ("left", "right")


class ProofError(ValueError):
    """Malformed or non-verifying proof. ``kind`` is 'malformed' or 'invalid'."""

    def __init__(self, msg: str, kind: str = "malformed"):
        super().__init__(msg)
        self.kind = kind


@dataclass(frozen=True)
class Sibling:
    side: str
    hash: bytes


@dataclass(frozen=True)
class Proof:
    leaf_index: int
    tree_size: int
    siblings: tuple[Sibling, ...]

    # ------------------------------------------------------------ serialise
    def to_dict(self) -> dict:
        return {
            "leaf_index": self.leaf_index,
            "tree_size": self.tree_size,
            "siblings": [{"side": s.side, "hash": s.hash.hex()} for s in self.siblings],
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    # ------------------------------------------------------------ parse
    @classmethod
    def from_json(cls, text: str | bytes) -> "Proof":
        def no_dupes(pairs):
            d = {}
            for k, v in pairs:
                if k in d:
                    raise ProofError(f"duplicate key {k!r}")
                d[k] = v
            return d

        try:
            obj = json.loads(text, object_pairs_hook=no_dupes)
        except ProofError:
            raise
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ProofError(f"proof is not valid JSON: {e}") from None
        return cls.from_dict(obj)

    @classmethod
    def from_dict(cls, obj: Any) -> "Proof":
        if not isinstance(obj, dict):
            raise ProofError("proof must be a JSON object")
        keys = set(obj)
        if keys != {"leaf_index", "tree_size", "siblings"}:
            missing = {"leaf_index", "tree_size", "siblings"} - keys
            extra = keys - {"leaf_index", "tree_size", "siblings"}
            raise ProofError(f"proof keys wrong (missing={sorted(missing)}, unexpected={sorted(extra)})")
        idx, size, sibs = obj["leaf_index"], obj["tree_size"], obj["siblings"]
        for name, v in (("leaf_index", idx), ("tree_size", size)):
            if not isinstance(v, int) or isinstance(v, bool):
                raise ProofError(f"{name} must be an integer, got {v!r}")
        if size < 1:
            raise ProofError(f"tree_size must be at least 1, got {size}")
        if not 0 <= idx < size:
            raise ProofError(f"wrong index: leaf_index {idx} is outside a tree of size {size}")
        if not isinstance(sibs, list):
            raise ProofError("siblings must be a list")
        parsed = []
        for n, s in enumerate(sibs):
            if not isinstance(s, dict) or set(s) != {"side", "hash"}:
                raise ProofError(f"sibling {n} must be an object with exactly 'side' and 'hash'")
            if s["side"] not in SIDES:
                raise ProofError(f"sibling {n} has invalid direction {s['side']!r} (use 'left' or 'right')")
            h = s["hash"]
            if not isinstance(h, str) or not _HASH_RE.fullmatch(h):
                raise ProofError(f"sibling {n} has malformed hash {h!r} (need 64 lowercase hex characters)")
            parsed.append(Sibling(s["side"], bytes.fromhex(h)))
        proof = cls(idx, size, tuple(parsed))
        proof.check_shape()
        return proof

    # ------------------------------------------------------------ structure
    def check_shape(self) -> None:
        """Reject proofs whose length or directions don't fit (leaf_index, tree_size)."""
        want = expected_sides(self.leaf_index, self.tree_size)
        got = [s.side for s in self.siblings]
        if len(got) > len(want):
            raise ProofError(
                f"proof too long: tree_size {self.tree_size}, leaf_index {self.leaf_index} "
                f"needs exactly {len(want)} siblings, got {len(got)}")
        if len(got) < len(want):
            raise ProofError(
                f"proof too short: needs {len(want)} siblings, got {len(got)}")
        for n, (g, w) in enumerate(zip(got, want)):
            if g != w:
                raise ProofError(
                    f"wrong index or direction: sibling {n} is {g!r} but leaf_index "
                    f"{self.leaf_index} in a tree of {self.tree_size} requires {w!r}")
        for s in self.siblings:
            if len(s.hash) != HASH_LEN:
                raise ProofError("sibling hash must be 32 bytes")

    def compute_root(self, leaf_data: bytes) -> bytes:
        h = leaf_hash(leaf_data)
        for s in self.siblings:
            h = node_hash(s.hash, h) if s.side == "left" else node_hash(h, s.hash)
        return h


def verify(leaf_data: bytes, proof: Proof, expected_root: bytes) -> None:
    """Return None if the proof is valid, otherwise raise ProofError.

    Uses only the leaf bytes, the proof and the expected root.
    """
    if len(expected_root) != HASH_LEN:
        raise ProofError("expected root must be 32 bytes")
    proof.check_shape()
    got = proof.compute_root(leaf_data)
    if got != expected_root:
        raise ProofError(
            f"root mismatch: proof leads to {got.hex()}, expected {expected_root.hex()}", kind="invalid")
