"""Merkle tree construction.

Specification (also in readme.md)
---------------------------------
H            SHA-256
Leaf hash    H(0x00 || data)
Node hash    H(0x01 || left || right)
Empty tree   root = H("")  (SHA-256 of zero bytes)
One leaf     root = leaf hash
Odd count    the last, unpaired node of a level is PROMOTED unchanged to the
             next level (it is NOT duplicated).

The 0x00 / 0x01 prefixes ("domain separation") make it impossible to pass an
internal node off as a leaf (a second-preimage attack). Promoting instead of
duplicating avoids Bitcoin's CVE-2012-2459, where [a, b, c] and [a, b, c, c]
have the same root. With these rules the tree is identical to the Merkle
tree of RFC 6962 (Certificate Transparency), so its published test vectors
apply.
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
HASH_LEN = 32
EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def next_level(level: Sequence[bytes]) -> list[bytes]:
    out = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
    if len(level) % 2:
        out.append(level[-1])          # promote the unpaired node
    return out


def expected_sides(index: int, size: int) -> list[str]:
    """The sibling directions a correct proof must have, bottom to top.

    Determined entirely by (index, size): at each level an odd position has
    its sibling on the left, an even position has it on the right, and an
    even position with no right neighbour is promoted (no sibling).
    """
    if size < 1:
        raise ValueError("tree_size must be at least 1")
    if not 0 <= index < size:
        raise ValueError(f"leaf_index {index} out of range for tree_size {size}")
    sides: list[str] = []
    i, n = index, size
    while n > 1:
        if i % 2 == 1:
            sides.append("left")
        elif i + 1 < n:
            sides.append("right")
        i //= 2
        n = (n + 1) // 2
    return sides


class MerkleTree:
    """Stores every level so proofs are produced without recomputation."""

    def __init__(self, leaves: Iterable[bytes]):
        level = [leaf_hash(d) for d in leaves]
        self.levels: list[list[bytes]] = [level]
        while len(level) > 1:
            level = next_level(level)
            self.levels.append(level)

    @classmethod
    def from_leaf_hashes(cls, hashes: Iterable[bytes]) -> "MerkleTree":
        t = cls.__new__(cls)
        level = list(hashes)
        if any(len(h) != HASH_LEN for h in level):
            raise ValueError("every leaf hash must be 32 bytes")
        t.levels = [level]
        while len(level) > 1:
            level = next_level(level)
            t.levels.append(level)
        return t

    @property
    def size(self) -> int:
        return len(self.levels[0])

    @property
    def root(self) -> bytes:
        return self.levels[-1][0] if self.size else EMPTY_ROOT

    @property
    def depth(self) -> int:
        return len(self.levels) - 1 if self.size else 0

    def prove(self, index: int):
        from .proof import Proof, Sibling

        if self.size == 0:
            raise ValueError("cannot prove inclusion in an empty tree")
        if not 0 <= index < self.size:
            raise ValueError(f"leaf_index {index} out of range for tree_size {self.size}")
        siblings = []
        i = index
        for level in self.levels[:-1]:
            if i % 2 == 1:
                siblings.append(Sibling("left", level[i - 1]))
            elif i + 1 < len(level):
                siblings.append(Sibling("right", level[i + 1]))
            i //= 2
        return Proof(index, self.size, tuple(siblings))

    def path_positions(self, index: int) -> list[tuple[int, int]]:
        """(level, position) of the leaf and every ancestor up to the root."""
        return [(lvl, index >> lvl) for lvl in range(len(self.levels))]
