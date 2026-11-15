"""merklelab: a from-scratch Merkle tree with inclusion proofs.

Only SHA-256 (hashlib) is borrowed; the tree, proofs and verification are
implemented here.
"""

from .proof import Proof, ProofError, Sibling, verify
from .tree import EMPTY_ROOT, MerkleTree, expected_sides, leaf_hash, node_hash

__version__ = "1.0.0"
__all__ = [
    "EMPTY_ROOT", "MerkleTree", "Proof", "ProofError", "Sibling",
    "expected_sides", "leaf_hash", "node_hash", "verify",
]
