"""The committed test vectors must keep matching the implementation."""

import json
from pathlib import Path

from merklelab import MerkleTree, Proof, leaf_hash, verify

V = json.loads((Path(__file__).resolve().parent.parent / "vectors" / "five_tx.json").read_text())


def test_five_tx_levels_and_root():
    data = [s.encode() for s in V["leaves"]]
    t = MerkleTree(data)
    assert [leaf_hash(d).hex() for d in data] == V["leaf_hashes"]
    assert [[h.hex() for h in lv] for lv in t.levels] == V["levels"]
    assert t.root.hex() == V["root"]


def test_five_tx_proofs():
    data = [s.encode() for s in V["leaves"]]
    root = bytes.fromhex(V["root"])
    for i, pd in enumerate(V["proofs"]):
        p = Proof.from_dict(pd)
        assert p == MerkleTree(data).prove(i)
        verify(data[i], p, root)
