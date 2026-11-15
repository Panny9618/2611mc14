import hashlib
import json
from pathlib import Path

import pytest

from merklelab import EMPTY_ROOT, MerkleTree, ProofError, expected_sides, leaf_hash, node_hash, verify

VEC = Path(__file__).resolve().parent.parent / "vectors"


def leaves(n):
    return [f"tx{i}".encode() for i in range(n)]


# ---------------------------------------------------------------- spec

def test_domain_separated_hashes():
    assert leaf_hash(b"abc") == hashlib.sha256(b"\x00abc").digest()
    l, r = b"L" * 32, b"R" * 32
    assert node_hash(l, r) == hashlib.sha256(b"\x01" + l + r).digest()
    assert node_hash(l, r) != node_hash(r, l)          # order matters


def test_rfc6962_reference_roots():
    v = json.loads((VEC / "rfc6962_roots.json").read_text())
    data = [bytes.fromhex(h) for h in v["leaves_hex"]]
    for row in v["roots"]:
        assert MerkleTree(data[: row["tree_size"]]).root.hex() == row["root"]


def test_zero_leaves():
    t = MerkleTree([])
    assert t.size == 0 and t.root == EMPTY_ROOT and t.depth == 0
    with pytest.raises(ValueError):
        t.prove(0)


def test_one_leaf_root_is_leaf_hash():
    t = MerkleTree([b"only"])
    assert t.root == leaf_hash(b"only")
    assert t.prove(0).siblings == ()


def test_two_and_four_leaves_by_hand():
    a, b, c, d = (leaf_hash(x) for x in (b"a", b"b", b"c", b"d"))
    assert MerkleTree([b"a", b"b"]).root == node_hash(a, b)
    assert MerkleTree([b"a", b"b", b"c", b"d"]).root == node_hash(node_hash(a, b), node_hash(c, d))


def test_odd_leaves_promote_not_duplicate():
    a, b, c = (leaf_hash(x) for x in (b"a", b"b", b"c"))
    assert MerkleTree([b"a", b"b", b"c"]).root == node_hash(node_hash(a, b), c)
    # Bitcoin-style duplication would make these equal (CVE-2012-2459); ours does not.
    assert MerkleTree([b"a", b"b", b"c"]).root != MerkleTree([b"a", b"b", b"c", b"c"]).root


def test_five_leaves_by_hand():
    h = [leaf_hash(x) for x in (b"0", b"1", b"2", b"3", b"4")]
    expected = node_hash(node_hash(node_hash(h[0], h[1]), node_hash(h[2], h[3])), h[4])
    assert MerkleTree([b"0", b"1", b"2", b"3", b"4"]).root == expected


def test_internal_node_cannot_pose_as_leaf():
    t = MerkleTree([b"a", b"b"])
    forged = leaf_hash(b"a") + leaf_hash(b"b")       # the 64 bytes hashed inside the root node
    assert MerkleTree([forged]).root != t.root       # differs only because of 0x00 vs 0x01 prefix
    assert leaf_hash(forged) != node_hash(leaf_hash(b"a"), leaf_hash(b"b"))


def test_order_of_leaves_matters():
    assert MerkleTree([b"a", b"b"]).root != MerkleTree([b"b", b"a"]).root


def test_from_leaf_hashes_matches():
    data = leaves(7)
    assert MerkleTree.from_leaf_hashes([leaf_hash(d) for d in data]).root == MerkleTree(data).root
    with pytest.raises(ValueError):
        MerkleTree.from_leaf_hashes([b"short"])


# ---------------------------------------------------------------- proofs, exhaustively

@pytest.mark.parametrize("n", list(range(1, 34)) + [100, 255, 256, 257, 1000])
def test_every_proof_verifies(n):
    data = leaves(n)
    t = MerkleTree(data)
    for i in range(n):
        p = t.prove(i)
        assert [s.side for s in p.siblings] == expected_sides(i, n)
        verify(data[i], p, t.root)


@pytest.mark.parametrize("n", [2, 5, 8, 13])
def test_proof_fails_for_other_leaves(n):
    data = leaves(n)
    t = MerkleTree(data)
    for i in range(n):
        p = t.prove(i)
        for j in range(n):
            if j != i:
                with pytest.raises(ProofError):
                    verify(data[j], p, t.root)


def test_expected_sides_examples():
    assert expected_sides(2, 5) == ["right", "left", "right"]
    assert expected_sides(4, 5) == ["left"]
    assert expected_sides(0, 1) == []
    assert expected_sides(7, 8) == ["left", "left", "left"]
    with pytest.raises(ValueError):
        expected_sides(5, 5)


def test_proof_length_at_most_ceil_log2():
    import math
    for n in (3, 5, 1000, 4097):
        t = MerkleTree(leaves(n))
        assert t.depth == math.ceil(math.log2(n))
        assert all(len(t.prove(i).siblings) <= t.depth for i in range(0, n, max(1, n // 50)))
