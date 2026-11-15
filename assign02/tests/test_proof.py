import copy
import json
from pathlib import Path

import pytest

from merklelab import MerkleTree, Proof, ProofError, verify

DATA = [line.encode() for line in (Path(__file__).resolve().parent.parent / "examples" / "txs5.txt").read_text().splitlines()]
TREE = MerkleTree(DATA)
ROOT = TREE.root
GOOD = TREE.prove(2).to_dict()
H = "ab" * 32


def parse(d):
    return Proof.from_json(json.dumps(d))


def mutate(fn):
    d = copy.deepcopy(GOOD)
    fn(d)
    return d


def test_roundtrip_json():
    p = TREE.prove(2)
    assert Proof.from_json(p.to_json()) == p
    assert Proof.from_json(p.to_json(indent=None)) == p
    verify(DATA[2], Proof.from_json(p.to_json()), ROOT)


def test_example_shape_matches_assignment():
    assert set(GOOD) == {"leaf_index", "tree_size", "siblings"}
    assert GOOD["leaf_index"] == 2 and GOOD["tree_size"] == 5
    assert [s["side"] for s in GOOD["siblings"]] == ["right", "left", "right"]


# ---------------------------------------------------------------- malformed hashes
@pytest.mark.parametrize("bad", ["ab" * 31, "ab" * 33, "AB" * 32, "zz" * 32, "0x" + "ab" * 31, "", 123, None, ["ab"]])
def test_malformed_hash_rejected(bad):
    with pytest.raises(ProofError, match="malformed hash"):
        parse(mutate(lambda d: d["siblings"][0].__setitem__("hash", bad)))


# ---------------------------------------------------------------- invalid directions
@pytest.mark.parametrize("bad", ["up", "LEFT", "Right", "", None, 0, "l"])
def test_invalid_direction_rejected(bad):
    with pytest.raises(ProofError, match="invalid direction"):
        parse(mutate(lambda d: d["siblings"][1].__setitem__("side", bad)))


def test_swapped_direction_rejected():
    with pytest.raises(ProofError, match="wrong index or direction"):
        parse(mutate(lambda d: d["siblings"][0].__setitem__("side", "left")))


# ---------------------------------------------------------------- wrong indexes
@pytest.mark.parametrize("idx", [5, 6, 100, -1])
def test_index_out_of_range(idx):
    with pytest.raises(ProofError, match="wrong index"):
        parse(mutate(lambda d: d.__setitem__("leaf_index", idx)))


@pytest.mark.parametrize("idx", [0, 1, 3, 4])
def test_other_index_with_same_siblings_rejected(idx):
    with pytest.raises(ProofError):
        verify(DATA[2], parse(mutate(lambda d: d.__setitem__("leaf_index", idx))), ROOT)


def test_wrong_tree_size_rejected():
    with pytest.raises(ProofError):
        verify(DATA[2], parse(mutate(lambda d: d.__setitem__("tree_size", 4))), ROOT)
    with pytest.raises(ProofError):
        parse(mutate(lambda d: d.__setitem__("tree_size", 0)))


@pytest.mark.parametrize("bad", [True, 2.0, "2", None])
def test_index_must_be_int(bad):
    with pytest.raises(ProofError, match="integer"):
        parse(mutate(lambda d: d.__setitem__("leaf_index", bad)))


# ---------------------------------------------------------------- length
def test_unnecessarily_long_proof_rejected():
    with pytest.raises(ProofError, match="too long"):
        parse(mutate(lambda d: d["siblings"].append({"side": "right", "hash": H})))


def test_short_proof_rejected():
    with pytest.raises(ProofError, match="too short"):
        parse(mutate(lambda d: d["siblings"].pop()))


def test_padding_attack_on_full_tree_rejected():
    t = MerkleTree(DATA[:4])
    d = t.prove(0).to_dict()
    d["siblings"].append({"side": "right", "hash": H})
    with pytest.raises(ProofError, match="too long"):
        parse(d)


# ---------------------------------------------------------------- structure
@pytest.mark.parametrize("text", [
    "[]", "null", "5", "not json", '{"leaf_index":2,"tree_size":5}',
    '{"leaf_index":2,"tree_size":5,"siblings":[],"extra":1}',
    '{"leaf_index":2,"leaf_index":2,"tree_size":5,"siblings":[]}',
    '{"leaf_index":2,"tree_size":5,"siblings":{}}',
    '{"leaf_index":2,"tree_size":5,"siblings":[{"side":"right"}]}',
    '{"leaf_index":2,"tree_size":5,"siblings":[{"side":"right","hash":"%s","x":1}]}' % H,
])
def test_structural_garbage_rejected(text):
    with pytest.raises(ProofError):
        Proof.from_json(text)


# ---------------------------------------------------------------- semantic
def test_wrong_leaf_root_or_sibling_fails():
    p = parse(GOOD)
    with pytest.raises(ProofError, match="root mismatch"):
        verify(b"Carol pays Dave 300", p, ROOT)
    with pytest.raises(ProofError, match="root mismatch"):
        verify(DATA[2], p, bytes(32))
    tampered = parse(mutate(lambda d: d["siblings"][2].__setitem__("hash", H)))
    with pytest.raises(ProofError, match="root mismatch") as e:
        verify(DATA[2], tampered, ROOT)
    assert e.value.kind == "invalid"


def test_reordered_siblings_fail():
    d = mutate(lambda d: d["siblings"].reverse())
    with pytest.raises(ProofError):
        verify(DATA[2], parse(d), ROOT)
