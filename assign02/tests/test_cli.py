import json
from pathlib import Path

import pytest

from merklelab.cli import main

EX = Path(__file__).resolve().parent.parent / "examples" / "txs5.txt"
ROOT5 = json.loads((Path(__file__).resolve().parent.parent / "vectors" / "five_tx.json").read_text())["root"]


def run(capsys, *argv):
    rc = main([str(a) for a in argv])
    out, err = capsys.readouterr()
    return rc, out, err


def test_root(capsys):
    rc, out, _ = run(capsys, "root", EX, "--json")
    assert rc == 0 and json.loads(out) == {"tree_size": 5, "depth": 3, "root": ROOT5}


def test_prove_verify_roundtrip(capsys, tmp_path):
    proof = tmp_path / "p.json"
    assert run(capsys, "prove", EX, "--index", 2, "-o", proof)[0] == 0
    rc, out, _ = run(capsys, "verify", "--leaf", "Carol pays Dave 3", "--proof", proof, "--root", ROOT5)
    assert rc == 0 and out.startswith("VALID")


def test_verify_wrong_leaf_exit_1(capsys, tmp_path):
    proof = tmp_path / "p.json"
    run(capsys, "prove", EX, "--index", 2, "-o", proof)
    rc, out, _ = run(capsys, "verify", "--leaf", "Carol pays Dave 300", "--proof", proof, "--root", ROOT5)
    assert rc == 1 and "root mismatch" in out


def test_verify_malformed_proof_exit_2(capsys, tmp_path):
    proof = tmp_path / "p.json"
    run(capsys, "prove", EX, "--index", 2, "-o", proof)
    d = json.loads(proof.read_text())
    d["siblings"].append({"side": "right", "hash": "00" * 32})
    proof.write_text(json.dumps(d))
    rc, out, _ = run(capsys, "verify", "--leaf", "Carol pays Dave 3", "--proof", proof, "--root", ROOT5)
    assert rc == 2 and "too long" in out


def test_verify_bad_root_hex(capsys, tmp_path):
    proof = tmp_path / "p.json"
    run(capsys, "prove", EX, "--index", 2, "-o", proof)
    assert run(capsys, "verify", "--leaf", "x", "--proof", proof, "--root", "abc")[0] == 2
    assert run(capsys, "verify", "--leaf", "x", "--proof", proof, "--root", "ab" * 31)[0] == 2


def test_prove_index_out_of_range(capsys):
    rc, _, err = run(capsys, "prove", EX, "--index", 5)
    assert rc == 2 and "out of range" in err


def test_hex_leaves_and_leaf_hex(capsys, tmp_path):
    f = tmp_path / "h.txt"
    f.write_text("00\n0x10\n2021\n")
    proof = tmp_path / "p.json"
    rc, out, _ = run(capsys, "root", f, "--hex", "--json")
    root = json.loads(out)["root"]
    run(capsys, "prove", f, "--hex", "--index", 1, "-o", proof)
    assert run(capsys, "verify", "--leaf-hex", "10", "--proof", proof, "--root", root)[0] == 0
    f.write_text("0g\n")
    assert run(capsys, "root", f, "--hex")[0] == 2


def test_crlf_rejected_and_empty_file(capsys, tmp_path):
    f = tmp_path / "w.txt"
    f.write_bytes(b"a\r\nb\r\n")
    rc, _, err = run(capsys, "root", f)
    assert rc == 2 and "CR" in err
    f.write_bytes(b"")
    rc, out, _ = run(capsys, "root", f, "--json")
    assert json.loads(out)["tree_size"] == 0


def test_final_newline_optional(capsys, tmp_path):
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("x\ny\n")
    b.write_text("x\ny")
    assert run(capsys, "root", a)[1] == run(capsys, "root", b)[1]


def test_tree_marks_path(capsys):
    rc, out, _ = run(capsys, "tree", EX, "--index", 2)
    assert rc == 0
    assert "<== target leaf" in out and out.count("SIBLING") == 3


def test_bench_small(capsys):
    rc, out, _ = run(capsys, "bench", "--sizes", "8,33", "--proofs", "10")
    assert rc == 0 and "| 33 |" in out
