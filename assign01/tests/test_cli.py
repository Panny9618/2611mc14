import json
import os
import subprocess
import sys

import pytest

from hashlab.cli import main

ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def run(capsys, *argv):
    rc = main(list(argv))
    out, err = capsys.readouterr()
    return rc, out, err


def test_text_output_format(capsys):
    rc, out, _ = run(capsys, "text", "abc")
    assert rc == 0
    assert out.splitlines() == ["bytes: 3", f"sha256: {ABC}", "sha256_base64: ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="]


def test_text_json(capsys):
    rc, out, _ = run(capsys, "text", "abc", "--json")
    assert json.loads(out) == {"bytes": 3, "sha256": ABC, "sha256_base64": "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="}


def test_hex_ok_and_malformed(capsys):
    assert run(capsys, "hex", "0x616263")[1].splitlines()[1] == f"sha256: {ABC}"
    rc, out, err = run(capsys, "hex", "61626")
    assert rc == 2 and out == "" and "malformed hex" in err


def test_file_and_missing_file(capsys, tmp_path):
    p = tmp_path / "abc.txt"
    p.write_bytes(b"abc")
    rc, out, _ = run(capsys, "file", str(p), "--json")
    assert rc == 0 and json.loads(out)["sha256"] == ABC
    rc, _, err = run(capsys, "file", str(tmp_path / "nope"))
    assert rc == 1 and "cannot read" in err


def test_file_stdin():
    r = subprocess.run([sys.executable, "-m", "hashlab", "file", "-", "--json"], input=b"abc", capture_output=True, check=True)
    assert json.loads(r.stdout)["sha256"] == ABC


def test_avalanche_example(capsys):
    rc, out, _ = run(capsys, "avalanche", "--text", "Alice pays Bob 10", "--bit", "7", "--json")
    d = json.loads(out)
    assert rc == 0
    assert (d["byte_before"], d["byte_after"]) == ("0x41", "0x40")
    assert 0 <= d["changed_bits_in_digest"] <= 256


def test_avalanche_errors(capsys):
    assert run(capsys, "avalanche", "--text", "A", "--bit", "8")[0] == 2
    assert run(capsys, "avalanche", "--text", "", "--bit", "0")[0] == 2
    assert run(capsys, "avalanche", "--hex", "zz", "--bit", "0")[0] == 2


def test_avalanche_sweep(capsys):
    rc, out, _ = run(capsys, "avalanche", "--hex", "00", "--sweep", "--json")
    assert rc == 0 and json.loads(out)["input_bits"] == 8


def test_canonical_json_file_and_output(capsys, tmp_path):
    src = tmp_path / "tx.json"
    src.write_text('{ "b": 1, "a": 2 }\n')
    dst = tmp_path / "tx.canon.json"
    rc, out, _ = run(capsys, "canonical-json", str(src), "-o", str(dst), "--json")
    assert rc == 0
    assert dst.read_bytes() == b'{"a":2,"b":1}'
    assert json.loads(out)["canonical"] == '{"a":2,"b":1}'


def test_canonical_json_rejects(capsys):
    rc, _, err = run(capsys, "canonical-json", "--string", '{"a":0.1}')
    assert rc == 2 and "R4" in err


def test_similar_runs(capsys):
    rc, out, _ = run(capsys, "similar", "--json")
    rows = json.loads(out)
    assert rc == 0 and len(rows) == 6
    assert [r["same_bytes"] for r in rows] == [False, False, False, False, False, True]


@pytest.mark.slow
def test_100mb_file_memory():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
    import memcheck
    r = memcheck.run(100)
    assert r["matches_hashlib"]
    assert r["external_tool_digest"] in (None, r["digest"])
    assert r["tracemalloc_peak_big"] < 16 * 1024 * 1024
    if r["rss_growth"] is not None:
        assert r["rss_growth"] < 16 * 1024 * 1024
