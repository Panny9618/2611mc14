import json

from chainlab.cli import main
from chainlab.crypto import save_key
from chainlab.measure import run as measure_run
from conftest import ALICE, BOB, MA


def run(capsys, *argv):
    rc = main([str(a) for a in argv])
    out, err = capsys.readouterr()
    return rc, out, err


def test_simulation_all_checks_pass(capsys, tmp_path):
    rc, out, _ = run(capsys, "simulate", "--out", tmp_path)
    assert rc == 0 and "[FAIL]" not in out and out.count("[PASS]") == 11
    for f in ("fork_log.md", "fork_diagram.svg", "header_dump.txt", "node.json"):
        assert (tmp_path / f).exists()


def test_cli_mine_fork_and_reorg(capsys, tmp_path):
    save_key(str(tmp_path / "ma.key.json"), MA)
    save_key(str(tmp_path / "alice.key.json"), ALICE)
    node = tmp_path / "node.json"
    assert run(capsys, "init", "--data", node, "--give", f"{ALICE.address}:110")[0] == 0
    rc, out, _ = run(capsys, "pay", "--data", node, "--key", tmp_path / "alice.key.json", "--to", BOB.address,
                     "--amount", 85, "--fee", 2)
    assert rc == 0 and "mempool" in out
    rc, out, _ = run(capsys, "mine", "--data", node, "--key", tmp_path / "ma.key.json", "--bits", 8)
    assert rc == 0 and "CONNECTED" in out and "block hash = SHA256(SHA256(header))" in out
    run(capsys, "mine", "--data", node, "--key", tmp_path / "ma.key.json", "--bits", 8)
    rc, out, _ = run(capsys, "mine", "--data", node, "--key", tmp_path / "ma.key.json", "--bits", 12, "--parent", "1")
    assert "REORG" in out
    rc, out, _ = run(capsys, "tree", "--data", node)
    assert "stale branch" in out and "active" in out
    rc, out, _ = run(capsys, "show", "--data", node, "--block", "0")
    assert "prev_hash" in out
    rc, out, _ = run(capsys, "status", "--data", node)
    assert "height   2" in out


def test_cli_submit_block_file(capsys, tmp_path):
    save_key(str(tmp_path / "ma.key.json"), MA)
    n1, n2, blk = tmp_path / "n1.json", tmp_path / "n2.json", tmp_path / "b.json"
    run(capsys, "init", "--data", n1, "--give", f"{ALICE.address}:5")
    run(capsys, "init", "--data", n2, "--give", f"{ALICE.address}:5")
    run(capsys, "mine", "--data", n1, "--key", tmp_path / "ma.key.json", "--bits", 8, "-o", blk)
    rc, out, _ = run(capsys, "submit", "--data", n2, "--block", blk)
    assert rc == 0 and "CONNECTED" in out
    d = json.loads(blk.read_text())
    d["header"]["nonce"] += 1
    blk.write_text(json.dumps(d))
    rc, out, _ = run(capsys, "submit", "--data", n2, "--block", blk)
    assert rc == 1 and ("BAD_POW" in out or "BAD_" in out)


def test_measure_small():
    rows = measure_run([(8, 200)], say=lambda *_: None)
    r = rows[0]
    assert r["expected"] == 256 and 0.7 < r["ratio"] < 1.3 and r["hashrate"] > 0
