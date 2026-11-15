import json

from conftest import ALICE, BOB
from utxolab.cli import main
from utxolab.crypto import save_key
from utxolab.ledger import Ledger


def run(capsys, *argv):
    rc = main([str(a) for a in argv])
    out, err = capsys.readouterr()
    return rc, out, err


def test_scenario_all_as_expected(capsys, tmp_path):
    rc, out, _ = run(capsys, "scenario", "--out", tmp_path)
    assert rc == 0 and "UNEXPECTED" not in out
    recs = [json.loads(line) for line in (tmp_path / "trace.jsonl").read_text().splitlines()]
    assert len(recs) == 17 and sum(r["result"] == "ACCEPTED" for r in recs) == 3
    assert all(r["state_unchanged"] for r in recs if r["result"] == "REJECTED")
    snaps = sorted((tmp_path / "snapshots").glob("*.json"))
    assert len(snaps) == 5
    final = Ledger.load(str(snaps[-1]))
    assert final.total_value() == 154 and final.total_fees == 6


def test_cli_init_pay_submit(capsys, tmp_path):
    save_key(str(tmp_path / "alice.key.json"), ALICE)
    st, tx, trace = tmp_path / "state.json", tmp_path / "tx.json", tmp_path / "trace.jsonl"
    assert run(capsys, "init", "--state", st, "--give", f"{ALICE.address}:40", "--give", f"{ALICE.address}:70")[0] == 0
    rc, _, err = run(capsys, "pay", "--state", st, "--key", tmp_path / "alice.key.json", "--to", BOB.address,
                     "--amount", 85, "--fee", 2, "-o", tx)
    assert rc == 0 and "change 23" in err
    rc, out, _ = run(capsys, "submit", "--state", st, "--tx", tx, "--expect-fee", 2, "--trace", trace)
    assert rc == 0 and out.startswith("ACCEPTED")
    rc, out, _ = run(capsys, "submit", "--state", st, "--tx", tx, "--trace", trace)
    assert rc == 1 and "DOUBLE_SPEND" in out and "(unchanged)" in out
    assert len(trace.read_text().splitlines()) == 2
    rc, out, _ = run(capsys, "balance", "--state", st)
    assert "85" in out and "23" in out and "= genesis 110" in out


def test_cli_rejects_malformed_tx_file(capsys, tmp_path):
    st, tx = tmp_path / "state.json", tmp_path / "tx.json"
    run(capsys, "init", "--state", st, "--give", f"{ALICE.address}:40")
    tx.write_text('{"version": 1, "inputs": [], "outputs": [], "extra": true}')
    rc, out, _ = run(capsys, "submit", "--state", st, "--tx", tx)
    assert rc == 1 and "MALFORMED" in out


def test_cli_init_refuses_overwrite_and_bad_address(capsys, tmp_path):
    st = tmp_path / "state.json"
    run(capsys, "init", "--state", st, "--give", f"{ALICE.address}:40")
    assert run(capsys, "init", "--state", st, "--give", f"{ALICE.address}:40")[0] == 2
    assert run(capsys, "init", "--state", tmp_path / "x.json", "--give", "notanaddress:5")[0] == 2
