import json
import os

from toywallet.cli import main


def run(capsys, *argv):
    rc = main([str(a) for a in argv])
    out, err = capsys.readouterr()
    return rc, out, err


def test_full_flow(capsys, tmp_path):
    d = tmp_path / "keys"
    assert run(capsys, "keygen", "--name", "alice", "--dir", d)[0] == 0
    rc, out, _ = run(capsys, "keygen", "--name", "bob", "--dir", d)
    bob = json.loads(out)["address"]
    assert "private_key" not in out                                   # only public data printed
    tx = tmp_path / "tx.json"
    assert run(capsys, "tx", "--from", d / "alice.pub.json", "--to", bob, "--amount", 1250000,
               "--nonce", 7, "--memo", "rent", "-o", tx)[0] == 0
    signed = tmp_path / "signed.json"
    assert run(capsys, "sign", "--key", d / "alice.key.json", "--tx", tx, "-o", signed, "--yes")[0] == 0
    state = tmp_path / "state.json"
    rc, out, _ = run(capsys, "verify", "--signed", signed, "--nonces", state, "--record")
    assert rc == 0 and out.startswith("VALID")
    rc, out, _ = run(capsys, "verify", "--signed", signed, "--nonces", state)
    assert rc == 1 and "REPLAYED_NONCE" in out
    rc, out, _ = run(capsys, "verify", "--signed", signed, "--network", "course-mainnet")
    assert rc == 1 and "WRONG_NETWORK" in out
    rc, out, _ = run(capsys, "bytes", "--tx", signed)
    assert "total bytes   : 110" in out


def test_keygen_refuses_overwrite(capsys, tmp_path):
    run(capsys, "keygen", "--name", "a", "--dir", tmp_path)
    rc, _, err = run(capsys, "keygen", "--name", "a", "--dir", tmp_path)
    assert rc == 2 and "refusing to overwrite" in err


def test_sign_non_interactive_needs_yes(capsys, tmp_path, monkeypatch):
    run(capsys, "keygen", "--name", "a", "--dir", tmp_path)
    _, out, _ = run(capsys, "keygen", "--name", "b", "--dir", tmp_path)
    tx = tmp_path / "tx.json"
    run(capsys, "tx", "--from", tmp_path / "a.pub.json", "--to", json.loads(out)["address"],
        "--amount", 5, "--nonce", 0, "--memo", "", "-o", tx)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    rc, _, err = run(capsys, "sign", "--key", tmp_path / "a.key.json", "--tx", tx)
    assert rc == 2 and "--yes" in err


def test_sign_interactive_confirmation(capsys, tmp_path, monkeypatch):
    run(capsys, "keygen", "--name", "a", "--dir", tmp_path)
    _, out, _ = run(capsys, "keygen", "--name", "b", "--dir", tmp_path)
    bob = json.loads(out)["address"]
    tx = tmp_path / "tx.json"
    run(capsys, "tx", "--from", tmp_path / "a.pub.json", "--to", bob, "--amount", 5, "--nonce", 0, "--memo", "", "-o", tx)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _: "WRONG!")
    assert run(capsys, "sign", "--key", tmp_path / "a.key.json", "--tx", tx)[0] == 2
    monkeypatch.setattr("builtins.input", lambda _: bob[-6:])
    rc, out, _ = run(capsys, "sign", "--key", tmp_path / "a.key.json", "--tx", tx)
    assert rc == 0 and '"signature"' in out


def test_address_commands(capsys, tmp_path):
    run(capsys, "keygen", "--name", "a", "--dir", tmp_path)
    rc, out, _ = run(capsys, "address", "--pub", tmp_path / "a.pub.json")
    assert rc == 0 and "valid      : yes" in out
    addr = json.loads((tmp_path / "a.pub.json").read_text())["address"]
    assert run(capsys, "address", "--check", addr)[0] == 0
    rc, _, err = run(capsys, "address", "--check", addr[:-1] + ("2" if addr[-1] != "2" else "3"))
    assert rc == 2 and "INVALID_CHECKSUM" in err
    rc, out, _ = run(capsys, "address", "--pub", tmp_path / "a.pub.json", "--network", "course-mainnet")
    assert "address    : 1" in out


def test_tx_rejects_bad_recipient(capsys, tmp_path):
    run(capsys, "keygen", "--name", "a", "--dir", tmp_path)
    rc, _, err = run(capsys, "tx", "--from", tmp_path / "a.pub.json", "--to", "1111111111111111111114oLvT2",
                     "--amount", 5, "--nonce", 0, "--memo", "")
    assert rc == 2 and "WRONG_NETWORK" in err       # a mainnet address in a testnet tx
