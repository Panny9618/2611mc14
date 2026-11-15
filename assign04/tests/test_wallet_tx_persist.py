import json

import pytest

from conftest import ALICE, BOB, CAROL
from utxolab.ledger import Ledger
from utxolab.tx import OutPoint, Transaction, TxFormatError, TxIn, TxOut
from utxolab.wallet import InsufficientFunds, build_payment, select_coins


# ------------------------------------------------------------------ coin selection
def test_largest_first_is_deterministic():
    utxos = {OutPoint("bb" * 32, 0): TxOut(10, b"x" * 20), OutPoint("aa" * 32, 1): TxOut(30, b"x" * 20),
             OutPoint("aa" * 32, 0): TxOut(30, b"x" * 20), OutPoint("cc" * 32, 0): TxOut(5, b"x" * 20)}
    picked = select_coins(utxos, 55)
    assert [(op.txid[:2], op.index, o.value) for op, o in picked] == [("aa", 0, 30), ("aa", 1, 30)]
    assert picked == select_coins(dict(reversed(list(utxos.items()))), 55)       # order-independent


def test_insufficient_funds(led):
    with pytest.raises(InsufficientFunds):
        build_payment(led, ALICE, BOB.pkh, 109, 2)


def test_exact_amount_has_no_change(led):
    p = build_payment(led, ALICE, BOB.pkh, 108, 2)
    assert p.change == 0 and len(p.tx.outputs) == 1


def test_single_coin_when_enough(led):
    p = build_payment(led, ALICE, BOB.pkh, 60, 2)
    assert [o.value for _, o in p.selected] == [70] and p.change == 8


# ------------------------------------------------------------------ txid and serialisation
def test_txid_from_canonical_bytes_excludes_signatures(led):
    t1 = build_payment(led, ALICE, BOB.pkh, 85, 2).tx
    t2 = build_payment(led, ALICE, BOB.pkh, 85, 2).tx          # fresh random ECDSA nonces
    assert t1.inputs[0].unlock != t2.inputs[0].unlock
    assert t1.txid == t2.txid


def test_json_roundtrip_and_formatting_independent(led):
    tx = build_payment(led, ALICE, BOB.pkh, 85, 2).tx
    d = tx.to_dict()
    again = Transaction.from_json(json.dumps({"outputs": d["outputs"], "inputs": d["inputs"], "version": 1}, indent=7))
    assert again == tx and again.txid == tx.txid


def test_body_layout():
    tx = Transaction((TxIn(OutPoint("11" * 32, 3)),), (TxOut(85, b"\x22" * 20),))
    b = tx.body()
    assert b[:4] == b"UTX\x00" and b[4] == 1 and b[5:7] == b"\x00\x01"
    assert b[7:39] == b"\x11" * 32 and b[39:43] == (3).to_bytes(4, "big")
    assert b[43:45] == b"\x00\x01" and b[45:53] == (85).to_bytes(8, "big") and b[53] == 1 and b[54:74] == b"\x22" * 20
    assert len(b) == 74


@pytest.mark.parametrize("raw", [
    '{"version":1,"inputs":[],"outputs":[],"x":1}',
    '{"version":2,"inputs":[],"outputs":[]}',
    '{"version":1,"inputs":[{"txid":"AB","index":0}],"outputs":[]}',
    '{"version":1,"inputs":[{"txid":"%s","index":-1}],"outputs":[]}' % ("ab" * 32),
    '{"version":1,"inputs":[],"outputs":[{"value":1.5,"lock":{"type":"p2pkh","pkh":"%s"}}]}' % ("ab" * 20),
    '{"version":1,"inputs":[],"outputs":[{"value":"5","lock":{"type":"p2pkh","pkh":"%s"}}]}' % ("ab" * 20),
    '{"version":1,"inputs":[],"outputs":[{"value":5,"lock":{"type":"p2sh","pkh":"%s"}}]}' % ("ab" * 20),
    '{"version":1,"version":1,"inputs":[],"outputs":[]}',
])
def test_malformed_json_rejected(raw):
    with pytest.raises(TxFormatError):
        Transaction.from_json(raw)


# ------------------------------------------------------------------ persistence
def test_save_and_reload_preserves_logical_contents(led, tmp_path):
    led.apply(build_payment(led, ALICE, BOB.pkh, 85, 2).tx)
    p = tmp_path / "s.json"
    led.save(str(p))
    again = Ledger.load(str(p))
    assert again.utxos == led.utxos and again.spent == led.spent and again.applied == led.applied
    assert again.utxo_set_hash() == led.utxo_set_hash() and again.total_fees == 2
    again.apply(build_payment(again, BOB, CAROL.pkh, 100, 1).tx)       # reloaded ledger keeps working
    tx = build_payment(led, ALICE, BOB.pkh, 20, 3).tx
    assert Ledger.load(str(p)).validate(tx).fee == 3


def test_reloaded_ledger_still_rejects_double_spend(led, tmp_path):
    tx = build_payment(led, ALICE, BOB.pkh, 85, 2).tx
    led.apply(tx)
    led.save(str(tmp_path / "s.json"))
    from utxolab.ledger import Rejected
    with pytest.raises(Rejected) as e:
        Ledger.load(str(tmp_path / "s.json")).apply(tx)
    assert e.value.code == "DOUBLE_SPEND"


def test_tampered_snapshot_detected(led, tmp_path):
    p = tmp_path / "s.json"
    led.save(str(p))
    snap = json.loads(p.read_text())
    snap["utxos"][0]["value"] += 1000
    p.write_text(json.dumps(snap))
    with pytest.raises(ValueError, match="corrupted"):
        Ledger.load(str(p))


def test_snapshot_is_order_independent(led, tmp_path):
    p = tmp_path / "s.json"
    led.save(str(p))
    snap = json.loads(p.read_text())
    snap["utxos"].reverse()
    p.write_text(json.dumps(snap))
    assert Ledger.load(str(p)).utxo_set_hash() == led.utxo_set_hash()
