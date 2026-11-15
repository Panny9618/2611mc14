import json
from pathlib import Path

import pytest

from toywallet.errors import WalletError
from toywallet.tx import Transaction, memo_hash

VEC = json.loads((Path(__file__).resolve().parent.parent / "vectors" / "tx_vector.json").read_text())


def test_golden_vector():
    tx = Transaction.from_dict(VEC["tx"])
    assert tx.to_bytes().hex() == VEC["signed_bytes_hex"]
    assert tx.txid() == VEC["txid"]
    assert len(tx.to_bytes()) == VEC["signed_bytes_len"] == 110
    assert VEC["tx"]["memo_hash"] == memo_hash(VEC["memo"])


def test_whitespace_and_key_order_give_same_bytes():
    a = json.dumps(VEC["tx"])
    b = json.dumps(dict(reversed(list(VEC["tx"].items()))), indent=9)
    c = "\n\t" + json.dumps(VEC["tx"], separators=(" , ", " : ")) + "\r\n"
    assert Transaction.from_json(a).to_bytes() == Transaction.from_json(b).to_bytes() == Transaction.from_json(c).to_bytes()


def test_layout_offsets():
    rows = Transaction.from_dict(VEC["tx"]).layout()
    assert [(o, n, len(b)) for o, n, b, _ in rows] == [
        (0, "magic", 4), (4, "version", 1), (5, "network_len", 1), (6, "network_id", 14),
        (20, "sender", 21), (41, "recipient", 21), (62, "amount_units", 8), (70, "nonce", 8), (78, "memo_hash", 32)]


def test_every_field_changes_the_bytes():
    base = Transaction.from_dict(VEC["tx"]).to_bytes()
    changes = {"amount_units": 1250001, "nonce": 8, "memo_hash": "00" * 32,
               "recipient": VEC["alice"]["address"], "sender": VEC["bob"]["address"]}
    for k, v in changes.items():
        assert Transaction.from_dict({**VEC["tx"], k: v}).to_bytes() != base, k


def mut(**kw):
    return {**VEC["tx"], **kw}


@pytest.mark.parametrize("obj,code", [
    (mut(amount_units=0), "MALFORMED"), (mut(amount_units=-5), "MALFORMED"),
    (mut(amount_units=2**64), "MALFORMED"), (mut(amount_units="10"), "MALFORMED"),
    (mut(amount_units=True), "MALFORMED"), (mut(nonce=-1), "MALFORMED"), (mut(nonce=2**64), "MALFORMED"),
    (mut(version=2), "MALFORMED"), (mut(network_id="Course-Testnet"), "MALFORMED"),
    (mut(network_id=""), "MALFORMED"), (mut(memo_hash="AB" * 32), "MALFORMED"), (mut(memo_hash="ab"), "MALFORMED"),
    (mut(sender=5), "MALFORMED_ADDRESS"),
    ({k: v for k, v in VEC["tx"].items() if k != "nonce"}, "MALFORMED"),
    (mut(extra=1), "MALFORMED"), ([], "MALFORMED"),
])
def test_field_rules(obj, code):
    with pytest.raises(WalletError) as e:
        Transaction.from_dict(obj)
    assert e.value.code == code


@pytest.mark.parametrize("text", ['{"amount_units": 1.5}', '{"a":1,"a":2}', "nope", '{"x": NaN}'])
def test_strict_json(text):
    with pytest.raises(WalletError):
        Transaction.from_json(text)


def test_max_u64_amount_ok():
    assert Transaction.from_dict(mut(amount_units=2**64 - 1)).to_bytes()[62:70] == b"\xff" * 8


def test_address_network_must_match():
    tx = Transaction.from_dict(mut(network_id="course-mainnet"))
    with pytest.raises(WalletError) as e:
        tx.to_bytes()
    assert e.value.code == "WRONG_NETWORK"


def test_unknown_network():
    with pytest.raises(WalletError) as e:
        Transaction.from_dict(mut(network_id="ethereum")).to_bytes()
    assert e.value.code == "WRONG_NETWORK"
