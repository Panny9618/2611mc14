"""Acceptance checks for the validator. Every rejection must leave the state unchanged."""

from dataclasses import replace

import pytest

from conftest import ALICE, BOB, CAROL, MALLORY, coin
from utxolab.crypto import N
from utxolab.ledger import Ledger, Rejected
from utxolab.tx import MAX_MONEY, OutPoint, Transaction, TxIn, TxOut, Unlock
from utxolab.wallet import build_payment, sign


def signed(led, spends, outs, keys):
    tx = Transaction(tuple(TxIn(op) for op in spends), tuple(outs))
    return sign(tx, [led.utxos[op] for op in spends], {k.pkh: k for k in keys})


def rejects(led, tx, code, expected_fee=None):
    before = (led.utxo_set_hash(), dict(led.utxos), dict(led.spent), list(led.applied), led.total_fees)
    with pytest.raises(Rejected) as e:
        led.apply(tx, expected_fee)
    assert e.value.code == code, e.value
    after = (led.utxo_set_hash(), dict(led.utxos), dict(led.spent), list(led.applied), led.total_fees)
    assert before == after, "a failed validation must not change the ledger"
    return e.value


# ------------------------------------------------------------------ the assignment example
def test_alice_pays_bob_85_fee_2(led):
    p = build_payment(led, ALICE, BOB.pkh, 85, 2)
    assert sorted(o.value for _, o in p.selected) == [40, 70]
    assert [(o.value, o.pkh) for o in p.tx.outputs] == [(85, BOB.pkh), (23, ALICE.pkh)]
    res = led.apply(p.tx, expected_fee=2)
    assert res.fee == 2 and res.sum_in == 110 and res.sum_out == 108
    assert led.balance(ALICE.pkh) == 23 and led.balance(BOB.pkh) == 135


def test_same_tx_twice_does_not_pay_twice(led):
    tx = build_payment(led, ALICE, BOB.pkh, 85, 2).tx
    led.apply(tx)
    err = rejects(led, tx, "DOUBLE_SPEND")
    assert "already accepted" in err.reason
    assert led.balance(BOB.pkh) == 135


# ------------------------------------------------------------------ inputs
def test_nonexistent_input(led):
    tx = sign(Transaction((TxIn(OutPoint("ab" * 32, 0)),), (TxOut(1, BOB.pkh),)), [TxOut(5, ALICE.pkh)], {ALICE.pkh: ALICE})
    rejects(led, tx, "MISSING_INPUT")


def test_existing_txid_wrong_index(led):
    op = coin(led, ALICE, 40)
    tx = sign(Transaction((TxIn(OutPoint(op.txid, 99)),), (TxOut(1, BOB.pkh),)), [TxOut(5, ALICE.pkh)], {ALICE.pkh: ALICE})
    rejects(led, tx, "MISSING_INPUT")


def test_repeated_outpoint_in_one_tx(led):
    c = coin(led, BOB, 50)
    tx = Transaction((TxIn(c), TxIn(c)), (TxOut(99, BOB.pkh),))
    rejects(led, sign(tx, [led.utxos[c]] * 2, {BOB.pkh: BOB}), "DUPLICATE_INPUT")


def test_second_spend_of_consumed_output(led):
    c = coin(led, BOB, 50)
    led.apply(signed(led, [c], [TxOut(49, CAROL.pkh)], [BOB]))
    again = sign(Transaction((TxIn(c),), (TxOut(48, MALLORY.pkh),)), [TxOut(50, BOB.pkh)], {BOB.pkh: BOB})
    rejects(led, again, "DOUBLE_SPEND")


def test_no_inputs_or_outputs(led):
    rejects(led, Transaction((), (TxOut(5, BOB.pkh),)), "NO_INPUTS")
    rejects(led, signed(led, [coin(led, BOB, 50)], [], [BOB]), "NO_OUTPUTS")


# ------------------------------------------------------------------ signatures
def test_bad_signature_wrong_key(led):
    c = coin(led, BOB, 50)
    tx = sign(Transaction((TxIn(c),), (TxOut(49, MALLORY.pkh),)), [TxOut(50, MALLORY.pkh)], {MALLORY.pkh: MALLORY})
    rejects(led, tx, "WRONG_KEY")


def test_bad_signature_stolen_pubkey(led):
    c = coin(led, BOB, 50)
    tx = sign(Transaction((TxIn(c),), (TxOut(49, MALLORY.pkh),)), [TxOut(50, MALLORY.pkh)], {MALLORY.pkh: MALLORY})
    tx = tx.with_unlocks([Unlock(BOB.public_bytes, tx.inputs[0].unlock.signature)])
    rejects(led, tx, "BAD_SIGNATURE")


@pytest.mark.parametrize("change", ["recipient", "amount", "add_output", "input_order"])
def test_any_modification_after_signing_breaks_signature(led, change):
    tx = build_payment(led, ALICE, BOB.pkh, 85, 2).tx
    o = list(tx.outputs)
    if change == "recipient":
        o[0] = TxOut(85, MALLORY.pkh)
    elif change == "amount":
        o[0], o[1] = TxOut(84, BOB.pkh), TxOut(24, ALICE.pkh)          # same total, different split
    elif change == "add_output":
        o[1] = TxOut(22, ALICE.pkh); o.append(TxOut(1, MALLORY.pkh))
    tampered = replace(tx, outputs=tuple(o), _cache={})
    if change == "input_order":
        tampered = replace(tx, inputs=tuple(reversed(tx.inputs)), _cache={})
    rejects(led, tampered, "BAD_SIGNATURE")


def test_signature_cannot_be_reused_for_other_input(led):
    tx = build_payment(led, ALICE, BOB.pkh, 85, 2).tx
    u0, u1 = tx.inputs[0].unlock, tx.inputs[1].unlock
    rejects(led, tx.with_unlocks([u1, u0]), "BAD_SIGNATURE")


def test_missing_unlock(led):
    c = coin(led, BOB, 50)
    rejects(led, Transaction((TxIn(c),), (TxOut(49, CAROL.pkh),)), "MISSING_UNLOCK")


def test_high_s_signature_rejected(led):
    tx = signed(led, [coin(led, BOB, 50)], [TxOut(49, CAROL.pkh)], [BOB])
    u = tx.inputs[0].unlock
    s = int.from_bytes(u.signature[32:], "big")
    rejects(led, tx.with_unlocks([Unlock(u.public_key, u.signature[:32] + (N - s).to_bytes(32, "big"))]),
            "NON_CANONICAL_SIGNATURE")


def test_malformed_public_key(led):
    tx = signed(led, [coin(led, BOB, 50)], [TxOut(49, CAROL.pkh)], [BOB])
    rejects(led, tx.with_unlocks([Unlock(b"\x04" + bytes(64), tx.inputs[0].unlock.signature)]), "MALFORMED")


# ------------------------------------------------------------------ values
@pytest.mark.parametrize("value,code", [(-1, "INVALID_VALUE"), (0, "INVALID_VALUE"), (2**64, "INVALID_VALUE"),
                                        (MAX_MONEY + 1, "INVALID_VALUE")])
def test_bad_output_values(led, value, code):
    c = coin(led, BOB, 50)
    tx = Transaction((TxIn(c, Unlock(BOB.public_bytes, b"\x01" * 64)),), (TxOut(value, CAROL.pkh),))
    rejects(led, tx, code)


def test_sum_overflow(led):
    rejects(led, signed(led, [coin(led, BOB, 50)], [TxOut(MAX_MONEY, CAROL.pkh)] * 2, [BOB]), "VALUE_OVERFLOW")


def test_value_creation(led):
    rejects(led, signed(led, [coin(led, BOB, 50)], [TxOut(51, CAROL.pkh)], [BOB]), "VALUE_CREATED")


def test_too_much_change_creates_value(led):
    rejects(led, signed(led, [coin(led, BOB, 50)], [TxOut(40, CAROL.pkh), TxOut(15, BOB.pkh)], [BOB]), "VALUE_CREATED")


def test_incorrect_change_with_expected_fee(led):
    tx = signed(led, [coin(led, BOB, 50)], [TxOut(40, CAROL.pkh), TxOut(5, BOB.pkh)], [BOB])
    rejects(led, tx, "INCORRECT_CHANGE", expected_fee=1)
    assert led.validate(tx).fee == 5          # valid by consensus, only the stated fee differs


def test_zero_fee_allowed(led):
    assert led.apply(signed(led, [coin(led, BOB, 50)], [TxOut(50, CAROL.pkh)], [BOB])).fee == 0


# ------------------------------------------------------------------ atomicity and accounting
def test_failure_in_last_input_changes_nothing(led):
    tx = build_payment(led, ALICE, BOB.pkh, 85, 2).tx
    bad = tx.with_unlocks([tx.inputs[0].unlock, Unlock(ALICE.public_bytes, tx.inputs[0].unlock.signature)])
    rejects(led, bad, "BAD_SIGNATURE")
    assert led.balance(ALICE.pkh) == 110


def test_supply_conserved_through_many_payments(led):
    for _ in range(5):
        led.apply(build_payment(led, ALICE if led.balance(ALICE.pkh) > 10 else BOB,
                                CAROL.pkh, 3, 1).tx)
    assert led.total_value() + led.total_fees == led.genesis_total == 160


def test_new_outputs_are_spendable(led):
    tx = build_payment(led, ALICE, BOB.pkh, 85, 2).tx
    led.apply(tx)
    assert OutPoint(tx.txid, 0) in led.utxos and led.utxos[OutPoint(tx.txid, 0)].value == 85
    led.apply(build_payment(led, BOB, CAROL.pkh, 100, 1).tx)
    assert led.balance(BOB.pkh) == 34 and led.balance(CAROL.pkh) == 100


def test_genesis_rejects_bad_values():
    with pytest.raises(Rejected):
        Ledger.genesis([TxOut(0, ALICE.pkh)])
    with pytest.raises(Rejected):
        Ledger.genesis([TxOut(MAX_MONEY, ALICE.pkh), TxOut(1, ALICE.pkh)])
