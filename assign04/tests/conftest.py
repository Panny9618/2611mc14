import pytest

from utxolab.crypto import KeyPair
from utxolab.ledger import Ledger
from utxolab.tx import TxOut

ALICE, BOB, CAROL, MALLORY = (KeyPair.from_scalar(d) for d in (0xA11CE, 0xB0B, 0xCA401, 0x3A11))


@pytest.fixture
def led():
    """Alice controls 40 and 70 (the assignment's example); Bob controls 50."""
    ledger, _ = Ledger.genesis([TxOut(40, ALICE.pkh), TxOut(70, ALICE.pkh), TxOut(50, BOB.pkh)])
    return ledger


def coin(led, kp, value):
    return next(op for op, o in sorted(led.utxos_of(kp.pkh).items()) if o.value == value)
