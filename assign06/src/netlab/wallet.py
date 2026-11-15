"""Wallet side: deterministic coin selection, change, and signing.

Coin-selection strategy: LARGEST-FIRST.
  1. Take the sender's unspent outputs.
  2. Sort by value descending; ties broken by (txid, index) ascending, so the
     result never depends on dictionary order or randomness.
  3. Add coins until the total covers amount + fee.
  4. change = total - amount - fee. If change > 0 a change output back to the
     sender is added; if it is exactly 0 there is no change output.
  Output order is fixed: payment first, change second.

Largest-first uses few inputs (small, cheap transactions) at the cost of
breaking big coins and leaving small ones behind.
"""

from __future__ import annotations

from dataclasses import dataclass

from .crypto import KeyPair
from .state import ChainState
from .tx import OutPoint, Transaction, TxIn, TxOut, Unlock

STRATEGY = "largest-first"


class InsufficientFunds(ValueError):
    pass


@dataclass(frozen=True)
class Payment:
    tx: Transaction
    selected: list[tuple[OutPoint, TxOut]]
    amount: int
    fee: int
    change: int


def select_coins(utxos: dict[OutPoint, TxOut], target: int) -> list[tuple[OutPoint, TxOut]]:
    ordered = sorted(utxos.items(), key=lambda kv: (-kv[1].value, kv[0].txid, kv[0].index))
    chosen, total = [], 0
    for op, out in ordered:
        if total >= target:
            break
        chosen.append((op, out))
        total += out.value
    if total < target:
        raise InsufficientFunds(f"need {target}, wallet has only {total}")
    return chosen


def build_payment(ledger: ChainState, sender: KeyPair, recipient_pkh: bytes, amount: int, fee: int) -> Payment:
    if amount < 1 or fee < 0:
        raise ValueError("amount must be >= 1 and fee >= 0")
    selected = select_coins(ledger.utxos_of(sender.pkh), amount + fee)
    total = sum(o.value for _, o in selected)
    change = total - amount - fee
    outputs = [TxOut(amount, recipient_pkh)]
    if change > 0:
        outputs.append(TxOut(change, sender.pkh))
    unsigned = Transaction(tuple(TxIn(op) for op, _ in selected), tuple(outputs))
    signed = sign(unsigned, [o for _, o in selected], {sender.pkh: sender})
    assert sum(o.value for o in signed.outputs) + fee == total, "change arithmetic"
    return Payment(signed, selected, amount, fee, change)


def sign(tx: Transaction, spent: list[TxOut], keys: dict[bytes, KeyPair]) -> Transaction:
    """Sign every input with the key whose PKH locks the coin being spent."""
    unlocks = []
    for n, out in enumerate(spent):
        kp = keys[out.pkh]
        unlocks.append(Unlock(kp.public_bytes, kp.sign(tx.sighash_message(n, out))))
    return tx.with_unlocks(unlocks)
