"""UTXO state and the per-transaction validator (from Assignment 4).

The rules for a normal (non-coinbase) transaction are unchanged from
Assignment 4; see that readme for the full order. Coinbase handling and block
connection live in chain.py.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .crypto import CryptoError, check_signature_encoding, load_public, pkh_of, verify
from .tx import MAX_IO, MAX_MONEY, OutPoint, Transaction, TxFormatError, TxOut


class Rejected(Exception):
    def __init__(self, code: str, reason: str):
        super().__init__(f"[{code}] {reason}")
        self.code = code
        self.reason = reason


@dataclass(frozen=True)
class TxResult:
    txid: str
    fee: int
    sum_in: int
    sum_out: int


class ChainState:
    def __init__(self) -> None:
        self.utxos: dict[OutPoint, TxOut] = {}
        self.spent: dict[OutPoint, str] = {}

    def balance(self, pkh: bytes) -> int:
        return sum(o.value for o in self.utxos.values() if o.pkh == pkh)

    def utxos_of(self, pkh: bytes) -> dict[OutPoint, TxOut]:
        return {op: o for op, o in self.utxos.items() if o.pkh == pkh}

    def total_value(self) -> int:
        return sum(o.value for o in self.utxos.values())

    def utxo_set_hash(self) -> str:
        h = hashlib.sha256()
        for op in sorted(self.utxos):
            h.update(op.to_bytes() + self.utxos[op].to_bytes())
        return h.hexdigest()

    def validate(self, tx: Transaction) -> TxResult:
        try:
            tx.body()
        except TxFormatError as e:
            raise Rejected("INVALID_VALUE" if "u64" in str(e) else "MALFORMED", str(e)) from None
        if not tx.inputs:
            raise Rejected("NO_INPUTS", "transaction spends nothing")
        if not tx.outputs:
            raise Rejected("NO_OUTPUTS", "transaction creates nothing")
        if len(tx.inputs) > MAX_IO or len(tx.outputs) > MAX_IO:
            raise Rejected("MALFORMED", f"more than {MAX_IO} inputs or outputs")
        sum_out = 0
        for n, o in enumerate(tx.outputs):
            if not 1 <= o.value <= MAX_MONEY:
                raise Rejected("INVALID_VALUE", f"output {n} value {o.value} not in [1, {MAX_MONEY}]")
            sum_out += o.value
            if sum_out > MAX_MONEY:
                raise Rejected("VALUE_OVERFLOW", "sum of outputs exceeds MAX_MONEY")
        seen: set[OutPoint] = set()
        for n, i in enumerate(tx.inputs):
            if i.prev in seen:
                raise Rejected("DUPLICATE_INPUT", f"input {n} repeats {i.prev}")
            seen.add(i.prev)
        spent_outputs = []
        for n, i in enumerate(tx.inputs):
            if i.prev in self.utxos:
                spent_outputs.append(self.utxos[i.prev])
            elif i.prev in self.spent:
                raise Rejected("DOUBLE_SPEND", f"input {n} {i.prev} already spent by tx {self.spent[i.prev][:12]}…")
            else:
                raise Rejected("MISSING_INPUT", f"input {n} {i.prev} does not exist")
        sum_in = sum(o.value for o in spent_outputs)
        if sum_out > sum_in:
            raise Rejected("VALUE_CREATED", f"outputs {sum_out} exceed inputs {sum_in}")
        for n, (i, spent) in enumerate(zip(tx.inputs, spent_outputs)):
            if i.unlock is None:
                raise Rejected("MISSING_UNLOCK", f"input {n} is not signed")
            try:
                load_public(i.unlock.public_key)
            except CryptoError as e:
                raise Rejected("MALFORMED", f"input {n}: {e}") from None
            if pkh_of(i.unlock.public_key) != spent.pkh:
                raise Rejected("WRONG_KEY", f"input {n}: key does not match the output's P2PKH lock")
            try:
                check_signature_encoding(i.unlock.signature)
            except CryptoError as e:
                raise Rejected("NON_CANONICAL_SIGNATURE", f"input {n}: {e}") from None
            if not verify(i.unlock.public_key, i.unlock.signature, tx.sighash_message(n, spent)):
                raise Rejected("BAD_SIGNATURE", f"input {n}: signature does not match")
        return TxResult(tx.txid, sum_in - sum_out, sum_in, sum_out)
