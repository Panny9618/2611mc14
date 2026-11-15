"""The UTXO set, the validator and atomic state updates.

Validation order (cheap checks first, all before any state change):

  1  MALFORMED           structure / encoding problems
  2  NO_INPUTS, NO_OUTPUTS
  3  INVALID_VALUE       an output value is not an integer in [1, MAX_MONEY] (negative, zero, > u64 ...)
  4  VALUE_OVERFLOW      the sum of outputs exceeds MAX_MONEY
  5  DUPLICATE_INPUT     the same outpoint appears twice in one transaction
  6  DOUBLE_SPEND        an input was already consumed by an accepted transaction
  7  MISSING_INPUT       an input refers to an outpoint that never existed
  8  VALUE_CREATED       sum(outputs) > sum(inputs)  (creating money, e.g. too much change)
  9  MISSING_UNLOCK / WRONG_KEY / NON_CANONICAL_SIGNATURE / BAD_SIGNATURE   authorisation
 10  INCORRECT_CHANGE    (only if the submitter states the expected fee) the fee implied by the
                          outputs differs from it, i.e. the change output is wrong

fee = sum(inputs) - sum(outputs). Only when every check passes are the spent
outputs removed and the new outputs added - in one step. A rejected
transaction leaves the ledger exactly as it was.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

from .crypto import CryptoError, check_signature_encoding, load_public, pkh_of, verify
from .tx import MAX_IO, MAX_MONEY, OutPoint, Transaction, TxFormatError, TxOut

SNAPSHOT_FORMAT = "utxo-snapshot-v1"


class Rejected(Exception):
    def __init__(self, code: str, reason: str):
        super().__init__(f"[{code}] {reason}")
        self.code = code
        self.reason = reason


@dataclass(frozen=True)
class Accepted:
    txid: str
    fee: int
    sum_in: int
    sum_out: int


class Ledger:
    def __init__(self) -> None:
        self.utxos: dict[OutPoint, TxOut] = {}
        self.spent: dict[OutPoint, str] = {}          # outpoint -> txid that spent it (for precise errors)
        self.applied: list[str] = []                  # accepted txids in order (genesis first)
        self.genesis_total = 0
        self.total_fees = 0

    # ------------------------------------------------------------------ genesis
    @classmethod
    def genesis(cls, outputs: list[TxOut]) -> tuple["Ledger", Transaction]:
        """Create the initial coins. The only transaction allowed to have no inputs."""
        led = cls()
        tx = Transaction((), tuple(outputs))
        for o in outputs:
            if not isinstance(o.value, int) or isinstance(o.value, bool) or not 1 <= o.value <= MAX_MONEY:
                raise Rejected("INVALID_VALUE", f"genesis value {o.value!r} out of range")
        if sum(o.value for o in outputs) > MAX_MONEY:
            raise Rejected("VALUE_OVERFLOW", "genesis total exceeds MAX_MONEY")
        for i, o in enumerate(outputs):
            led.utxos[tx.outpoint(i)] = o
        led.applied.append(tx.txid)
        led.genesis_total = sum(o.value for o in outputs)
        return led, tx

    # ------------------------------------------------------------------ queries
    def balance(self, pkh: bytes) -> int:
        return sum(o.value for o in self.utxos.values() if o.pkh == pkh)

    def utxos_of(self, pkh: bytes) -> dict[OutPoint, TxOut]:
        return {op: o for op, o in self.utxos.items() if o.pkh == pkh}

    def total_value(self) -> int:
        return sum(o.value for o in self.utxos.values())

    def utxo_set_hash(self) -> str:
        """Commitment to the logical UTXO set: SHA-256 over entries sorted by outpoint."""
        h = hashlib.sha256()
        for op in sorted(self.utxos):
            h.update(op.to_bytes() + self.utxos[op].to_bytes())
        return h.hexdigest()

    # ------------------------------------------------------------------ validation
    def validate(self, tx: Transaction, expected_fee: int | None = None) -> Accepted:
        try:
            tx.body()
        except TxFormatError as e:
            if "u64" in str(e):
                raise Rejected("INVALID_VALUE", str(e)) from None
            raise Rejected("MALFORMED", str(e)) from None
        if not tx.inputs:
            raise Rejected("NO_INPUTS", "a transaction must spend at least one output (only genesis has none)")
        if not tx.outputs:
            raise Rejected("NO_OUTPUTS", "a transaction must create at least one output")
        if len(tx.inputs) > MAX_IO or len(tx.outputs) > MAX_IO:
            raise Rejected("MALFORMED", f"more than {MAX_IO} inputs or outputs")

        # 3-4  output values and overflow
        sum_out = 0
        for n, o in enumerate(tx.outputs):
            if not 1 <= o.value <= MAX_MONEY:
                raise Rejected("INVALID_VALUE", f"output {n} value {o.value} not in [1, {MAX_MONEY}]")
            sum_out += o.value
            if sum_out > MAX_MONEY:
                raise Rejected("VALUE_OVERFLOW", f"sum of outputs exceeds MAX_MONEY ({MAX_MONEY}) at output {n}")

        # 5  duplicate inputs
        seen: set[OutPoint] = set()
        for n, i in enumerate(tx.inputs):
            if i.prev in seen:
                raise Rejected("DUPLICATE_INPUT", f"input {n} repeats outpoint {i.prev} within the same transaction")
            seen.add(i.prev)

        # 6-7  existence
        spent_outputs: list[TxOut] = []
        for n, i in enumerate(tx.inputs):
            if i.prev in self.utxos:
                spent_outputs.append(self.utxos[i.prev])
                continue
            if i.prev in self.spent:
                by = self.spent[i.prev]
                note = " (this exact transaction was already accepted)" if by == tx.txid else ""
                raise Rejected("DOUBLE_SPEND", f"input {n} {i.prev} was already spent by tx {by[:12]}…{note}")
            raise Rejected("MISSING_INPUT", f"input {n} {i.prev} does not exist")

        # 8  conservation of value
        sum_in = sum(o.value for o in spent_outputs)
        if sum_out > sum_in:
            raise Rejected("VALUE_CREATED", f"outputs {sum_out} exceed inputs {sum_in} by {sum_out - sum_in}")

        # 9  authorisation (P2PKH)
        for n, (i, spent) in enumerate(zip(tx.inputs, spent_outputs)):
            if i.unlock is None:
                raise Rejected("MISSING_UNLOCK", f"input {n} has no public key / signature")
            try:
                load_public(i.unlock.public_key)
            except CryptoError as e:
                raise Rejected("MALFORMED", f"input {n}: {e}") from None
            if pkh_of(i.unlock.public_key) != spent.pkh:
                raise Rejected("WRONG_KEY", f"input {n}: public key does not hash to the output's locking PKH")
            try:
                check_signature_encoding(i.unlock.signature)
            except CryptoError as e:
                raise Rejected("NON_CANONICAL_SIGNATURE", f"input {n}: {e}") from None
            if not verify(i.unlock.public_key, i.unlock.signature, tx.sighash_message(n, spent)):
                raise Rejected("BAD_SIGNATURE", f"input {n}: signature does not match this transaction")

        fee = sum_in - sum_out
        # 10  wallet/submitter policy: change must be exactly inputs - payment - fee
        if expected_fee is not None and fee != expected_fee:
            raise Rejected("INCORRECT_CHANGE",
                           f"implied fee is {fee} but {expected_fee} was expected - change output is off by {fee - expected_fee}")
        return Accepted(tx.txid, fee, sum_in, sum_out)

    def apply(self, tx: Transaction, expected_fee: int | None = None) -> Accepted:
        """Validate, then update the UTXO set atomically (all-or-nothing)."""
        result = self.validate(tx, expected_fee)
        new_utxos = dict(self.utxos)
        new_spent = dict(self.spent)
        txid = tx.txid
        for i in tx.inputs:
            del new_utxos[i.prev]
            new_spent[i.prev] = txid
        for n, o in enumerate(tx.outputs):
            new_utxos[OutPoint(txid, n)] = o
        # commit: plain assignments that cannot fail half-way
        self.utxos, self.spent = new_utxos, new_spent
        self.applied = self.applied + [txid]
        self.total_fees += result.fee
        return result

    # ------------------------------------------------------------------ persistence
    def to_snapshot(self) -> dict:
        return {
            "format": SNAPSHOT_FORMAT,
            "genesis_total": self.genesis_total,
            "total_fees": self.total_fees,
            "applied_txids": self.applied,
            "utxo_count": len(self.utxos),
            "utxo_total_value": self.total_value(),
            "utxo_set_hash": self.utxo_set_hash(),
            "utxos": [{"txid": op.txid, "index": op.index, **self.utxos[op].to_dict()} for op in sorted(self.utxos)],
            "spent": [{"txid": op.txid, "index": op.index, "spent_by": by} for op, by in sorted(self.spent.items())],
        }

    def save(self, path: str) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(self.to_snapshot(), f, indent=2)
            f.write("\n")
        os.replace(tmp, path)          # atomic rename: readers see the old or the new file, never half

    @classmethod
    def from_snapshot(cls, snap: dict) -> "Ledger":
        if snap.get("format") != SNAPSHOT_FORMAT:
            raise ValueError(f"unknown snapshot format {snap.get('format')!r}")
        led = cls()
        for u in snap["utxos"]:
            op = OutPoint(u["txid"], u["index"])
            if op in led.utxos:
                raise ValueError(f"snapshot lists {op} twice")
            led.utxos[op] = TxOut(u["value"], bytes.fromhex(u["lock"]["pkh"]))
        led.spent = {OutPoint(s["txid"], s["index"]): s["spent_by"] for s in snap["spent"]}
        led.applied = list(snap["applied_txids"])
        led.genesis_total = snap["genesis_total"]
        led.total_fees = snap["total_fees"]
        if led.utxo_set_hash() != snap["utxo_set_hash"]:
            raise ValueError("snapshot corrupted: UTXO set does not match utxo_set_hash")
        if led.total_value() + led.total_fees != led.genesis_total:
            raise ValueError("snapshot inconsistent: utxo total + fees != genesis total")
        if set(led.utxos) & set(led.spent):
            raise ValueError("snapshot inconsistent: an outpoint is both unspent and spent")
        return led

    @classmethod
    def load(cls, path: str) -> "Ledger":
        with open(path, encoding="utf-8") as f:
            return cls.from_snapshot(json.load(f))
