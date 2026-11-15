"""Transactions, outpoints, outputs and their canonical bytes.

Canonical body (what the txid commits to; signatures are NOT included, so a
signature can never change a txid):

    "UTX" 0x00                      4   magic
    version                         1   u8 = 1
    n_inputs                        2   u16 big-endian
    per input:  prev_txid          32
                prev_index          4   u32
    n_outputs                       2   u16
    per output: value               8   u64 (1 .. MAX_MONEY)
                lock_type           1   0x01 = P2PKH
                pkh                20

txid = SHA-256(body)

Each input is unlocked by (public_key, signature). Input i signs

    "UTXSIG" 0x00 0x00 || body || u32(i) || value_spent(u64) || lock_spent(21)

so a signature covers every input and output (it cannot be moved to another
transaction) and the exact coin being spent, including its value.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from typing import Any

MAGIC = b"UTX\x00"
SIG_MAGIC = b"UTXSIG\x00\x00"
VERSION = 1
COIN = 100_000_000
MAX_MONEY = 21_000_000 * COIN          # 2.1e15 units; any single value or total above is invalid
U64_MAX = 2**64 - 1
MAX_IO = 1000
P2PKH = 0x01
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX40 = re.compile(r"[0-9a-f]{40}")


class TxFormatError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class OutPoint:
    txid: str              # 64 lowercase hex
    index: int             # u32

    def to_bytes(self) -> bytes:
        return bytes.fromhex(self.txid) + self.index.to_bytes(4, "big")

    def __str__(self) -> str:
        return f"{self.txid[:12]}…:{self.index}"


@dataclass(frozen=True)
class TxOut:
    value: int
    pkh: bytes             # P2PKH locking condition: spender must show a key with this hash

    def lock_bytes(self) -> bytes:
        return bytes([P2PKH]) + self.pkh

    def to_bytes(self) -> bytes:
        return self.value.to_bytes(8, "big") + self.lock_bytes()

    def to_dict(self) -> dict:
        return {"value": self.value, "lock": {"type": "p2pkh", "pkh": self.pkh.hex()}}


@dataclass(frozen=True)
class Unlock:
    public_key: bytes
    signature: bytes


@dataclass(frozen=True)
class TxIn:
    prev: OutPoint
    unlock: Unlock | None = None


@dataclass(frozen=True)
class Transaction:
    inputs: tuple[TxIn, ...]
    outputs: tuple[TxOut, ...]
    version: int = VERSION
    _cache: dict = field(default_factory=dict, compare=False, repr=False, hash=False)

    # ------------------------------------------------------------------ bytes / ids
    def body(self) -> bytes:
        if "body" not in self._cache:
            parts = [MAGIC, bytes([self.version]), len(self.inputs).to_bytes(2, "big")]
            parts += [i.prev.to_bytes() for i in self.inputs]
            parts.append(len(self.outputs).to_bytes(2, "big"))
            for o in self.outputs:
                if not isinstance(o.value, int) or not 0 <= o.value <= U64_MAX:
                    raise TxFormatError(f"output value {o.value!r} cannot be encoded as u64")
                parts.append(o.to_bytes())
            self._cache["body"] = b"".join(parts)
        return self._cache["body"]

    @property
    def txid(self) -> str:
        return hashlib.sha256(self.body()).hexdigest()

    def sighash_message(self, i: int, spent: TxOut) -> bytes:
        return SIG_MAGIC + self.body() + i.to_bytes(4, "big") + spent.to_bytes()

    def outpoint(self, index: int) -> OutPoint:
        return OutPoint(self.txid, index)

    def with_unlocks(self, unlocks: list[Unlock]) -> "Transaction":
        return replace(self, inputs=tuple(TxIn(i.prev, u) for i, u in zip(self.inputs, unlocks)), _cache={})

    # ------------------------------------------------------------------ JSON
    def to_dict(self) -> dict:
        ins = []
        for i in self.inputs:
            d: dict[str, Any] = {"txid": i.prev.txid, "index": i.prev.index}
            if i.unlock:
                d["unlock"] = {"public_key": i.unlock.public_key.hex(), "signature": i.unlock.signature.hex()}
            ins.append(d)
        return {"version": self.version, "inputs": ins, "outputs": [o.to_dict() for o in self.outputs]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, raw: str | bytes) -> "Transaction":
        def no_dupes(pairs):
            d = {}
            for k, v in pairs:
                if k in d:
                    raise TxFormatError(f"duplicate key {k!r}")
                d[k] = v
            return d

        def no_float(s):
            raise TxFormatError(f"non-integer number {s}")

        try:
            obj = json.loads(raw, object_pairs_hook=no_dupes, parse_float=no_float,
                             parse_constant=lambda s: no_float(s))
        except json.JSONDecodeError as e:
            raise TxFormatError(f"invalid JSON: {e}") from None
        return cls.from_dict(obj)

    @classmethod
    def from_dict(cls, obj: Any) -> "Transaction":
        """Parse structure and types. Value ranges are checked by the validator, so that
        negative or overflowing values reach it and get a precise rejection reason."""
        def need(cond, msg):
            if not cond:
                raise TxFormatError(msg)

        def is_int(v):
            return isinstance(v, int) and not isinstance(v, bool)

        need(isinstance(obj, dict) and set(obj) == {"version", "inputs", "outputs"},
             "transaction must have exactly keys version, inputs, outputs")
        need(obj["version"] == VERSION and is_int(obj["version"]), f"version must be {VERSION}")
        need(isinstance(obj["inputs"], list) and isinstance(obj["outputs"], list), "inputs/outputs must be lists")
        ins = []
        for n, i in enumerate(obj["inputs"]):
            need(isinstance(i, dict) and set(i) in ({"txid", "index"}, {"txid", "index", "unlock"}),
                 f"input {n}: keys must be txid, index[, unlock]")
            need(isinstance(i["txid"], str) and bool(_HEX64.fullmatch(i["txid"])), f"input {n}: txid must be 64 lowercase hex")
            need(is_int(i["index"]) and 0 <= i["index"] <= 0xFFFFFFFF, f"input {n}: index must be a u32")
            unlock = None
            if "unlock" in i:
                u = i["unlock"]
                need(isinstance(u, dict) and set(u) == {"public_key", "signature"}, f"input {n}: bad unlock")
                try:
                    unlock = Unlock(bytes.fromhex(u["public_key"]), bytes.fromhex(u["signature"]))
                except (TypeError, ValueError):
                    raise TxFormatError(f"input {n}: unlock fields must be hex") from None
                need(u["public_key"] == unlock.public_key.hex() and u["signature"] == unlock.signature.hex(),
                     f"input {n}: unlock hex must be lowercase")
            ins.append(TxIn(OutPoint(i["txid"], i["index"]), unlock))
        outs = []
        for n, o in enumerate(obj["outputs"]):
            need(isinstance(o, dict) and set(o) == {"value", "lock"}, f"output {n}: keys must be value, lock")
            need(is_int(o["value"]), f"output {n}: value must be an integer")
            lk = o["lock"]
            need(isinstance(lk, dict) and lk.get("type") == "p2pkh" and set(lk) == {"type", "pkh"}
                 and isinstance(lk["pkh"], str) and bool(_HEX40.fullmatch(lk["pkh"])),
                 f"output {n}: lock must be {{'type': 'p2pkh', 'pkh': <40 lowercase hex>}}")
            outs.append(TxOut(o["value"], bytes.fromhex(lk["pkh"])))
        return cls(tuple(ins), tuple(outs))
