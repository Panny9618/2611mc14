"""Scripted scenario: accepted and rejected transactions with precise reasons.

Produces, in an output directory:
  snapshots/00_genesis.json ... 03_final.json   ledger snapshots after each accepted step
  trace.jsonl                                   one JSON record per submission
  trace.md                                      the same as a readable table

Actors use FIXED private scalars so the run is reproducible. These keys are
public knowledge and for testing only.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace
from typing import Callable

from .crypto import N, KeyPair, address_of_pkh
from .ledger import Ledger, Rejected
from .tx import MAX_MONEY, OutPoint, Transaction, TxIn, TxOut, Unlock
from .wallet import build_payment, sign

ALICE, BOB, CAROL, MALLORY = (KeyPair.from_scalar(d) for d in (0xA11CE, 0xB0B, 0xCA401, 0x3A11))
NAMES = {ALICE.pkh: "Alice", BOB.pkh: "Bob", CAROL.pkh: "Carol", MALLORY.pkh: "Mallory"}


def who(pkh: bytes) -> str:
    return NAMES.get(pkh, address_of_pkh(pkh)[:10] + "…")


@dataclass
class Step:
    label: str
    make: Callable[[Ledger], Transaction]
    expect: str                 # "ACCEPTED" or a rejection code
    expected_fee: int | None = None


def _manual(led: Ledger, spends: list[OutPoint], outs: list[TxOut], signer: dict) -> Transaction:
    tx = Transaction(tuple(TxIn(op) for op in spends), tuple(outs))
    return sign(tx, [led.utxos[op] for op in spends], signer)


def bob_coin(led: Ledger, value: int) -> OutPoint:
    return next(op for op, o in sorted(led.utxos_of(BOB.pkh).items()) if o.value == value)


def steps() -> list[Step]:
    first: dict = {}

    def s1(led):
        first["tx"] = build_payment(led, ALICE, BOB.pkh, 85, 2).tx
        return first["tx"]

    def missing(led):
        fake = OutPoint("ab" * 32, 0)
        tx = Transaction((TxIn(fake),), (TxOut(10, BOB.pkh),))
        return sign(tx, [TxOut(10, ALICE.pkh)], {ALICE.pkh: ALICE})

    def dup(led):
        c = bob_coin(led, 50)
        tx = Transaction((TxIn(c), TxIn(c)), (TxOut(99, BOB.pkh),))
        return sign(tx, [led.utxos[c]] * 2, {BOB.pkh: BOB})

    def mallory_own_key(led):
        c = bob_coin(led, 50)
        tx = Transaction((TxIn(c),), (TxOut(49, MALLORY.pkh),))
        return sign(tx, [TxOut(50, MALLORY.pkh)], {MALLORY.pkh: MALLORY})   # signs as if it were hers

    def mallory_bobs_pubkey(led):
        t = mallory_own_key(led)
        u = t.inputs[0].unlock
        return t.with_unlocks([Unlock(BOB.public_bytes, u.signature)])

    def redirected(led):
        c = bob_coin(led, 50)
        t = _manual(led, [c], [TxOut(40, CAROL.pkh), TxOut(9, BOB.pkh)], {BOB.pkh: BOB})
        return replace(t, outputs=(TxOut(40, MALLORY.pkh), t.outputs[1]), _cache={})

    def neg(led):
        # A negative value cannot even be serialised, so it cannot be signed; the validator
        # must still reject it cleanly when it arrives as JSON.
        c = bob_coin(led, 50)
        return Transaction((TxIn(c, Unlock(BOB.public_bytes, b"\x01" * 64)),), (TxOut(-5, CAROL.pkh), TxOut(54, BOB.pkh)))

    def u64_overflow(led):
        c = bob_coin(led, 50)
        return Transaction((TxIn(c, Unlock(BOB.public_bytes, b"\x01" * 64)),), (TxOut(2**64, CAROL.pkh),))

    def sum_overflow(led):
        c = bob_coin(led, 50)
        return _manual(led, [c], [TxOut(MAX_MONEY, CAROL.pkh), TxOut(MAX_MONEY, CAROL.pkh)], {BOB.pkh: BOB})

    def too_much_change(led):
        c = bob_coin(led, 50)
        return _manual(led, [c], [TxOut(40, CAROL.pkh), TxOut(15, BOB.pkh)], {BOB.pkh: BOB})

    def too_little_change(led):
        c = bob_coin(led, 50)
        return _manual(led, [c], [TxOut(40, CAROL.pkh), TxOut(5, BOB.pkh)], {BOB.pkh: BOB})

    def unsigned(led):
        c = bob_coin(led, 50)
        return Transaction((TxIn(c),), (TxOut(49, CAROL.pkh),))

    def high_s(led):
        c = bob_coin(led, 50)
        t = _manual(led, [c], [TxOut(49, CAROL.pkh)], {BOB.pkh: BOB})
        u = t.inputs[0].unlock
        r, s = u.signature[:32], int.from_bytes(u.signature[32:], "big")
        return t.with_unlocks([Unlock(u.public_key, r + (N - s).to_bytes(32, "big"))])

    return [
        Step("Alice pays Bob 85, fee 2 (largest-first: 70 + 40, change 23)", s1, "ACCEPTED", 2),
        Step("The same signed transaction submitted again", lambda led: first["tx"], "DOUBLE_SPEND"),
        Step("Spend an outpoint that never existed", missing, "MISSING_INPUT"),
        Step("Bob lists his 50-coin twice in one transaction", dup, "DUPLICATE_INPUT"),
        Step("Mallory spends Bob's 50 using her own key", mallory_own_key, "WRONG_KEY"),
        Step("Mallory attaches Bob's public key to her signature", mallory_bobs_pubkey, "BAD_SIGNATURE"),
        Step("Bob signs 40 to Carol; Mallory redirects the output to herself", redirected, "BAD_SIGNATURE"),
        Step("Output with a negative value (-5)", neg, "INVALID_VALUE"),
        Step("Output value 2^64 (does not fit in u64)", u64_overflow, "INVALID_VALUE"),
        Step("Two outputs of MAX_MONEY each (sum overflows)", sum_overflow, "VALUE_OVERFLOW"),
        Step("Bob pays 40 from 50 but returns 15 change (creates 5)", too_much_change, "VALUE_CREATED"),
        Step("Bob pays 40 fee 1 from 50 but returns only 5 change", too_little_change, "INCORRECT_CHANGE", 1),
        Step("Input with no public key / signature", unsigned, "MISSING_UNLOCK"),
        Step("Valid signature replaced by its high-S twin (r, n-s)", high_s, "NON_CANONICAL_SIGNATURE"),
        Step("Bob pays Carol 100, fee 1 (largest-first: 85 + 50, change 34)",
             lambda led: build_payment(led, BOB, CAROL.pkh, 100, 1).tx, "ACCEPTED", 1),
        Step("Alice pays Carol 20, fee 3 from her 23 (exact: no change output)",
             lambda led: build_payment(led, ALICE, CAROL.pkh, 20, 3).tx, "ACCEPTED", 3),
        Step("Bob tries to spend the 85 he already spent", _respend, "DOUBLE_SPEND"),
    ]


def _respend(led: Ledger) -> Transaction:
    spent85 = next(op for op, by in led.spent.items() if op.index == 0 and op.txid == led.applied[1])
    tx = Transaction((TxIn(spent85),), (TxOut(80, MALLORY.pkh),))
    return sign(tx, [TxOut(85, BOB.pkh)], {BOB.pkh: BOB})


def describe(tx: Transaction, led: Ledger) -> tuple[str, str]:
    ins = []
    for i in tx.inputs:
        o = led.utxos.get(i.prev)
        if o:
            ins.append(f"{o.value} ({who(o.pkh)})")
        elif i.prev in led.spent:
            ins.append(f"{i.prev} (already spent)")
        else:
            ins.append(f"{i.prev} (unknown)")
    outs = [f"{o.value} → {who(o.pkh)}" for o in tx.outputs]
    return ", ".join(ins), ", ".join(outs)


def run(out_dir: str) -> list[dict]:
    snap_dir = os.path.join(out_dir, "snapshots")
    os.makedirs(snap_dir, exist_ok=True)
    led, gtx = Ledger.genesis([TxOut(40, ALICE.pkh), TxOut(70, ALICE.pkh), TxOut(50, BOB.pkh)])
    led.save(os.path.join(snap_dir, "00_genesis.json"))
    snaps = 1
    records = []
    for n, st in enumerate(steps(), 1):
        before = led.utxo_set_hash()
        tx = st.make(led)
        ins, outs = describe(tx, led)
        rec = {"step": n, "label": st.label, "txid": tx.txid if _encodable(tx) else None,
               "inputs": ins, "outputs": outs, "expected_fee": st.expected_fee, "state_before": before}
        try:
            res = led.apply(tx, st.expected_fee)
            rec.update(result="ACCEPTED", code=None, fee=res.fee, reason=f"fee {res.fee} (in {res.sum_in}, out {res.sum_out})")
            name = f"{snaps:02d}_after_step{n:02d}.json"
            led.save(os.path.join(snap_dir, name))
            rec["snapshot"] = f"snapshots/{name}"
            snaps += 1
        except Rejected as e:
            rec.update(result="REJECTED", code=e.code, fee=None, reason=e.reason)
        rec["state_after"] = led.utxo_set_hash()
        rec["state_unchanged"] = rec["state_before"] == rec["state_after"]
        rec["as_expected"] = (rec["result"] if rec["result"] == "ACCEPTED" else rec["code"]) == st.expect
        rec["balances"] = {who(p): led.balance(p) for p in NAMES}
        records.append(rec)

    led.save(os.path.join(snap_dir, f"{snaps:02d}_final.json"))
    with open(os.path.join(out_dir, "trace.jsonl"), "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    with open(os.path.join(out_dir, "trace.md"), "w", encoding="utf-8") as f:
        f.write(render_markdown(records, led, gtx))
    return records


def _encodable(tx: Transaction) -> bool:
    try:
        tx.body()
        return True
    except ValueError:
        return False


def render_markdown(records: list[dict], led: Ledger, gtx: Transaction) -> str:
    lines = ["# Assignment 4 — Ledger Trace", "",
             "Generated by `ledger scenario`. Actors use fixed test-only keys "
             "(Alice 0xA11CE, Bob 0xB0B, Carol 0xCA401, Mallory 0x3A11).", "",
             f"**Genesis** (`{gtx.txid[:16]}…`): Alice 40, Alice 70, Bob 50 — total 160.", "",
             "| # | Submission | Inputs | Outputs | Result | Reason | UTXO set |",
             "|---:|---|---|---|---|---|---|"]
    for r in records:
        res = "✅ ACCEPTED" if r["result"] == "ACCEPTED" else f"❌ `{r['code']}`"
        state = f"`{r['state_before'][:8]}` → `{r['state_after'][:8]}`" + (" unchanged" if r["state_unchanged"] else "")
        lines.append(f"| {r['step']} | {r['label']} | {r['inputs']} | {r['outputs']} | {res} | {r['reason']} | {state} |")
    b = records[-1]["balances"]
    lines += ["", "**Final balances:** " + ", ".join(f"{k} {v}" for k, v in b.items())
              + f" · fees collected {led.total_fees} · total {led.total_value()} + {led.total_fees} = {led.genesis_total} (supply conserved)",
              "", f"Every rejected submission left the UTXO-set hash unchanged: "
              f"**{all(r['state_unchanged'] for r in records if r['result'] == 'REJECTED')}**. "
              f"Every result matched expectation: **{all(r['as_expected'] for r in records)}**.", ""]
    return "\n".join(lines)
