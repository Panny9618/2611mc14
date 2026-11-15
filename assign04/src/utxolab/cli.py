"""ledger: command-line interface.

    ledger keygen   --name alice
    ledger init     --state state.json --give <ADDRESS>:<VALUE> [--give ...]
    ledger balance  --state state.json
    ledger utxos    --state state.json [--address A]
    ledger pay      --state state.json --key keys/alice.key.json --to <ADDR> --amount 85 --fee 2 -o tx.json
    ledger show     --tx tx.json
    ledger submit   --state state.json --tx tx.json [--expect-fee 2] [--trace trace.jsonl]
    ledger scenario --out examples/scenario

Exit codes: 0 ok / accepted · 1 rejected · 2 other error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Sequence

from . import __version__
from .crypto import CryptoError, KeyPair, address_of_pkh, load_key, pkh_of_address, save_key
from .ledger import Ledger, Rejected
from .tx import Transaction, TxFormatError, TxOut
from .wallet import STRATEGY, InsufficientFunds, build_payment


class CliError(Exception):
    pass


def _load_state(path: str) -> Ledger:
    if not os.path.exists(path):
        raise CliError(f"{path} not found; create it with `ledger init`")
    try:
        return Ledger.load(path)
    except (ValueError, KeyError) as e:
        raise CliError(f"cannot load {path}: {e}") from None


def _addr(text: str) -> bytes:
    try:
        return pkh_of_address(text)
    except CryptoError as e:
        raise CliError(str(e)) from None


# --------------------------------------------------------------------------- commands

def cmd_keygen(a) -> int:
    os.makedirs(a.dir, exist_ok=True)
    path = os.path.join(a.dir, f"{a.name}.key.json")
    kp = KeyPair.generate()
    try:
        save_key(path, kp)
    except FileExistsError:
        raise CliError(f"{path} exists; refusing to overwrite") from None
    print(f"address: {kp.address}")
    print(f"private key saved to {path} (0600, test only)", file=sys.stderr)
    return 0


def cmd_init(a) -> int:
    if os.path.exists(a.state) and not a.force:
        raise CliError(f"{a.state} exists; use --force to replace it")
    outs = []
    for g in a.give:
        addr, _, val = g.rpartition(":")
        if not addr or not val.isdigit():
            raise CliError(f"--give must be ADDRESS:VALUE, got {g!r}")
        outs.append(TxOut(int(val), _addr(addr)))
    led, gtx = Ledger.genesis(outs)
    led.save(a.state)
    print(f"genesis {gtx.txid}")
    for i, o in enumerate(outs):
        print(f"  {gtx.txid[:12]}…:{i}  {o.value:>10}  {address_of_pkh(o.pkh)}")
    print(f"saved {a.state}  utxo_set_hash {led.utxo_set_hash()}")
    return 0


def cmd_balance(a) -> int:
    led = _load_state(a.state)
    by: dict[bytes, list[int]] = {}
    for o in led.utxos.values():
        by.setdefault(o.pkh, []).append(o.value)
    for pkh, vals in sorted(by.items(), key=lambda kv: -sum(kv[1])):
        print(f"{address_of_pkh(pkh)}  {sum(vals):>10}  ({len(vals)} coin{'s' if len(vals) != 1 else ''}: {sorted(vals, reverse=True)})")
    print(f"total unspent {led.total_value()} + fees {led.total_fees} = genesis {led.genesis_total}")
    print(f"utxo_set_hash {led.utxo_set_hash()}")
    return 0


def cmd_utxos(a) -> int:
    led = _load_state(a.state)
    want = _addr(a.address) if a.address else None
    for op in sorted(led.utxos):
        o = led.utxos[op]
        if want is None or o.pkh == want:
            print(f"{op.txid}:{op.index}  {o.value:>10}  p2pkh {o.pkh.hex()}  {address_of_pkh(o.pkh)}")
    return 0


def cmd_pay(a) -> int:
    led = _load_state(a.state)
    try:
        kp = load_key(a.key)
    except (OSError, CryptoError, KeyError, ValueError) as e:
        raise CliError(f"cannot load key: {e}") from None
    try:
        p = build_payment(led, kp, _addr(a.to), a.amount, a.fee)
    except InsufficientFunds as e:
        raise CliError(str(e)) from None
    print(f"coin selection ({STRATEGY}) for amount {a.amount} + fee {a.fee} = {a.amount + a.fee}:", file=sys.stderr)
    for op, o in p.selected:
        print(f"  spend {op}  {o.value}", file=sys.stderr)
    print(f"  total {sum(o.value for _, o in p.selected)} → pay {a.amount}, change {p.change}, fee {a.fee}", file=sys.stderr)
    print(f"txid {p.tx.txid}", file=sys.stderr)
    with open(a.output, "w", encoding="utf-8") as f:
        f.write(p.tx.to_json() + "\n")
    print(f"wrote {a.output} (not yet submitted)", file=sys.stderr)
    return 0


def _read_tx(path: str) -> Transaction:
    try:
        return Transaction.from_json(open(path, "rb").read())
    except OSError as e:
        raise CliError(f"cannot read {path}: {e.strerror}") from None


def cmd_show(a) -> int:
    tx = _read_tx(a.tx)
    print(f"txid  {tx.txid}   (SHA-256 of the {len(tx.body())}-byte body; signatures excluded)")
    for n, i in enumerate(tx.inputs):
        print(f"in  {n}: {i.prev.txid}:{i.prev.index}  {'signed' if i.unlock else 'UNSIGNED'}")
    for n, o in enumerate(tx.outputs):
        print(f"out {n}: {o.value:>10} → {address_of_pkh(o.pkh)}")
    print(f"body  {tx.body().hex()}")
    return 0


def cmd_submit(a) -> int:
    led = _load_state(a.state)
    before = led.utxo_set_hash()
    rec = {"time": time.strftime("%Y-%m-%dT%H:%M:%S"), "tx_file": a.tx}
    try:
        tx = _read_tx(a.tx)
        rec["txid"] = tx.txid if _ok(tx) else None
        res = led.apply(tx, a.expect_fee)
        led.save(a.state)
        rec.update(result="ACCEPTED", fee=res.fee)
        print(f"ACCEPTED {res.txid}")
        print(f"  inputs {res.sum_in} → outputs {res.sum_out}, fee {res.fee}")
        code = 0
    except (Rejected, TxFormatError) as e:
        c, reason = (e.code, e.reason) if isinstance(e, Rejected) else ("MALFORMED", str(e))
        rec.update(result="REJECTED", code=c, reason=reason)
        print(f"REJECTED [{c}] {reason}")
        code = 1
    after = led.utxo_set_hash()
    rec.update(state_before=before, state_after=after)
    print(f"  utxo_set_hash {before[:16]}… → {after[:16]}…{'  (unchanged)' if before == after else ''}")
    if a.trace:
        with open(a.trace, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    return code


def _ok(tx: Transaction) -> bool:
    try:
        tx.body()
        return True
    except ValueError:
        return False


def cmd_scenario(a) -> int:
    from .scenario import run
    recs = run(a.out)
    for r in recs:
        res = "ACCEPTED" if r["result"] == "ACCEPTED" else f"REJECTED [{r['code']}]"
        ok = "" if r["as_expected"] else "   <-- UNEXPECTED"
        print(f"{r['step']:>2}. {res:<34} {r['label']}{ok}")
    print(f"\nwrote {a.out}/trace.md, trace.jsonl and snapshots/")
    print("final balances: " + ", ".join(f"{k} {v}" for k, v in recs[-1]["balances"].items()))
    return 0 if all(r["as_expected"] for r in recs) else 1


# --------------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ledger", description="In-memory UTXO ledger and validator.")
    p.add_argument("--version", action="version", version=f"ledger {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("keygen"); sp.add_argument("--name", required=True); sp.add_argument("--dir", default="keys")
    sp.set_defaults(func=cmd_keygen)

    sp = sub.add_parser("init", help="create a ledger with genesis outputs")
    sp.add_argument("--state", required=True); sp.add_argument("--give", action="append", required=True, metavar="ADDR:VALUE")
    sp.add_argument("--force", action="store_true"); sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("balance"); sp.add_argument("--state", required=True); sp.set_defaults(func=cmd_balance)

    sp = sub.add_parser("utxos"); sp.add_argument("--state", required=True); sp.add_argument("--address")
    sp.set_defaults(func=cmd_utxos)

    sp = sub.add_parser("pay", help="wallet: select coins, add change, sign")
    sp.add_argument("--state", required=True); sp.add_argument("--key", required=True); sp.add_argument("--to", required=True)
    sp.add_argument("--amount", type=int, required=True); sp.add_argument("--fee", type=int, required=True)
    sp.add_argument("-o", "--output", required=True); sp.set_defaults(func=cmd_pay)

    sp = sub.add_parser("show"); sp.add_argument("--tx", required=True); sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("submit", help="validate and apply a transaction")
    sp.add_argument("--state", required=True); sp.add_argument("--tx", required=True)
    sp.add_argument("--expect-fee", type=int, help="reject with INCORRECT_CHANGE if the implied fee differs")
    sp.add_argument("--trace", help="append a JSON line per submission to this file"); sp.set_defaults(func=cmd_submit)

    sp = sub.add_parser("scenario", help="run the scripted accepted/rejected scenario")
    sp.add_argument("--out", default="examples/scenario"); sp.set_defaults(func=cmd_scenario)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        return a.func(a)
    except CliError as e:
        print(f"ledger: error: {e}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0


if __name__ == "__main__":
    sys.exit(main())
