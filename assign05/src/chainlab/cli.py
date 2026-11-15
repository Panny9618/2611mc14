"""chain: command-line interface for the node-local chain manager.

    chain keygen   --name miner
    chain init     --data node.json --give <ADDR>:<VALUE> ...
    chain mine     --data node.json --key keys/miner.key.json [--bits 16] [--parent REF] [--tx tx.json ...]
    chain pay      --data node.json --key keys/alice.key.json --to <ADDR> --amount N --fee F
    chain submit   --data node.json --block block.json
    chain status   --data node.json
    chain tree     --data node.json
    chain show     --data node.json --block REF          (REF = height on the active chain or hash prefix)
    chain simulate --out examples/fork_sim
    chain measure  --bits 12,16,20 --blocks 300,40,5

Exit codes: 0 ok · 1 block/tx rejected · 2 usage error.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Sequence

from . import __version__
from .block import Block, bits_of, target_for_bits
from .chain import Chain, make_genesis
from .crypto import CryptoError, KeyPair, address_of_pkh, load_key, pkh_of_address, save_key
from .state import Rejected
from .tx import Transaction, TxOut
from .wallet import InsufficientFunds, build_payment


class CliError(Exception):
    pass


def _load(path: str) -> Chain:
    if not os.path.exists(path):
        raise CliError(f"{path} not found; create it with `chain init`")
    return Chain.load(path)


def _key(path: str) -> KeyPair:
    try:
        return load_key(path)
    except (OSError, CryptoError, KeyError, ValueError) as e:
        raise CliError(f"cannot load key {path}: {e}") from None


def _pkh(addr: str) -> bytes:
    try:
        return pkh_of_address(addr)
    except CryptoError as e:
        raise CliError(str(e)) from None


def _print_result(r, indent="") -> None:
    print(indent + r.line())
    if r.status == "REORG":
        print(f"{indent}  disconnected: {[h[:12] for h in r.disconnected]}")
        print(f"{indent}  connected   : {[h[:12] for h in r.connected]}")
        print(f"{indent}  stale txs   : {len(r.resurrected)} returned to mempool, {len(r.conflicted)} dropped as conflicting")
    for c in r.children:
        _print_result(c, indent + "  (orphan) ")


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
    return 0


def cmd_init(a) -> int:
    if os.path.exists(a.data) and not a.force:
        raise CliError(f"{a.data} exists; use --force to replace it")
    outs = []
    for g in a.give or []:
        addr, _, val = g.rpartition(":")
        if not val.isdigit():
            raise CliError(f"--give must be ADDRESS:VALUE, got {g!r}")
        outs.append(TxOut(int(val), _pkh(addr)))
    if not outs:
        outs = [TxOut(1, bytes(20))]                        # unspendable placeholder
    g = make_genesis(outs)
    ch = Chain(g)
    ch.save(a.data)
    print(f"genesis {g.hash}  (height 0)")
    print(f"saved {a.data}")
    return 0


def cmd_mine(a) -> int:
    ch = _load(a.data)
    miner = _key(a.key)
    parent = ch.find(a.parent) if a.parent else None
    txs = None if not (a.tx or a.no_mempool) else [Transaction.from_json(open(p, "rb").read()) for p in (a.tx or [])]
    target = target_for_bits(a.bits)
    print(f"mining on {(parent or ch.tip.hash)[:16]}… at {a.bits} leading zero bits "
          f"(expected {2 ** a.bits:,} attempts)…", file=sys.stderr)
    m = ch.build_and_mine(miner.pkh, target, txs, parent=parent)
    print(f"found nonce {m.block.header.nonce:,} after {m.attempts:,} attempts in {m.seconds:.2f} s "
          f"({m.hashrate:,.0f} H/s); block has {len(m.block.txs)} txs", file=sys.stderr)
    print(m.block.header.dump())
    name = os.path.splitext(os.path.basename(a.key))[0].replace(".key", "")
    r = ch.submit(m.block, miner=name)
    _print_result(r)
    ch.save(a.data)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(m.block.to_json() + "\n")
        print(f"wrote {a.output}", file=sys.stderr)
    return 1 if r.status == "REJECTED" else 0


def cmd_pay(a) -> int:
    ch = _load(a.data)
    kp = _key(a.key)
    try:
        p = build_payment(ch.state, kp, _pkh(a.to), a.amount, a.fee)
    except InsufficientFunds as e:
        raise CliError(str(e)) from None
    try:
        ch.add_to_mempool(p.tx)
    except Rejected as e:
        print(f"REJECTED [{e.code}] {e.reason}")
        return 1
    ch.save(a.data)
    print(f"added {p.tx.txid[:16]}… to the mempool: pay {a.amount}, change {p.change}, fee {a.fee}")
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(p.tx.to_json() + "\n")
    return 0


def cmd_submit(a) -> int:
    ch = _load(a.data)
    try:
        b = Block.from_json(open(a.block, "rb").read())
    except (OSError, ValueError) as e:
        raise CliError(f"cannot read block: {e}") from None
    r = ch.submit(b, miner=a.miner)
    _print_result(r)
    ch.save(a.data)
    return 1 if r.status == "REJECTED" else 0


def cmd_status(a) -> int:
    ch = _load(a.data)
    t = ch.tip
    print(f"tip      {t.hash}")
    print(f"height   {t.height}    cumulative work {t.work:,}")
    print(f"utxo set {ch.state.utxo_set_hash()}  ({len(ch.state.utxos)} outputs, total {ch.state.total_value()})")
    print(f"known    {len(ch.entries)} blocks, {sum(1 for e in ch.entries.values() if e.invalid)} invalid; mempool {len(ch.mempool)} txs")
    by: dict[bytes, int] = {}
    for o in ch.state.utxos.values():
        by[o.pkh] = by.get(o.pkh, 0) + o.value
    for pkh, v in sorted(by.items(), key=lambda kv: -kv[1]):
        print(f"  {address_of_pkh(pkh)}  {v}")
    return 0


def cmd_tree(a) -> int:
    ch = _load(a.data)
    active = set(ch.active)
    print(f"{'h':>3}  {'hash':<18} {'miner':<10} {'bits':>5} {'cum. work':>12}  status")
    for e in sorted(ch.entries.values(), key=lambda e: (e.height, e.seq)):
        st = f"INVALID ({e.invalid})" if e.invalid else ("active" if e.hash in active else "stale branch")
        mark = "*" if e.hash == ch.tip.hash else " "
        print(f"{e.height:>3}{mark} {e.hash[:16]}… {e.miner[:10]:<10} {bits_of(e.header.target):>5.0f} {e.work:>12,}  {st}"
              + (f"   parent {e.parent[:10]}…" if e.parent and e.hash not in active else ""))
    return 0


def cmd_show(a) -> int:
    ch = _load(a.data)
    try:
        h = ch.find(a.block)
    except KeyError as e:
        raise CliError(str(e)) from None
    e, b = ch.entries[h], ch.blocks[h]
    print(f"block at height {e.height}, {len(b.txs)} transactions, cumulative work {e.work:,}\n")
    print(b.header.dump())
    for n, t in enumerate(b.txs):
        kind = "coinbase" if n == 0 else "tx"
        print(f"  {kind:<8} {t.txid[:16]}…  outputs {[o.value for o in t.outputs]}")
    return 0


def cmd_simulate(a) -> int:
    from .sim import run
    s = run(a.out)
    print(f"\nwrote {a.out}/fork_log.md, fork_diagram.svg, header_dump.txt, node.json")
    return 0 if s.ok else 1


def cmd_measure(a) -> int:
    from .measure import markdown, run
    bits = [int(x) for x in a.bits.split(",")]
    blocks = [int(x) for x in a.blocks.split(",")]
    if len(bits) != len(blocks):
        raise CliError("--bits and --blocks need the same number of values")
    rows = run(list(zip(bits, blocks)))
    md = markdown(rows)
    print("\n" + md)
    if a.md:
        with open(a.md, "w", encoding="utf-8") as f:
            f.write(md + "\n")
    return 0


# --------------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="chain", description="Toy proof-of-work chain manager.")
    p.add_argument("--version", action="version", version=f"chain {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("keygen"); sp.add_argument("--name", required=True); sp.add_argument("--dir", default="keys")
    sp.set_defaults(func=cmd_keygen)

    sp = sub.add_parser("init"); sp.add_argument("--data", required=True); sp.add_argument("--give", action="append", metavar="ADDR:VALUE")
    sp.add_argument("--force", action="store_true"); sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("mine", help="mine a block and submit it to this node")
    sp.add_argument("--data", required=True); sp.add_argument("--key", required=True, help="miner key (receives the coinbase)")
    sp.add_argument("--bits", type=int, default=16, help="leading zero bits of the target (default 16)")
    sp.add_argument("--parent", help="mine on this block instead of the tip (height or hash prefix) to create a fork")
    sp.add_argument("--tx", action="append", help="transaction file(s) to include")
    sp.add_argument("--no-mempool", action="store_true", help="do not include mempool transactions")
    sp.add_argument("-o", "--output", help="also write the block to this file"); sp.set_defaults(func=cmd_mine)

    sp = sub.add_parser("pay", help="build a payment against the tip and add it to the mempool")
    sp.add_argument("--data", required=True); sp.add_argument("--key", required=True); sp.add_argument("--to", required=True)
    sp.add_argument("--amount", type=int, required=True); sp.add_argument("--fee", type=int, required=True)
    sp.add_argument("-o", "--output"); sp.set_defaults(func=cmd_pay)

    sp = sub.add_parser("submit"); sp.add_argument("--data", required=True); sp.add_argument("--block", required=True)
    sp.add_argument("--miner", default=""); sp.set_defaults(func=cmd_submit)

    sp = sub.add_parser("status"); sp.add_argument("--data", required=True); sp.set_defaults(func=cmd_status)
    sp = sub.add_parser("tree"); sp.add_argument("--data", required=True); sp.set_defaults(func=cmd_tree)
    sp = sub.add_parser("show"); sp.add_argument("--data", required=True); sp.add_argument("--block", required=True)
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("simulate", help="two-miner fork simulation"); sp.add_argument("--out", default="examples/fork_sim")
    sp.set_defaults(func=cmd_simulate)

    sp = sub.add_parser("measure", help="hash rate and expected vs observed attempts")
    sp.add_argument("--bits", default="12,16,20"); sp.add_argument("--blocks", default="300,40,5")
    sp.add_argument("--md", help="write the table to this markdown file"); sp.set_defaults(func=cmd_measure)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        return a.func(a)
    except CliError as e:
        print(f"chain: error: {e}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return 0


if __name__ == "__main__":
    sys.exit(main())
