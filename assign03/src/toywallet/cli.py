"""wallet: command-line interface.

    wallet keygen  --name alice                    new key pair (private file 0600, public file)
    wallet address --pub keys/alice.pub.json       derive / explain an address
    wallet address --check <ADDRESS>               validate an address
    wallet tx      --from ... --to ... --amount ... --nonce ... --memo ...   build an unsigned tx
    wallet bytes   --tx tx.json                    byte-level dump of the signed message
    wallet sign    --key keys/alice.key.json --tx tx.json -o signed.json
    wallet verify  --signed signed.json [--nonces state.json --record]

Exit codes: 0 ok · 1 verification rejected · 2 any other error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Sequence

from . import __version__
from .address import DEFAULT_NETWORK, NETWORKS, address_from_pubkey, parse_address
from .base58 import b58decode
from .errors import WalletError
from .keys import KeyPair, generate_private_key, load_private_file, load_public_file, parse_public_hex, compressed, write_private_file, write_public_file
from .nonces import NonceStore
from .signing import dumps, sign_tx, verify_signed
from .tx import Transaction, memo_hash, strict_json


def _read(path: str) -> bytes:
    try:
        return sys.stdin.buffer.read() if path == "-" else open(path, "rb").read()
    except OSError as e:
        raise WalletError(WalletError.MALFORMED, f"cannot read {path}: {e.strerror}") from None


def _write_or_print(text: str, out: str | None) -> None:
    if out:
        with open(out, "w", encoding="utf-8", newline="\n") as f:
            f.write(text + "\n")
        print(f"wrote {out}", file=sys.stderr)
    else:
        print(text)


def _load_tx(path: str) -> Transaction:
    obj = strict_json(_read(path))
    if isinstance(obj, dict) and "tx" in obj and "signature" in obj:
        obj = obj["tx"]                 # accept a signed file too
    return Transaction.from_dict(obj)


# --------------------------------------------------------------------------- commands

def cmd_keygen(a) -> int:
    os.makedirs(a.dir, exist_ok=True)
    priv_path = os.path.join(a.dir, f"{a.name}.key.json")
    pub_path = os.path.join(a.dir, f"{a.name}.pub.json")
    kp = KeyPair(generate_private_key(), a.network)
    write_private_file(priv_path, kp)
    write_public_file(pub_path, kp)
    print(json.dumps(kp.public_record(), indent=2))
    print(f"\npublic key file : {pub_path}  (safe to share)", file=sys.stderr)
    print(f"private key file: {priv_path}  (permissions 0600, TEST ONLY - never share, never commit)", file=sys.stderr)
    return 0


def _explain(addr_text: str) -> None:
    a = parse_address(addr_text)
    raw = b58decode(addr_text)
    print(f"address    : {a.text}")
    print(f"network    : {a.network}")
    print(f"version    : 0x{a.version:02x}")
    print(f"pubkey hash: {a.pkh.hex()}   (SHA-256(public key)[:20])")
    print(f"checksum   : {raw[-4:].hex()}   (SHA-256(SHA-256(version||hash))[:4])")
    print("valid      : yes")


def cmd_address(a) -> int:
    if a.check:
        _explain(a.check)
        return 0
    if a.pub:
        rec = load_public_file(a.pub)
        pub_hex, net = rec["public_key"], a.network or rec["network_id"]
    else:
        pub_hex, net = a.public_key, a.network or DEFAULT_NETWORK
    pub = parse_public_hex(pub_hex)
    print(f"public key : {pub_hex}")
    _explain(address_from_pubkey(compressed(pub), net))
    return 0


def cmd_tx(a) -> int:
    rec = load_public_file(a.sender)
    if (a.memo is None) == (a.memo_hash is None):
        raise WalletError(WalletError.MALFORMED, "give exactly one of --memo or --memo-hash")
    tx = Transaction.from_dict({
        "version": 1, "network_id": rec["network_id"], "sender": rec["address"], "recipient": a.to,
        "amount_units": a.amount, "nonce": a.nonce,
        "memo_hash": memo_hash(a.memo) if a.memo is not None else a.memo_hash,
    })
    tx.to_bytes()                        # validate addresses now, not at signing time
    _write_or_print(json.dumps(tx.to_dict(), indent=2), a.output)
    return 0


def cmd_bytes(a) -> int:
    tx = _load_tx(a.tx)
    b = tx.to_bytes()
    print(f"{'offset':>6}  {'field':<13} {'size':>4}  {'hex':<66} meaning")
    for off, name, chunk, meaning in tx.layout():
        hx = chunk.hex()
        hx = hx if len(hx) <= 64 else hx[:61] + "..."
        print(f"{off:>6}  {name:<13} {len(chunk):>4}  {hx:<66} {meaning}")
    print(f"\ntotal bytes   : {len(b)}")
    print(f"signed bytes  : {b.hex()}")
    print(f"txid          : {tx.txid()}   (SHA-256 of the signed bytes)")
    print(f"canonical JSON: {tx.canonical_json()}")
    return 0


def _confirm(tx: Transaction, assume_yes: bool) -> None:
    print("about to sign:", file=sys.stderr)
    print(f"  network   : {tx.network_id}", file=sys.stderr)
    print(f"  recipient : {tx.recipient}", file=sys.stderr)
    print(f"  amount    : {tx.amount_units:,} units", file=sys.stderr)
    print(f"  nonce     : {tx.nonce}", file=sys.stderr)
    if assume_yes:
        return
    if not sys.stdin.isatty():
        raise WalletError(WalletError.MALFORMED, "non-interactive signing needs --yes after checking the details above")
    want = tx.recipient[-6:]
    got = input(f"Check the FULL recipient address against a trusted source, then type its last 6 characters: ").strip()
    if got != want:
        raise WalletError(WalletError.MALFORMED, "recipient confirmation did not match; nothing signed")


def cmd_sign(a) -> int:
    kp = load_private_file(a.key)
    tx = _load_tx(a.tx)
    tx.to_bytes()
    _confirm(tx, a.yes)
    signed = sign_tx(tx, kp, allow_mainnet=a.allow_mainnet)
    _write_or_print(dumps(signed), a.output)
    print(f"txid: {tx.txid()}", file=sys.stderr)
    return 0


def cmd_verify(a) -> int:
    store = NonceStore(a.nonces) if a.nonces else None
    try:
        v = verify_signed(_read(a.signed), a.network, store)
    except WalletError as e:
        print(f"REJECTED [{e.code}]: {e.message}")
        return 1
    if store is not None and a.record:
        store.record(v.tx.sender, v.tx.nonce)       # before any output, so a closed pipe can't skip it
    print("VALID")
    print(f"  signer   : {v.signer}")
    print(f"  recipient: {v.tx.recipient}")
    print(f"  amount   : {v.tx.amount_units:,} units   nonce: {v.tx.nonce}   network: {v.tx.network_id}")
    print(f"  txid     : {v.txid}")
    if store is None:
        print("  note     : no --nonces state given, so replay was not checked")
    elif a.record:
        print(f"  recorded nonce {v.tx.nonce} for {v.tx.sender} in {a.nonces}")
    return 0


# --------------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wallet", description="Educational secp256k1 wallet for the course toy chain.")
    p.add_argument("--version", action="version", version=f"wallet {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    nets = sorted(NETWORKS)

    sp = sub.add_parser("keygen", help="generate a key pair")
    sp.add_argument("--name", required=True)
    sp.add_argument("--dir", default="keys")
    sp.add_argument("--network", default=DEFAULT_NETWORK, choices=nets)
    sp.set_defaults(func=cmd_keygen)

    sp = sub.add_parser("address", help="derive, explain or check an address")
    g = sp.add_mutually_exclusive_group(required=True)
    g.add_argument("--pub", help="public key file")
    g.add_argument("--public-key", help="66-hex compressed public key")
    g.add_argument("--check", metavar="ADDRESS", help="validate an address")
    sp.add_argument("--network", choices=nets)
    sp.set_defaults(func=cmd_address)

    sp = sub.add_parser("tx", help="build an unsigned transaction")
    sp.add_argument("--from", dest="sender", required=True, help="sender's .pub.json")
    sp.add_argument("--to", required=True, help="recipient address")
    sp.add_argument("--amount", type=int, required=True, help="amount in smallest integer units")
    sp.add_argument("--nonce", type=int, required=True)
    sp.add_argument("--memo")
    sp.add_argument("--memo-hash")
    sp.add_argument("-o", "--output")
    sp.set_defaults(func=cmd_tx)

    sp = sub.add_parser("bytes", help="byte-level dump of a transaction")
    sp.add_argument("--tx", required=True)
    sp.set_defaults(func=cmd_bytes)

    sp = sub.add_parser("sign", help="sign a transaction")
    sp.add_argument("--key", required=True, help="private key file")
    sp.add_argument("--tx", required=True)
    sp.add_argument("-o", "--output")
    sp.add_argument("--yes", action="store_true", help="skip the interactive recipient confirmation")
    sp.add_argument("--allow-mainnet", action="store_true")
    sp.set_defaults(func=cmd_sign)

    sp = sub.add_parser("verify", help="verify a signed transaction independently")
    sp.add_argument("--signed", required=True)
    sp.add_argument("--network", default=DEFAULT_NETWORK, help="network this verifier is on")
    sp.add_argument("--nonces", help="JSON file of last accepted nonce per sender (enables replay check)")
    sp.add_argument("--record", action="store_true", help="after a VALID result, record the nonce")
    sp.set_defaults(func=cmd_verify)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        return a.func(a)
    except WalletError as e:
        print(f"wallet: error [{e.code}]: {e.message}", file=sys.stderr)
        return 2
    except BrokenPipeError:                 # e.g. `wallet verify ... | head -1`
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 0


if __name__ == "__main__":
    sys.exit(main())
