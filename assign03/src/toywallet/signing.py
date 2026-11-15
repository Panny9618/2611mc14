"""Signing and independent verification.

Signature scheme : ECDSA over secp256k1 with SHA-256 of the canonical transaction bytes.
Signature format : exactly 64 bytes  r || s  (32-byte big-endian each), sent as 128 lowercase hex.
Canonical rules  : 1 <= r < n,  1 <= s <= n/2  ("low-S").

Why low-S: if (r, s) is valid then (r, n - s) is also valid for the same message.
Accepting both would let anyone change a signature (and any ID computed over it)
without the key. The signer therefore always outputs the low-S form, and the
verifier rejects the high-S twin as non-canonical. Variable-length DER, uppercase
hex or a 0x prefix are rejected too: there is exactly one valid encoding.

Signed transaction JSON (exactly these keys):
    {"tx": {...}, "public_key": "<66 hex>", "signature": "<128 hex>"}
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from .address import MAINNET, address_from_pubkey
from .errors import WalletError
from .keys import N, KeyPair, compressed, parse_public_hex
from .nonces import NonceStore
from .tx import Transaction, strict_json

HALF_N = N // 2
_SIG_RE = re.compile(r"[0-9a-f]{128}")
ALGO = ec.ECDSA(hashes.SHA256())


def sign_tx(tx: Transaction, kp: KeyPair, allow_mainnet: bool = False) -> dict:
    if tx.network_id == MAINNET and not allow_mainnet:
        raise WalletError(WalletError.MAINNET_BLOCKED,
                          "refusing to sign a course-mainnet transaction without --allow-mainnet")
    if tx.network_id != kp.network_id:
        raise WalletError(WalletError.WRONG_NETWORK,
                          f"key is for {kp.network_id} but transaction is for {tx.network_id}")
    msg = tx.to_bytes()                                   # also validates both addresses
    if tx.sender != kp.address:
        raise WalletError(WalletError.WRONG_SIGNER, f"sender {tx.sender} is not this key's address {kp.address}")
    r, s = decode_dss_signature(kp.private.sign(msg, ALGO))
    if s > HALF_N:
        s = N - s                                         # normalise to low-S
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return {"tx": tx.to_dict(), "public_key": kp.public_bytes.hex(), "signature": sig.hex()}


def parse_signature(h: str) -> tuple[int, int]:
    if not isinstance(h, str) or not _SIG_RE.fullmatch(h):
        raise WalletError(WalletError.NON_CANONICAL_SIGNATURE,
                          "signature must be exactly 128 lowercase hex characters (64-byte r||s)")
    r, s = int(h[:64], 16), int(h[64:], 16)
    if not 1 <= r < N:
        raise WalletError(WalletError.NON_CANONICAL_SIGNATURE, "r out of range [1, n-1]")
    if not 1 <= s < N:
        raise WalletError(WalletError.NON_CANONICAL_SIGNATURE, "s out of range [1, n-1]")
    if s > HALF_N:
        raise WalletError(WalletError.NON_CANONICAL_SIGNATURE, "high-S signature (s > n/2); only the low-S form is canonical")
    return r, s


@dataclass(frozen=True)
class Verified:
    tx: Transaction
    txid: str
    signer: str


def verify_signed(raw: str | bytes | dict, expected_network: str, nonces: NonceStore | None = None) -> Verified:
    """Check every rule; raise WalletError with a specific code on the first failure."""
    obj = strict_json(raw) if not isinstance(raw, dict) else raw
    if not isinstance(obj, dict) or set(obj) != {"tx", "public_key", "signature"}:
        raise WalletError(WalletError.MALFORMED, "signed transaction must have exactly keys tx, public_key, signature")
    tx = Transaction.from_dict(obj["tx"])
    if tx.network_id != expected_network:
        raise WalletError(WalletError.WRONG_NETWORK,
                          f"transaction is for {tx.network_id!r} but this verifier is on {expected_network!r}")
    msg = tx.to_bytes()                                   # validates addresses + checksums + their network
    pub = parse_public_hex(obj["public_key"])
    r, s = parse_signature(obj["signature"])
    signer = address_from_pubkey(compressed(pub), tx.network_id)
    if signer != tx.sender:
        raise WalletError(WalletError.WRONG_SIGNER, f"public key belongs to {signer}, not sender {tx.sender}")
    try:
        pub.verify(encode_dss_signature(r, s), msg, ALGO)
    except InvalidSignature:
        raise WalletError(WalletError.BAD_SIGNATURE,
                          "signature does not match the transaction bytes (a signed field was changed)") from None
    if nonces is not None:
        nonces.check(tx.sender, tx.nonce)
    return Verified(tx, tx.txid(), signer)


def dumps(signed: dict) -> str:
    return json.dumps(signed, indent=2)
