"""Keys, addresses and low-S ECDSA (same conventions as Assignment 3).

All elliptic-curve work is done by the `cryptography` library; randomness comes
from the OS (`secrets`). Addresses are Base58Check(0x6f || PKH) on course-testnet,
where PKH = SHA-256(compressed public key)[:20].
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .base58 import Base58Error, ChecksumError, b58check_decode, b58check_encode

CURVE = ec.SECP256K1()
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HALF_N = N // 2
ALGO = ec.ECDSA(hashes.SHA256())
TESTNET_VERSION = 0x6F
WARNING = "TEST-ONLY PRIVATE KEY. Never use it for real funds."


class CryptoError(ValueError):
    pass


def pkh_of(pub33: bytes) -> bytes:
    return hashlib.sha256(pub33).digest()[:20]


def address_of_pkh(pkh: bytes) -> str:
    return b58check_encode(bytes([TESTNET_VERSION]) + pkh)


def pkh_of_address(addr: str) -> bytes:
    try:
        payload = b58check_decode(addr)
    except ChecksumError:
        raise CryptoError(f"address {addr!r}: invalid checksum") from None
    except Base58Error as e:
        raise CryptoError(f"address {addr!r}: {e}") from None
    if len(payload) != 21 or payload[0] != TESTNET_VERSION:
        raise CryptoError(f"address {addr!r}: not a course-testnet P2PKH address")
    return payload[1:]


@dataclass(frozen=True)
class KeyPair:
    private: ec.EllipticCurvePrivateKey

    @classmethod
    def generate(cls) -> "KeyPair":
        while True:
            d = int.from_bytes(secrets.token_bytes(32), "big")
            if 1 <= d < N:
                return cls(ec.derive_private_key(d, CURVE))

    @classmethod
    def from_scalar(cls, d: int) -> "KeyPair":
        """For reproducible demos and tests only."""
        return cls(ec.derive_private_key(d, CURVE))

    @property
    def public_bytes(self) -> bytes:
        return self.private.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

    @property
    def pkh(self) -> bytes:
        return pkh_of(self.public_bytes)

    @property
    def address(self) -> str:
        return address_of_pkh(self.pkh)

    def sign(self, msg: bytes) -> bytes:
        r, s = decode_dss_signature(self.private.sign(msg, ALGO))
        s = min(s, N - s)                                    # low-S
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def load_public(pub33: bytes) -> ec.EllipticCurvePublicKey:
    if len(pub33) != 33 or pub33[0] not in (2, 3):
        raise CryptoError("public key must be 33-byte compressed")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, pub33)
    except ValueError:
        raise CryptoError("public key is not on secp256k1") from None


def check_signature_encoding(sig: bytes) -> tuple[int, int]:
    if len(sig) != 64:
        raise CryptoError("signature must be 64 bytes r||s")
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r < N and 1 <= s <= HALF_N):
        raise CryptoError("signature r/s out of range or high-S")
    return r, s


def verify(pub33: bytes, sig: bytes, msg: bytes) -> bool:
    r, s = check_signature_encoding(sig)
    try:
        load_public(pub33).verify(encode_dss_signature(r, s), msg, ALGO)
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------- key files

def save_key(path: str, kp: KeyPair) -> None:
    rec = {"WARNING": WARNING, "public_key": kp.public_bytes.hex(), "address": kp.address,
           "private_key": kp.private.private_numbers().private_value.to_bytes(32, "big").hex()}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(rec, indent=2) + "\n")


def load_key(path: str) -> KeyPair:
    st = os.stat(path)
    if os.name == "posix" and st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise CryptoError(f"{path} is readable by others; run: chmod 600 {path}")
    rec = json.loads(open(path, encoding="utf-8").read())
    kp = KeyPair(ec.derive_private_key(int(rec["private_key"], 16), CURVE))
    if kp.address != rec.get("address"):
        raise CryptoError(f"{path}: address does not match private key")
    return kp
