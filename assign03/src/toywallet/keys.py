"""Key generation and key files.

* The private scalar comes from the operating system's CSPRNG
  (`secrets.token_bytes`, i.e. os.urandom / getrandom). Values outside
  [1, n-1] are rejected and re-drawn, so there is no modulo bias.
* All curve arithmetic (scalar -> public point, point validation) is done by
  the `cryptography` library.
* Private key files are created atomically with permissions 0600 and refuse to
  overwrite; loading refuses files that group/others can read.
"""

from __future__ import annotations

import json
import os
import secrets
import stat
import sys
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .address import address_from_pubkey, check_network
from .errors import WalletError

CURVE = ec.SECP256K1()
# secp256k1 group order n
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

WARNING = ("TEST-ONLY PRIVATE KEY. Never use it for real funds or on a real network. "
           "Anyone who can read this file can sign transactions for the address below.")


def generate_private_key() -> ec.EllipticCurvePrivateKey:
    while True:
        d = int.from_bytes(secrets.token_bytes(32), "big")
        if 1 <= d < N:
            return ec.derive_private_key(d, CURVE)


def private_from_hex(h: str) -> ec.EllipticCurvePrivateKey:
    if not isinstance(h, str) or len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
        raise WalletError(WalletError.KEY_FILE, "private_key must be 64 lowercase hex characters")
    d = int(h, 16)
    if not 1 <= d < N:
        raise WalletError(WalletError.KEY_FILE, "private key out of range [1, n-1]")
    return ec.derive_private_key(d, CURVE)


def private_to_hex(k: ec.EllipticCurvePrivateKey) -> str:
    return k.private_numbers().private_value.to_bytes(32, "big").hex()


def compressed(pub: ec.EllipticCurvePublicKey) -> bytes:
    return pub.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def load_public_key(data: bytes) -> ec.EllipticCurvePublicKey:
    """Accept only a valid 33-byte compressed point that lies on secp256k1."""
    if len(data) != 33 or data[0] not in (2, 3):
        raise WalletError(WalletError.MALFORMED_PUBLIC_KEY, "public key must be 33-byte compressed SEC1 (02/03 prefix)")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, data)
    except ValueError:
        raise WalletError(WalletError.MALFORMED_PUBLIC_KEY, "public key is not a point on secp256k1") from None


def parse_public_hex(h: str) -> ec.EllipticCurvePublicKey:
    if not isinstance(h, str) or len(h) != 66 or any(c not in "0123456789abcdef" for c in h):
        raise WalletError(WalletError.MALFORMED_PUBLIC_KEY, "public_key must be 66 lowercase hex characters")
    return load_public_key(bytes.fromhex(h))


@dataclass(frozen=True)
class KeyPair:
    private: ec.EllipticCurvePrivateKey
    network_id: str

    @property
    def public_bytes(self) -> bytes:
        return compressed(self.private.public_key())

    @property
    def address(self) -> str:
        return address_from_pubkey(self.public_bytes, self.network_id)

    def public_record(self) -> dict:
        return {"network_id": self.network_id, "public_key": self.public_bytes.hex(), "address": self.address}


# --------------------------------------------------------------------------- files

def write_private_file(path: str, kp: KeyPair) -> None:
    rec = {"WARNING": WARNING, **kp.public_record(), "private_key": private_to_hex(kp.private)}
    data = (json.dumps(rec, indent=2) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        raise WalletError(WalletError.KEY_FILE, f"{path} already exists; refusing to overwrite a key") from None
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    if os.name == "posix":
        os.chmod(path, 0o600)  # in case the umask widened nothing; keep it exact


def write_public_file(path: str, kp: KeyPair) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(kp.public_record(), indent=2) + "\n")


def load_private_file(path: str) -> KeyPair:
    try:
        st = os.stat(path)
    except OSError as e:
        raise WalletError(WalletError.KEY_FILE, f"cannot read {path}: {e.strerror}") from None
    if os.name == "posix" and st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise WalletError(WalletError.KEY_FILE,
                          f"{path} has permissions {stat.filemode(st.st_mode)}; group/others must have no access. "
                          f"Fix with: chmod 600 {path}")
    try:
        rec = json.loads(open(path, encoding="utf-8").read())
        kp = KeyPair(private_from_hex(rec["private_key"]), rec["network_id"])
    except (ValueError, KeyError, TypeError) as e:
        if isinstance(e, WalletError):
            raise
        raise WalletError(WalletError.KEY_FILE, f"{path} is not a valid key file") from None
    check_network(kp.network_id)
    if rec.get("public_key") != kp.public_bytes.hex() or rec.get("address") != kp.address:
        raise WalletError(WalletError.KEY_FILE, f"{path}: stored public key/address do not match the private key")
    print(f"warning: using {WARNING.split('.')[0].lower()} from {path}", file=sys.stderr)
    return kp


def load_public_file(path: str) -> dict:
    try:
        rec = json.loads(open(path, encoding="utf-8").read())
    except (OSError, ValueError):
        raise WalletError(WalletError.KEY_FILE, f"cannot read public key file {path}") from None
    if "private_key" in rec:
        raise WalletError(WalletError.KEY_FILE, f"{path} contains a private key; pass the .pub.json file instead")
    pub = parse_public_hex(rec.get("public_key"))
    net = rec.get("network_id")
    check_network(net)
    if address_from_pubkey(compressed(pub), net) != rec.get("address"):
        raise WalletError(WalletError.KEY_FILE, f"{path}: address does not match public key")
    return rec
