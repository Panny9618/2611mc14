"""Stand-alone verifier written only from docs/transaction_format.md.

It does NOT import the toywallet package: it re-implements Base58Check
decoding and the byte layout from the specification, and uses `cryptography`
only for the ECDSA check. If this script and `wallet verify` agree, the
specification is complete enough for anyone to verify a signed transaction
from public data alone.

Usage: python scripts/independent_verify.py signed.json [expected_network]
"""

import hashlib
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
VERSIONS = {"course-testnet": 0x6F, "course-mainnet": 0x00}


def sha(b):
    return hashlib.sha256(b).digest()


def addr21(a, network):
    n = 0
    for c in a:
        n = n * 58 + B58.index(c)          # ValueError if not Base58
    raw = b"\0" * (len(a) - len(a.lstrip("1"))) + (n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b"")
    payload, chk = raw[:-4], raw[-4:]
    assert sha(sha(payload))[:4] == chk, "address checksum"
    assert len(payload) == 21 and payload[0] == VERSIONS[network], "address version/length"
    return payload


def main(path, network="course-testnet"):
    d = json.load(open(path, encoding="utf-8"))
    t = d["tx"]
    assert t["network_id"] == network, "wrong network"
    net = t["network_id"].encode()
    msg = (b"CTX\x00" + bytes([t["version"], len(net)]) + net + addr21(t["sender"], network)
           + addr21(t["recipient"], network) + t["amount_units"].to_bytes(8, "big")
           + t["nonce"].to_bytes(8, "big") + bytes.fromhex(t["memo_hash"]))
    pub = bytes.fromhex(d["public_key"])
    assert len(pub) == 33 and pub[0] in (2, 3), "compressed public key"
    assert addr21(t["sender"], network)[1:] == sha(pub)[:20], "public key does not hash to sender"
    sig = d["signature"]
    assert len(sig) == 128 and sig == sig.lower(), "signature encoding"
    r, s = int(sig[:64], 16), int(sig[64:], 16)
    assert 1 <= r < N and 1 <= s <= N // 2, "signature range / low-S"
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub)
    key.verify(encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256()))
    print(f"VALID (independent): {len(msg)} signed bytes, txid {sha(msg).hex()}")


if __name__ == "__main__":
    try:
        main(*sys.argv[1:])
    except (AssertionError, ValueError, KeyError, InvalidSignature) as e:
        print(f"REJECTED (independent): {type(e).__name__} {e}")
        sys.exit(1)
