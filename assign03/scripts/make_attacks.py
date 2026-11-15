"""Turn one valid signed transaction into a set of attack / mistake files.

Usage: python scripts/make_attacks.py signed.json attacks/

Every output must be REJECTED by `wallet verify` except reordered_whitespace.json,
which is the same transaction with different key order and spacing and must be VALID.
"""

from __future__ import annotations

import copy
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature  # noqa: E402

from toywallet.keys import N, KeyPair, generate_private_key  # noqa: E402
from toywallet.signing import ALGO  # noqa: E402
from toywallet.tx import Transaction  # noqa: E402


def flip_char(addr: str, pos: int) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    c = addr[pos]
    return addr[:pos] + alphabet[(alphabet.index(c) + 1) % 58] + addr[pos + 1:]


def main(src: str, out_dir: str) -> None:
    good = json.load(open(src, encoding="utf-8"))
    os.makedirs(out_dir, exist_ok=True)
    made = {}

    def make(name, fn, note):
        d = copy.deepcopy(good)
        fn(d)
        made[name] = note
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
            json.dump(d, f, indent=2)

    make("tampered_amount.json", lambda d: d["tx"].__setitem__("amount_units", d["tx"]["amount_units"] * 100),
         "amount multiplied by 100 after signing -> BAD_SIGNATURE")
    make("tampered_recipient.json", lambda d: d["tx"].__setitem__("recipient", d["tx"]["sender"]),
         "recipient swapped after signing -> BAD_SIGNATURE")
    make("wrong_network.json", lambda d: d["tx"].__setitem__("network_id", "course-mainnet"),
         "network_id changed to course-mainnet -> WRONG_NETWORK")
    make("malformed_address.json", lambda d: d["tx"].__setitem__("recipient", "m0OIl-not-base58"),
         "recipient contains characters outside Base58 -> MALFORMED_ADDRESS")
    make("bad_checksum.json", lambda d: d["tx"].__setitem__("recipient", flip_char(d["tx"]["recipient"], 10)),
         "one character of the recipient mistyped -> INVALID_CHECKSUM")

    r, s = int(good["signature"][:64], 16), int(good["signature"][64:], 16)
    make("high_s.json", lambda d: d.__setitem__("signature", f"{r:064x}{N - s:064x}"),
         "(r, n-s): mathematically valid twin of the signature -> NON_CANONICAL_SIGNATURE")
    make("der_signature.json", lambda d: d.__setitem__("signature", encode_dss_signature(r, s).hex()),
         "same signature but DER-encoded -> NON_CANONICAL_SIGNATURE")
    make("uppercase_signature.json", lambda d: d.__setitem__("signature", good["signature"].upper()),
         "same signature in uppercase hex -> NON_CANONICAL_SIGNATURE")

    # Mallory signs Alice's transaction with her own key and attaches her public key.
    tx = Transaction.from_dict(good["tx"])
    mallory = KeyPair(generate_private_key(), tx.network_id)
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    mr, ms = decode_dss_signature(mallory.private.sign(tx.to_bytes(), ALGO))
    ms = min(ms, N - ms)
    make("wrong_signer.json", lambda d: (d.__setitem__("public_key", mallory.public_bytes.hex()),
                                         d.__setitem__("signature", f"{mr:064x}{ms:064x}")),
         "valid signature by a different key (Mallory) -> WRONG_SIGNER")

    # Same transaction, different JSON key order and whitespace: must stay VALID.
    reordered = {"signature": good["signature"], "public_key": good["public_key"],
                 "tx": dict(reversed(list(good["tx"].items())))}
    with open(os.path.join(out_dir, "reordered_whitespace.json"), "w", encoding="utf-8") as f:
        f.write(json.dumps(reordered, indent=7, separators=(" ,  ", " :   ")))
    made["reordered_whitespace.json"] = "same tx, reversed key order + odd whitespace -> VALID (same signed bytes)"

    for name, note in made.items():
        print(f"{name:<28} {note}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
