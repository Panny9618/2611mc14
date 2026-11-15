import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from toywallet.errors import WalletError
from toywallet.keys import N, KeyPair, generate_private_key
from toywallet.nonces import NonceStore
from toywallet.signing import HALF_N, sign_tx, verify_signed
from toywallet.tx import Transaction

ROOT = Path(__file__).resolve().parent.parent
NET = "course-testnet"


def code_of(signed, network=NET, store=None):
    with pytest.raises(WalletError) as e:
        verify_signed(signed, network, store)
    return e.value.code


def test_sign_and_verify(tx, alice):
    s = sign_tx(tx, alice)
    v = verify_signed(s, NET)
    assert v.signer == alice.address and v.tx == tx


def test_signatures_always_low_s(tx, alice):
    for _ in range(40):
        assert int(sign_tx(tx, alice)["signature"][64:], 16) <= HALF_N


def test_verify_from_json_text_with_other_formatting(tx, alice):
    s = sign_tx(tx, alice)
    text = json.dumps({"signature": s["signature"], "tx": dict(reversed(list(s["tx"].items()))),
                       "public_key": s["public_key"]}, indent=5)
    verify_signed(text, NET)


@pytest.mark.parametrize("field,value,code", [
    ("amount_units", 1_250_001, "BAD_SIGNATURE"),
    ("amount_units", 125_000_000, "BAD_SIGNATURE"),
    ("nonce", 8, "BAD_SIGNATURE"),
    ("memo_hash", "00" * 32, "BAD_SIGNATURE"),
])
def test_changing_any_signed_field_fails(tx, alice, field, value, code):
    s = sign_tx(tx, alice)
    s["tx"][field] = value
    assert code_of(s) == code


def test_changing_recipient_fails(tx, alice):
    s = sign_tx(tx, alice)
    s["tx"]["recipient"] = alice.address
    assert code_of(s) == "BAD_SIGNATURE"


def test_changing_sender_fails(tx, alice, bob):
    s = sign_tx(tx, alice)
    s["tx"]["sender"] = bob.address
    assert code_of(s) == "WRONG_SIGNER"


def test_wrong_network(tx, alice):
    s = sign_tx(tx, alice)
    assert code_of(s, network="course-mainnet") == "WRONG_NETWORK"
    s2 = copy.deepcopy(s)
    s2["tx"]["network_id"] = "course-mainnet"
    assert code_of(s2) == "WRONG_NETWORK"
    assert code_of(s2, network="course-mainnet") == "WRONG_NETWORK"   # addresses are testnet


def test_wrong_signer(tx, alice):
    mallory = KeyPair(generate_private_key(), NET)
    forged = Transaction(**{**tx.to_dict(), "sender": mallory.address})
    s = sign_tx(forged, mallory)
    s["tx"] = tx.to_dict()                                    # claim it is Alice's
    assert code_of(s) == "WRONG_SIGNER"
    s = sign_tx(tx, alice)
    s["public_key"] = mallory.public_bytes.hex()
    assert code_of(s) == "WRONG_SIGNER"


def test_replayed_nonce(tx, alice, tmp_path):
    state = tmp_path / "nonces.json"
    s = sign_tx(tx, alice)
    store = NonceStore(str(state))
    v = verify_signed(s, NET, store)
    store.record(v.tx.sender, v.tx.nonce)
    assert code_of(s, store=NonceStore(str(state))) == "REPLAYED_NONCE"       # reloaded from disk
    older = sign_tx(Transaction(**{**tx.to_dict(), "nonce": 3}), alice)
    assert code_of(older, store=NonceStore(str(state))) == "REPLAYED_NONCE"
    newer = sign_tx(Transaction(**{**tx.to_dict(), "nonce": 8}), alice)
    verify_signed(newer, NET, NonceStore(str(state)))


def test_nonce_is_per_sender(tx, alice, bob):
    store = NonceStore()
    store.record(alice.address, 7)
    store.check(bob.address, 7)


@pytest.mark.parametrize("field", ["sender", "recipient"])
def test_malformed_and_bad_checksum_addresses(tx, alice, field):
    s = sign_tx(tx, alice)
    s1 = copy.deepcopy(s)
    s1["tx"][field] = "m0OIl0OIl"
    assert code_of(s1) == "MALFORMED_ADDRESS"
    s2 = copy.deepcopy(s)
    a = s2["tx"][field]
    s2["tx"][field] = a[:-1] + ("2" if a[-1] != "2" else "3")
    assert code_of(s2) == "INVALID_CHECKSUM"


def _sig(s):
    return int(s["signature"][:64], 16), int(s["signature"][64:], 16)


@pytest.mark.parametrize("make", [
    lambda r, s, h: f"{r:064x}{N - s:064x}",                 # high-S twin
    lambda r, s, h: encode_dss_signature(r, s).hex(),        # DER
    lambda r, s, h: h.upper(),                               # uppercase
    lambda r, s, h: "0x" + h,                                # prefix
    lambda r, s, h: h[:-2],                                  # short
    lambda r, s, h: h + "00",                                # long
    lambda r, s, h: f"{0:064x}{s:064x}",                     # r = 0
    lambda r, s, h: f"{r:064x}{0:064x}",                     # s = 0
    lambda r, s, h: f"{N:064x}{s:064x}",                     # r = n
    lambda r, s, h: f"{r:064x}{N:064x}",                     # s = n
    lambda r, s, h: "zz" + h[2:],                            # non-hex
])
def test_non_canonical_signatures(tx, alice, make):
    s = sign_tx(tx, alice)
    r, sv = _sig(s)
    s["signature"] = make(r, sv, s["signature"])
    assert code_of(s) == "NON_CANONICAL_SIGNATURE"


def test_high_s_twin_is_mathematically_valid(tx, alice):
    """Shows why the rule matters: OpenSSL itself accepts (r, n-s)."""
    s = sign_tx(tx, alice)
    r, sv = _sig(s)
    from toywallet.keys import parse_public_hex
    from toywallet.signing import ALGO
    parse_public_hex(s["public_key"]).verify(encode_dss_signature(r, N - sv), tx.to_bytes(), ALGO)


def test_malformed_public_key(tx, alice):
    s = sign_tx(tx, alice)
    s["public_key"] = "04" + "11" * 64
    assert code_of(s) == "MALFORMED_PUBLIC_KEY"


@pytest.mark.parametrize("obj", [{}, {"tx": {}, "public_key": "", "signature": ""}, {"tx": 1, "public_key": 1, "signature": 1, "x": 1}])
def test_malformed_envelope(obj):
    with pytest.raises(WalletError):
        verify_signed(obj, NET)


def test_mainnet_guard(alice, bob):
    m_alice = KeyPair(alice.private, "course-mainnet")
    m_bob = KeyPair(bob.private, "course-mainnet")
    tx = Transaction(1, "course-mainnet", m_alice.address, m_bob.address, 5, 0, "00" * 32)
    with pytest.raises(WalletError) as e:
        sign_tx(tx, m_alice)
    assert e.value.code == "MAINNET_BLOCKED"
    verify_signed(sign_tx(tx, m_alice, allow_mainnet=True), "course-mainnet")


def test_signer_refuses_foreign_sender(tx, bob):
    with pytest.raises(WalletError) as e:
        sign_tx(tx, bob)
    assert e.value.code == "WRONG_SIGNER"


def test_signer_refuses_key_network_mismatch(tx, alice):
    with pytest.raises(WalletError):
        sign_tx(tx, KeyPair(alice.private, "course-mainnet"))


# ------------------------------------------------------------- committed examples + independent verifier

EXPECTED = {
    "bad_checksum.json": "INVALID_CHECKSUM", "der_signature.json": "NON_CANONICAL_SIGNATURE",
    "high_s.json": "NON_CANONICAL_SIGNATURE", "malformed_address.json": "MALFORMED_ADDRESS",
    "tampered_amount.json": "BAD_SIGNATURE", "tampered_recipient.json": "BAD_SIGNATURE",
    "uppercase_signature.json": "NON_CANONICAL_SIGNATURE", "wrong_network.json": "WRONG_NETWORK",
    "wrong_signer.json": "WRONG_SIGNER",
}


def test_example_signed_tx_valid():
    verify_signed((ROOT / "examples" / "signed_tx.json").read_bytes(), NET)
    verify_signed((ROOT / "examples" / "attacks" / "reordered_whitespace.json").read_bytes(), NET)


@pytest.mark.parametrize("name,code", sorted(EXPECTED.items()))
def test_example_attacks_rejected(name, code):
    assert code_of((ROOT / "examples" / "attacks" / name).read_bytes()) == code


@pytest.mark.parametrize("name,ok", [("signed_tx.json", True), ("attacks/reordered_whitespace.json", True)]
                         + [(f"attacks/{n}", False) for n in sorted(EXPECTED)])
def test_independent_verifier_agrees(name, ok):
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "independent_verify.py"), str(ROOT / "examples" / name)],
                       capture_output=True, text=True)
    assert (r.returncode == 0) == ok, r.stdout + r.stderr
