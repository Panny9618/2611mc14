import json
import os
import stat

import pytest

from toywallet.errors import WalletError
from toywallet.keys import (
    N, KeyPair, generate_private_key, load_private_file, load_public_file, parse_public_hex,
    private_from_hex, write_private_file, write_public_file,
)

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")


def test_generator_point_for_scalar_one(fixed_alice):
    assert fixed_alice.public_bytes.hex() == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def test_keys_are_random_and_in_range():
    ds = {generate_private_key().private_numbers().private_value for _ in range(50)}
    assert len(ds) == 50 and all(1 <= d < N for d in ds)


@posix_only
def test_private_file_is_0600_and_warns(tmp_path, alice):
    p = tmp_path / "a.key.json"
    write_private_file(str(p), alice)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    rec = json.loads(p.read_text())
    assert "TEST-ONLY" in rec["WARNING"]
    assert load_private_file(str(p)).address == alice.address


def test_refuses_to_overwrite(tmp_path, alice, bob):
    p = tmp_path / "a.key.json"
    write_private_file(str(p), alice)
    with pytest.raises(WalletError, match="refusing to overwrite"):
        write_private_file(str(p), bob)
    assert load_private_file(str(p)).address == alice.address


@posix_only
def test_refuses_world_readable_key(tmp_path, alice):
    p = tmp_path / "a.key.json"
    write_private_file(str(p), alice)
    os.chmod(p, 0o644)
    with pytest.raises(WalletError, match="chmod 600"):
        load_private_file(str(p))


def test_detects_edited_key_file(tmp_path, alice, bob):
    p = tmp_path / "a.key.json"
    write_private_file(str(p), alice)
    rec = json.loads(p.read_text())
    rec["address"] = bob.address
    os.chmod(p, 0o600)
    p.write_text(json.dumps(rec))
    with pytest.raises(WalletError, match="do not match"):
        load_private_file(str(p))


def test_public_file_has_no_secret(tmp_path, alice):
    p = tmp_path / "a.pub.json"
    write_public_file(str(p), alice)
    rec = json.loads(p.read_text())
    assert set(rec) == {"network_id", "public_key", "address"}
    assert alice.public_record() == load_public_file(str(p))


def test_private_file_rejected_as_public(tmp_path, alice):
    p = tmp_path / "a.key.json"
    write_private_file(str(p), alice)
    with pytest.raises(WalletError, match="contains a private key"):
        load_public_file(str(p))


@pytest.mark.parametrize("bad", [
    "04" + "11" * 64,                     # uncompressed form
    "02" + "ff" * 32,                     # x >= field prime: not on curve
    "05" + "11" * 32,                     # bad prefix
    "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",  # uppercase
    "02" + "11" * 31,
])
def test_bad_public_keys(bad):
    with pytest.raises(WalletError):
        parse_public_hex(bad)


@pytest.mark.parametrize("bad", ["00" * 32, f"{N:064x}", "ab" * 31, "AB" * 32])
def test_bad_private_hex(bad):
    with pytest.raises(WalletError):
        private_from_hex(bad)
