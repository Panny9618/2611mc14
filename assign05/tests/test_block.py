import hashlib
from dataclasses import replace

import pytest

from chainlab.block import (HEADER_LEN, POW_LIMIT, Block, Header, bits_of, dsha, merkle_root, mine,
                            target_for_bits, work_of)
from chainlab.chain import make_coinbase
from chainlab.tx import TxOut


def test_header_layout():
    h = Header(1, b"\x11" * 32, b"\x22" * 32, 0x0102030405060708, target_for_bits(16), 0x0A0B0C0D0E0F1011)
    b = h.to_bytes()
    assert len(b) == HEADER_LEN == 116
    assert b[0:4] == b"\x00\x00\x00\x01" and b[4:36] == b"\x11" * 32 and b[36:68] == b"\x22" * 32
    assert b[68:76] == bytes.fromhex("0102030405060708")
    assert b[76:108] == bytes.fromhex("0000" + "ff" * 30)
    assert b[108:116] == bytes.fromhex("0a0b0c0d0e0f1011")
    assert h.hash == hashlib.sha256(hashlib.sha256(b).digest()).digest() == dsha(b)


def test_targets_and_work():
    assert target_for_bits(16) == (1 << 240) - 1
    assert work_of(target_for_bits(16)) == 2**16
    assert work_of(target_for_bits(20)) == 16 * work_of(target_for_bits(16))
    assert round(bits_of(target_for_bits(12))) == 12
    assert POW_LIMIT == target_for_bits(8)
    with pytest.raises(ValueError):
        target_for_bits(7)


def test_merkle_root_matches_rfc6962_vectors():
    # same tree as Assignment 2; reference roots from RFC 6962 / Certificate Transparency
    leaves = [b"", b"\x00", b"\x10", b"\x20\x21", b"\x30\x31", b"\x40\x41\x42\x43", bytes(range(0x50, 0x58)), bytes(range(0x60, 0x70))]
    assert merkle_root(leaves[:1]).hex() == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    assert merkle_root(leaves[:5]).hex() == "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4"
    assert merkle_root(leaves).hex() == "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"


def test_mining_meets_target_and_roundtrips():
    cb = make_coinbase(1, [TxOut(50, b"\x01" * 20)])
    r = mine(b"\x00" * 32, [cb], target_for_bits(10), 1_800_000_000)
    assert r.block.header.meets_target()
    assert int.from_bytes(r.block.header.hash, "big") <= target_for_bits(10)
    assert r.attempts >= 1 and r.block.header.nonce == r.attempts - 1
    again = Block.from_json(r.block.to_json())
    assert again == r.block and again.hash == r.block.hash


def test_changing_any_header_field_breaks_pow():
    cb = make_coinbase(1, [TxOut(50, b"\x01" * 20)])
    blk = mine(b"\x00" * 32, [cb], target_for_bits(16), 1_800_000_000).block
    h = blk.header
    for field, value in [("nonce", h.nonce + 1), ("timestamp", h.timestamp + 1), ("prev_hash", b"\x01" * 32),
                         ("merkle_root", b"\x02" * 32)]:
        assert not replace(h, **{field: value}).meets_target(), field


def test_malformed_block_json():
    with pytest.raises(ValueError):
        Block.from_dict({"header": {"version": 1}, "transactions": []})
