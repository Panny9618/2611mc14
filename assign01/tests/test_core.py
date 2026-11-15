import base64
import hashlib
import shutil
import subprocess

import pytest

from hashlab.core import (
    HexError, avalanche, digest_bytes, digest_file, flip_bit, hamming_distance, parse_hex, text_to_bytes,
)

# Published SHA-256 test vectors (FIPS 180-2 / NIST examples)
VECTORS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
]


@pytest.mark.parametrize("data,expected", VECTORS)
def test_known_vectors(data, expected):
    d = digest_bytes(data)
    assert d.hex == expected
    assert d.length == len(data)
    assert d.b64 == base64.b64encode(bytes.fromhex(expected)).decode()


def test_million_a_from_file(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(b"a" * 1_000_000)
    assert digest_file(str(p)).hex == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"


def test_text_is_utf8_exact_and_newline_matters():
    assert text_to_bytes("Alice pays Bob 10") == b"Alice pays Bob 10"
    a = digest_bytes(text_to_bytes("Alice pays Bob 10"))
    b = digest_bytes(text_to_bytes("Alice pays Bob 10\n"))
    assert (a.length, b.length) == (17, 18)
    assert a.hex != b.hex


def test_text_non_ascii_byte_length():
    assert len(text_to_bytes("₹")) == 3          # U+20B9 is 3 UTF-8 bytes
    assert len(text_to_bytes("नमस्ते")) == 18


# ---------------------------------------------------------------- hex parsing

@pytest.mark.parametrize("s,expected", [
    ("616263", b"abc"), ("0x616263", b"abc"), ("0X616263", b"abc"),
    ("DEADbeef", b"\xde\xad\xbe\xef"), ("", b""), ("0x", b""), ("00", b"\x00"),
])
def test_hex_valid(s, expected):
    assert parse_hex(s) == expected


@pytest.mark.parametrize("s", ["abc", "0x1", "zz", "61 62", "61:62", "0xg0", "６１", "-1", "61\n", "0x0x61"])
def test_hex_malformed_rejected(s):
    with pytest.raises(HexError):
        parse_hex(s)


def test_hex_and_text_agree():
    assert digest_bytes(parse_hex("416c696365")).hex == digest_bytes(b"Alice").hex


# ---------------------------------------------------------------- streaming

@pytest.mark.parametrize("chunk", [1, 7, 64, 1024 * 1024])
def test_streaming_matches_whole_buffer(tmp_path, chunk):
    data = bytes(range(256)) * 1000 + b"tail"
    p = tmp_path / "f.bin"
    p.write_bytes(data)
    d = digest_file(str(p), chunk)
    assert d.hex == hashlib.sha256(data).hexdigest()
    assert d.length == len(data)


def test_empty_file(tmp_path):
    p = tmp_path / "empty"
    p.write_bytes(b"")
    assert digest_file(str(p)).hex == VECTORS[0][1]


@pytest.mark.skipif(not (shutil.which("sha256sum") or shutil.which("shasum")), reason="no external SHA-256 tool")
def test_matches_independent_utility(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(bytes(range(256)) * 4097 + b"\r\n\x00")
    cmd = ["sha256sum", str(p)] if shutil.which("sha256sum") else ["shasum", "-a", "256", str(p)]
    external = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.split()[0]
    assert digest_file(str(p)).hex == external


# ---------------------------------------------------------------- avalanche

def test_flip_bit_msb_first():
    assert flip_bit(b"A", 7) == b"@"         # 0x41 -> 0x40
    assert flip_bit(b"A", 0) == b"\xc1"      # MSB
    assert flip_bit(b"\x00\x00", 8) == b"\x00\x80"


def test_flip_bit_twice_restores():
    data = b"Alice pays Bob 10"
    assert flip_bit(flip_bit(data, 42), 42) == data


@pytest.mark.parametrize("bit", [-1, 8])
def test_flip_bit_out_of_range(bit):
    with pytest.raises(ValueError):
        flip_bit(b"A", bit)


def test_flip_bit_empty():
    with pytest.raises(ValueError):
        flip_bit(b"", 0)


def test_hamming():
    assert hamming_distance(b"\x00", b"\xff") == 8
    assert hamming_distance(b"\x0f\x00", b"\x0f\x01") == 1
    with pytest.raises(ValueError):
        hamming_distance(b"a", b"ab")


def test_avalanche_range_and_average():
    data = b"Alice pays Bob 10"
    results = [avalanche(data, b).changed_bits for b in range(len(data) * 8)]
    assert all(0 < r <= 256 for r in results)
    mean = sum(results) / len(results)
    assert 110 < mean < 146                   # ~128 expected for a good hash
