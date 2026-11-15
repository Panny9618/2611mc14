import pytest

from toywallet.address import address_from_pubkey, parse_address, pubkey_hash
from toywallet.base58 import ALPHABET, Base58Error, ChecksumError, b58check_decode, b58check_encode, b58decode, b58encode
from toywallet.errors import WalletError

# Bitcoin Core base58_encode_decode.json vectors
B58 = [
    ("", ""), ("61", "2g"), ("626262", "a3gV"), ("636363", "aPEr"),
    ("73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"),
    ("00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"),
    ("516b6fcd0f", "ABnLTmg"), ("bf4f89001e670274dd", "3SEo3LWLoPntC"), ("572e4794", "3EFU7m"),
    ("ecac89cad93923c02321", "EJDM8drfXA6uyA"), ("10c8511e", "Rt5zm"), ("00000000000000000000", "1111111111"),
]


@pytest.mark.parametrize("hx,enc", B58)
def test_base58_vectors(hx, enc):
    assert b58encode(bytes.fromhex(hx)) == enc
    assert b58decode(enc) == bytes.fromhex(hx)


def test_base58check_known():
    assert b58check_encode(bytes(21)) == "1111111111111111111114oLvT2"   # Bitcoin's all-zero P2PKH address
    assert b58check_decode("1111111111111111111114oLvT2") == bytes(21)


@pytest.mark.parametrize("bad", ["0", "O", "I", "l", "+", " ", "é"])
def test_base58_rejects_ambiguous_chars(bad):
    with pytest.raises(Base58Error):
        b58decode("abc" + bad)


def test_checksum_detects_change():
    s = b58check_encode(b"\x6f" + bytes(range(20)))
    with pytest.raises(ChecksumError):
        b58check_decode(s[:-1] + ("2" if s[-1] != "2" else "3"))


def test_address_prefixes(fixed_alice):
    pub = fixed_alice.public_bytes
    assert address_from_pubkey(pub, "course-testnet")[0] in "mn"
    assert address_from_pubkey(pub, "course-mainnet")[0] == "1"
    assert address_from_pubkey(pub, "course-testnet") == "mgvcECAzwwFKK3qmz5qkv1UzSBJRc91a46"


def test_parse_roundtrip(alice):
    a = parse_address(alice.address)
    assert a.network == "course-testnet" and a.version == 0x6F
    assert a.pkh == pubkey_hash(alice.public_bytes) and len(a.raw) == 21


def test_every_single_character_typo_is_detected(alice):
    addr = alice.address
    for pos in range(len(addr)):
        c = addr[pos]
        typo = addr[:pos] + ALPHABET[(ALPHABET.index(c) + 1) % 58] + addr[pos + 1:]
        with pytest.raises(WalletError) as e:
            parse_address(typo)
        assert e.value.code in (WalletError.INVALID_CHECKSUM, WalletError.MALFORMED_ADDRESS)


@pytest.mark.parametrize("bad,code", [
    ("", WalletError.MALFORMED_ADDRESS),
    ("m0OIl", WalletError.MALFORMED_ADDRESS),
    ("1111", WalletError.MALFORMED_ADDRESS),
    (b58check_encode(b"\x6f" + bytes(19)), WalletError.MALFORMED_ADDRESS),     # 19-byte hash
    (b58check_encode(b"\x05" + bytes(20)), WalletError.MALFORMED_ADDRESS),     # unknown version
])
def test_malformed_addresses(bad, code):
    with pytest.raises(WalletError) as e:
        parse_address(bad)
    assert e.value.code == code


def test_whitespace_rejected(alice):
    with pytest.raises(WalletError):
        parse_address(alice.address + " ")


def test_pubkey_hash_needs_compressed():
    with pytest.raises(WalletError):
        pubkey_hash(b"\x04" + bytes(64))
