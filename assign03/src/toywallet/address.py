"""Networks and addresses.

address = Base58Check( version_byte || PKH )
PKH     = first 20 bytes of SHA-256( compressed_public_key )   (33-byte SEC1)

The version byte identifies the network, so a testnet address can never be
mistaken for a mainnet one:

    network_id        version  addresses start with
    course-testnet    0x6f     'm' or 'n'
    course-mainnet    0x00     '1'
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .base58 import Base58Error, ChecksumError, b58check_decode, b58check_encode
from .errors import WalletError

NETWORKS: dict[str, int] = {"course-testnet": 0x6F, "course-mainnet": 0x00}
VERSION_TO_NETWORK = {v: k for k, v in NETWORKS.items()}
MAINNET = "course-mainnet"
DEFAULT_NETWORK = "course-testnet"
PKH_LEN = 20
RAW_ADDRESS_LEN = 1 + PKH_LEN


def pubkey_hash(compressed_pubkey: bytes) -> bytes:
    if len(compressed_pubkey) != 33 or compressed_pubkey[0] not in (2, 3):
        raise WalletError(WalletError.MALFORMED_PUBLIC_KEY, "public key must be 33-byte compressed SEC1 (02/03 prefix)")
    return hashlib.sha256(compressed_pubkey).digest()[:PKH_LEN]


def check_network(network_id: str) -> int:
    if network_id not in NETWORKS:
        raise WalletError(WalletError.WRONG_NETWORK, f"unknown network {network_id!r}; known: {sorted(NETWORKS)}")
    return NETWORKS[network_id]


def address_from_pubkey(compressed_pubkey: bytes, network_id: str) -> str:
    return b58check_encode(bytes([check_network(network_id)]) + pubkey_hash(compressed_pubkey))


@dataclass(frozen=True)
class Address:
    text: str
    version: int
    pkh: bytes

    @property
    def network(self) -> str:
        return VERSION_TO_NETWORK[self.version]

    @property
    def raw(self) -> bytes:
        """21 bytes used inside the transaction: version || PKH."""
        return bytes([self.version]) + self.pkh


def parse_address(text: str, field: str = "address") -> Address:
    if not isinstance(text, str) or not text:
        raise WalletError(WalletError.MALFORMED_ADDRESS, f"{field}: must be a non-empty string")
    if text != text.strip():
        raise WalletError(WalletError.MALFORMED_ADDRESS, f"{field}: leading/trailing whitespace")
    try:
        payload = b58check_decode(text)
    except ChecksumError as e:
        raise WalletError(WalletError.INVALID_CHECKSUM, f"{field} {text!r}: {e}") from None
    except Base58Error as e:
        raise WalletError(WalletError.MALFORMED_ADDRESS, f"{field} {text!r}: {e}") from None
    if len(payload) != RAW_ADDRESS_LEN:
        raise WalletError(WalletError.MALFORMED_ADDRESS, f"{field}: payload is {len(payload)} bytes, expected {RAW_ADDRESS_LEN}")
    if payload[0] not in VERSION_TO_NETWORK:
        raise WalletError(WalletError.MALFORMED_ADDRESS, f"{field}: unknown version byte 0x{payload[0]:02x}")
    return Address(text, payload[0], payload[1:])
