"""One exception type with a stable machine-readable code per rejection reason."""

from __future__ import annotations


class WalletError(ValueError):
    MALFORMED = "MALFORMED"
    MALFORMED_ADDRESS = "MALFORMED_ADDRESS"
    INVALID_CHECKSUM = "INVALID_CHECKSUM"
    WRONG_NETWORK = "WRONG_NETWORK"
    MAINNET_BLOCKED = "MAINNET_BLOCKED"
    MALFORMED_PUBLIC_KEY = "MALFORMED_PUBLIC_KEY"
    NON_CANONICAL_SIGNATURE = "NON_CANONICAL_SIGNATURE"
    WRONG_SIGNER = "WRONG_SIGNER"
    BAD_SIGNATURE = "BAD_SIGNATURE"
    REPLAYED_NONCE = "REPLAYED_NONCE"
    KEY_FILE = "KEY_FILE"

    def __init__(self, code: str, message: str):
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
