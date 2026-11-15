"""Replay protection.

Each sender has a nonce counter. A transaction is accepted only if its nonce is
strictly greater than the highest nonce already accepted from that sender, so
re-submitting an old signed transaction (a replay) is rejected. The state is a
small JSON file {"<address>": <last accepted nonce>} written atomically.
"""

from __future__ import annotations

import json
import os

from .errors import WalletError


class NonceStore:
    def __init__(self, path: str | None = None):
        self.path = path
        self.last: dict[str, int] = {}
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self.last = json.load(f)

    def check(self, sender: str, nonce: int) -> None:
        last = self.last.get(sender)
        if last is not None and nonce <= last:
            raise WalletError(WalletError.REPLAYED_NONCE,
                              f"nonce {nonce} already used: last accepted nonce for {sender} is {last}")

    def record(self, sender: str, nonce: int) -> None:
        self.check(sender, nonce)
        self.last[sender] = nonce
        if self.path:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.last, f, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
