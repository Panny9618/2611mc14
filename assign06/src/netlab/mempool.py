"""Mempool: validated unconfirmed transactions waiting to be mined.

Policy
  validation    every tx must be valid against the current tip's UTXO set (Assignment 4 rules)
  duplicates    a txid already in the pool is ignored (DUPLICATE, no re-relay)
  confirmed     only spends confirmed outputs; a tx spending another unconfirmed tx
                is refused (MISSING_INPUT) - keeps conflict handling simple
  conflicts     two pool txs may not spend the same outpoint. A newcomer that
                conflicts is rejected (CONFLICT) unless its fee-rate is at least
                RBF_FACTOR x every conflicting tx's fee-rate; then the old ones are
                evicted (replace-by-fee)
  fee-rate      fee / size in units per byte (size = body + 97 bytes per signature);
                miners take the highest fee-rate first
  expiry        a tx older than `expiry` seconds is dropped
  capacity      when full, the lowest fee-rate tx is evicted (or the newcomer refused)
  new block     confirmed txs and txs that no longer apply (inputs now spent) are removed
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .state import ChainState, Rejected
from .tx import OutPoint, Transaction

RBF_FACTOR = 1.25
UNLOCK_SIZE = 97


def tx_size(tx: Transaction) -> int:
    return len(tx.body()) + UNLOCK_SIZE * len(tx.inputs)


@dataclass
class Entry:
    tx: Transaction
    fee: int
    size: int
    added: float

    @property
    def feerate(self) -> float:
        return self.fee / self.size


class Mempool:
    def __init__(self, max_txs: int = 5000, expiry: float = 600.0, clock=time.time):
        self.max_txs, self.expiry, self.clock = max_txs, expiry, clock
        self.entries: dict[str, Entry] = {}
        self.by_outpoint: dict[OutPoint, str] = {}

    def __contains__(self, txid: str) -> bool:
        return txid in self.entries

    def __len__(self) -> int:
        return len(self.entries)

    def get(self, txid: str) -> Transaction | None:
        e = self.entries.get(txid)
        return e.tx if e else None

    def add(self, tx: Transaction, state: ChainState) -> tuple[str, list[str]]:
        """Return ('ACCEPTED' | 'REPLACED', evicted_txids) or raise Rejected."""
        txid = tx.txid
        if txid in self.entries:
            raise Rejected("DUPLICATE", "already in the mempool")
        r = state.validate(tx)
        e = Entry(tx, r.fee, tx_size(tx), self.clock())
        conflicts = {self.by_outpoint[i.prev] for i in tx.inputs if i.prev in self.by_outpoint}
        evicted: list[str] = []
        if conflicts:
            worst = max(self.entries[c].feerate for c in conflicts)
            if e.feerate < RBF_FACTOR * worst:
                raise Rejected("CONFLICT", f"spends the same output as {sorted(conflicts)[0][:12]}… "
                                           f"(replacement needs fee-rate ≥ {RBF_FACTOR}× {worst:.3f})")
            for c in conflicts:
                self._remove(c)
                evicted.append(c)
        if len(self.entries) >= self.max_txs:
            low = min(self.entries.values(), key=lambda x: (x.feerate, x.tx.txid))
            if low.feerate >= e.feerate:
                raise Rejected("MEMPOOL_FULL", "fee-rate too low for a full mempool")
            self._remove(low.tx.txid)
            evicted.append(low.tx.txid)
        self.entries[txid] = e
        for i in tx.inputs:
            self.by_outpoint[i.prev] = txid
        return ("REPLACED" if conflicts else "ACCEPTED"), evicted

    def _remove(self, txid: str) -> None:
        e = self.entries.pop(txid)
        for i in e.tx.inputs:
            if self.by_outpoint.get(i.prev) == txid:
                del self.by_outpoint[i.prev]

    def select(self, max_txs: int = 500) -> list[Transaction]:
        """Highest fee-rate first (ties by txid, so every node picks the same order)."""
        best = sorted(self.entries.values(), key=lambda e: (-e.feerate, e.tx.txid))
        return [e.tx for e in best[:max_txs]]

    def expire(self) -> list[str]:
        cutoff = self.clock() - self.expiry
        old = [t for t, e in self.entries.items() if e.added < cutoff]
        for t in old:
            self._remove(t)
        return old

    def revalidate(self, state: ChainState) -> tuple[list[str], list[str]]:
        """After the tip changes: drop confirmed txs and txs whose inputs are gone.
        Returns (confirmed_or_spent, invalid)."""
        gone, invalid = [], []
        for txid, e in list(self.entries.items()):
            if any(i.prev not in state.utxos for i in e.tx.inputs):
                self._remove(txid)
                gone.append(txid)
                continue
            try:
                state.validate(e.tx)
            except Rejected:
                self._remove(txid)
                invalid.append(txid)
        return gone, invalid
