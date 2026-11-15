"""Node-local chain manager: block validation, most-work selection, reorganisation.

Every block the node has seen is kept in an index with its height and
cumulative chain work (the sum of work_of(target) from genesis). The ACTIVE
chain is the valid chain with the MOST cumulative work, not the most blocks.
On equal work the block seen first is kept.

Connecting a block validates every transaction in order against the UTXO state
and records UNDO data (the exact outputs it spent and the outpoints it
created). Disconnecting replays the undo data backwards, so spent outputs are
restored exactly.

Reorganisation = find the fork point, disconnect the active blocks above it
(newest first), connect the new branch (oldest first). If any block of the new
branch fails, that block and its descendants are marked invalid, the partial
connection is rolled back and the old chain is reconnected: the active chain
and the UTXO set end exactly as they were.

Block-level consensus rules
  context-free : target in [1, POW_LIMIT]; hash <= target; 1..MAX_BLOCK_TXS txs;
                 first tx is the coinbase and no other tx is; no duplicate txids;
                 merkle_root matches the txids
  contextual   : parent known and valid; coinbase input index == height;
                 timestamp > median of the previous 11; timestamp <= now + 2 h
  state        : every tx valid (Assignment 4 rules) against the state left by
                 the txs before it; coinbase outputs <= SUBSIDY + fees of the block
"""

from __future__ import annotations

import json
import os
import statistics
import time
from dataclasses import dataclass, field

from .block import MAX_BLOCK_TXS, NULL_HASH, POW_LIMIT, Block, Header, mine, work_of
from .state import ChainState, Rejected
from .tx import MAX_MONEY, OutPoint, Transaction, TxIn, TxOut

SUBSIDY = 50
MAX_FUTURE = 2 * 60 * 60
MTP_WINDOW = 11
NULL_TXID = "00" * 32
GENESIS_TIME = 1_767_225_600          # 2026-01-01 00:00:00 UTC


def make_coinbase(height: int, outputs: list[TxOut]) -> Transaction:
    """Coinbase = exactly one input with the null outpoint whose index is the height."""
    return Transaction((TxIn(OutPoint(NULL_TXID, height)),), tuple(outputs))


def is_coinbase(tx: Transaction) -> bool:
    return len(tx.inputs) == 1 and tx.inputs[0].prev.txid == NULL_TXID


def make_genesis(allocations: list[TxOut], target: int = POW_LIMIT, timestamp: int = GENESIS_TIME) -> Block:
    return mine(NULL_HASH, [make_coinbase(0, allocations)], target, timestamp).block


@dataclass
class Entry:
    hash: str
    header: Header
    height: int
    work: int                 # cumulative chain work up to and including this block
    parent: str | None
    seq: int                  # arrival order
    invalid: str | None = None
    miner: str = ""


@dataclass
class Undo:
    spent: list[tuple[OutPoint, TxOut]] = field(default_factory=list)
    created: list[OutPoint] = field(default_factory=list)
    fees: int = 0


@dataclass
class Result:
    status: str               # CONNECTED | REORG | SIDE_BRANCH | DUPLICATE | ORPHAN | REJECTED
    hash: str
    code: str | None = None
    reason: str | None = None
    height: int | None = None
    disconnected: list[str] = field(default_factory=list)
    connected: list[str] = field(default_factory=list)
    resurrected: list[str] = field(default_factory=list)
    conflicted: list[str] = field(default_factory=list)
    children: list["Result"] = field(default_factory=list)

    def line(self) -> str:
        s = f"{self.status:<11} {self.hash[:16]}…"
        if self.height is not None:
            s += f" h={self.height}"
        if self.code:
            s += f" [{self.code}] {self.reason}"
        if self.status == "REORG":
            s += f"  disconnected {len(self.disconnected)}, connected {len(self.connected)}"
        return s


class BlockFailed(Exception):
    pass


class Chain:
    def __init__(self, genesis: Block, now=time.time):
        self.now = now
        self.entries: dict[str, Entry] = {}
        self.blocks: dict[str, Block] = {}
        self.order: list[str] = []
        self.rejected: dict[str, str] = {}             # context-free failures (never indexed)
        self.orphans: dict[str, list[tuple[Block, str]]] = {}
        self.state = ChainState()
        self.active: list[str] = []
        self.undos: dict[str, Undo] = {}
        self.mempool: dict[str, Transaction] = {}
        self.last_reorg: Result | None = None
        g = genesis.hash
        if not genesis.header.meets_target() or genesis.header.prev_hash != NULL_HASH:
            raise ValueError("bad genesis block")
        self.entries[g] = Entry(g, genesis.header, 0, genesis.header.work, None, 0, miner="genesis")
        self.blocks[g] = genesis
        self.order.append(g)
        self._connect(g)

    # ------------------------------------------------------------------ queries
    @property
    def genesis(self) -> Block:
        return self.blocks[self.active[0]]

    @property
    def tip(self) -> Entry:
        return self.entries[self.active[-1]]

    @property
    def height(self) -> int:
        return len(self.active) - 1

    def ancestors(self, h: str):
        while h is not None:
            yield self.entries[h]
            h = self.entries[h].parent

    def median_time_past(self, h: str) -> int:
        ts = [e.header.timestamp for _, e in zip(range(MTP_WINDOW), self.ancestors(h))]
        return int(statistics.median(ts))

    def state_at(self, h: str) -> ChainState:
        """UTXO state after block h (rebuilt from genesis; fine for a toy chain)."""
        path = [e.hash for e in self.ancestors(h)][::-1]
        st = ChainState()
        for n, bh in enumerate(path):
            _apply_block(st, self.blocks[bh], n, Undo(), genesis=(n == 0))
        return st

    def find(self, ref: str) -> str:
        if ref.isdigit() and int(ref) <= self.height:
            return self.active[int(ref)]
        hits = [h for h in self.entries if h.startswith(ref)]
        if len(hits) != 1:
            raise KeyError(f"block {ref!r} not found or ambiguous")
        return hits[0]

    # ------------------------------------------------------------------ submission
    def submit(self, block: Block, miner: str = "") -> Result:
        h = block.hash
        if h in self.entries:
            e = self.entries[h]
            return Result("REJECTED", h, "KNOWN_INVALID", e.invalid) if e.invalid else Result("DUPLICATE", h, height=e.height)
        try:
            check_block(block)
        except Rejected as e:
            self.rejected[h] = e.code
            return Result("REJECTED", h, e.code, e.reason)

        parent = block.header.prev_hash.hex()
        if parent not in self.entries:
            self.orphans.setdefault(parent, []).append((block, miner))
            return Result("ORPHAN", h, reason=f"parent {parent[:16]}… unknown; held until it arrives")
        pe = self.entries[parent]
        height = pe.height + 1
        entry = Entry(h, block.header, height, pe.work + block.header.work, parent, len(self.order), miner=miner)
        self.entries[h] = entry
        self.blocks[h] = block
        self.order.append(h)
        try:
            if pe.invalid:
                raise Rejected("INVALID_PARENT", f"parent is invalid ({pe.invalid})")
            cb = block.txs[0].inputs[0].prev.index
            if cb != height:
                raise Rejected("BAD_COINBASE_HEIGHT", f"coinbase says height {cb}, block is at height {height}")
            mtp = self.median_time_past(parent)
            if block.header.timestamp <= mtp:
                raise Rejected("TIME_TOO_OLD", f"timestamp {block.header.timestamp} <= median time past {mtp}")
            if block.header.timestamp > self.now() + MAX_FUTURE:
                raise Rejected("TIME_TOO_NEW", "timestamp more than 2 hours in the future")
        except Rejected as e:
            self._mark_invalid(h, e.code)
            return Result("REJECTED", h, e.code, e.reason, height)

        old_tip = self.tip.hash
        self.last_reorg = None
        failures = self._activate_best()
        if entry.invalid:
            if h in failures:
                code, reason = failures[h]
            else:
                bad = next(iter(failures.items()), None)
                code, reason = "INVALID_PARENT", (f"ancestor {bad[0][:16]}… failed: [{bad[1][0]}] {bad[1][1]}" if bad else "")
            res = Result("REJECTED", h, code, reason, height)
        elif self.tip.hash == old_tip:
            res = Result("SIDE_BRANCH", h, height=height,
                         reason=f"stored; branch work {entry.work:,} <= active {self.tip.work:,}")
        elif self.last_reorg and self.last_reorg.disconnected:
            res = self.last_reorg
            res.hash, res.height = h, height
        else:
            res = Result("CONNECTED", h, height=height,
                         connected=self.last_reorg.connected if self.last_reorg else [h])
        for child, child_miner in self.orphans.pop(h, []):
            res.children.append(self.submit(child, child_miner))
        return res

    # ------------------------------------------------------------------ fork choice
    def _activate_best(self) -> dict[str, tuple[str, str]]:
        failures: dict[str, tuple[str, str]] = {}
        while True:
            cur = self.tip
            cands = [e for e in self.entries.values() if not e.invalid and e.work > cur.work]
            if not cands:
                return failures
            best = max(cands, key=lambda e: (e.work, -e.seq))
            try:
                self._reorg_to(best.hash)
                return failures
            except BlockFailed as bf:
                failures[bf.args[0]] = bf.args[1]

    def _reorg_to(self, target: str) -> None:
        on_active = set(self.active)
        path = []
        for e in self.ancestors(target):
            if e.hash in on_active:
                fork = e
                break
            path.append(e.hash)
        path.reverse()
        disconnected = []
        while self.tip.hash != fork.hash:
            disconnected.append(self.tip.hash)
            self._disconnect(self.tip.hash)
        connected = []
        for h in path:
            try:
                self._connect(h)
            except Rejected as e:
                self._mark_invalid(h, e.code)
                for c in reversed(connected):
                    self._disconnect(c)
                for d in reversed(disconnected):
                    self._connect(d)                       # old chain was valid: cannot fail
                raise BlockFailed(h, (e.code, e.reason))
            connected.append(h)
        self.last_reorg = Result("REORG", target, disconnected=disconnected, connected=connected)
        self._update_mempool(disconnected, connected)

    def _mark_invalid(self, h: str, code: str) -> None:
        self.entries[h].invalid = code
        for e in self.entries.values():                    # descendants are invalid too
            if e.invalid is None and e.parent and any(a.hash == h for a in self.ancestors(e.parent)):
                e.invalid = "INVALID_PARENT"

    # ------------------------------------------------------------------ connect / disconnect
    def _connect(self, h: str) -> None:
        undo = Undo()
        _apply_block(self.state, self.blocks[h], len(self.active), undo, genesis=not self.active)
        self.undos[h] = undo
        self.active.append(h)

    def _disconnect(self, h: str) -> None:
        assert self.active[-1] == h
        undo = self.undos.pop(h)
        _rollback(self.state, undo)
        self.active.pop()

    def _update_mempool(self, disconnected: list[str], connected: list[str]) -> None:
        now_confirmed = {t.txid for c in connected for t in self.blocks[c].txs}
        stale = [t for d in reversed(disconnected) for t in self.blocks[d].txs[1:] if t.txid not in now_confirmed]
        for t in stale:
            self.mempool[t.txid] = t
        res = self.last_reorg
        scratch_ok = self._revalidate_mempool()
        res.resurrected = [t.txid for t in stale if t.txid in scratch_ok]
        res.conflicted = [t.txid for t in stale if t.txid not in scratch_ok]

    def _revalidate_mempool(self) -> set[str]:
        """Keep only mempool txs that still apply, in order, on top of the tip."""
        st = ChainState()
        st.utxos, st.spent = dict(self.state.utxos), dict(self.state.spent)
        keep = {}
        for txid, t in self.mempool.items():
            try:
                st.validate(t)
            except Rejected:
                continue
            _apply_tx(st, t, Undo())
            keep[txid] = t
        self.mempool = keep
        return set(keep)

    def add_to_mempool(self, tx: Transaction) -> None:
        self.mempool[tx.txid] = tx
        if tx.txid not in self._revalidate_mempool():
            raise Rejected("MEMPOOL_REJECT", "transaction does not apply on top of the current tip")

    # ------------------------------------------------------------------ mining
    def build_and_mine(self, miner_pkh: bytes, target: int, txs: list[Transaction] | None = None,
                       parent: str | None = None, timestamp: int | None = None, payout: int | None = None):
        """Mine a block on `parent` (default: tip) paying SUBSIDY + fees to miner_pkh."""
        parent = parent or self.tip.hash
        pe = self.entries[parent]
        st = self.state_at(parent)
        chosen, fees = [], 0
        for t in (txs if txs is not None else list(self.mempool.values())):
            try:
                r = st.validate(t)
            except Rejected:
                continue
            _apply_tx(st, t, Undo())
            chosen.append(t)
            fees += r.fee
        value = SUBSIDY + fees if payout is None else payout
        cb = make_coinbase(pe.height + 1, [TxOut(value, miner_pkh)])
        ts = timestamp if timestamp is not None else max(int(self.now()), self.median_time_past(parent) + 1)
        return mine(bytes.fromhex(parent), [cb] + chosen, target, ts)

    # ------------------------------------------------------------------ persistence
    def save(self, path: str) -> None:
        data = {"format": "chainlab-node-v1", "blocks": [self.blocks[h].to_dict() for h in self.order],
                "miners": {h: self.entries[h].miner for h in self.order}, "mempool": [t.to_dict() for t in self.mempool.values()]}
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str) -> "Chain":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        blocks = [Block.from_dict(b) for b in data["blocks"]]
        ch = cls(blocks[0])
        for b in blocks[1:]:
            ch.submit(b, miner=data.get("miners", {}).get(b.hash, ""))
        for t in data.get("mempool", []):
            try:
                ch.add_to_mempool(Transaction.from_dict(t))
            except Rejected:
                pass
        return ch


# --------------------------------------------------------------------------- block rules

def check_block(block: Block) -> None:
    """Context-free checks: need nothing but the block itself."""
    h = block.header
    if h.version != 1:
        raise Rejected("BAD_VERSION", f"version {h.version}")
    if not 1 <= h.target <= POW_LIMIT:
        raise Rejected("BAD_TARGET", "target outside [1, POW_LIMIT]")
    if not h.meets_target():
        raise Rejected("BAD_POW", f"hash {h.hash_hex[:16]}… is above the target")
    if not 1 <= len(block.txs) <= MAX_BLOCK_TXS:
        raise Rejected("BAD_TX_COUNT", f"{len(block.txs)} transactions")
    if not is_coinbase(block.txs[0]) or block.txs[0].inputs[0].unlock is not None:
        raise Rejected("BAD_COINBASE", "first transaction must be a coinbase (one null-outpoint input)")
    for n, t in enumerate(block.txs[1:], 1):
        if any(i.prev.txid == NULL_TXID for i in t.inputs):
            raise Rejected("BAD_COINBASE", f"transaction {n} is a second coinbase")
    try:
        txids = [t.txid for t in block.txs]
    except ValueError as e:
        raise Rejected("INVALID_TX", f"unencodable transaction: {e}") from None
    if len(set(txids)) != len(txids):
        raise Rejected("DUPLICATE_TX", "the same transaction appears twice")
    if block.computed_merkle_root() != h.merkle_root:
        raise Rejected("BAD_MERKLE_ROOT", "merkle_root does not match the transactions")


def _apply_tx(st: ChainState, tx: Transaction, undo: Undo) -> None:
    txid = tx.txid
    for i in tx.inputs:
        if i.prev.txid != NULL_TXID:
            undo.spent.append((i.prev, st.utxos.pop(i.prev)))
            st.spent[i.prev] = txid
    for n, o in enumerate(tx.outputs):
        op = OutPoint(txid, n)
        if op in st.utxos:
            raise Rejected("DUPLICATE_TXID", f"output {op} already exists")
        st.utxos[op] = o
        undo.created.append(op)


def _rollback(st: ChainState, undo: Undo) -> None:
    for op in reversed(undo.created):
        del st.utxos[op]
    for op, o in reversed(undo.spent):
        st.utxos[op] = o
        st.spent.pop(op, None)


def _apply_block(st: ChainState, block: Block, height: int, undo: Undo, genesis: bool = False) -> None:
    """Validate and apply all txs; on any failure restore `st` exactly and raise."""
    try:
        for n, tx in enumerate(block.txs[1:], 1):
            try:
                r = st.validate(tx)
            except Rejected as e:
                raise Rejected("INVALID_TX", f"tx {n} ({tx.txid[:12]}…) rejected: [{e.code}] {e.reason}") from None
            _apply_tx(st, tx, undo)
            undo.fees += r.fee
        cb = block.txs[0]
        total = 0
        for o in cb.outputs:
            if not 1 <= o.value <= MAX_MONEY:
                raise Rejected("BAD_COINBASE", f"coinbase output value {o.value} out of range")
            total += o.value
        if total > MAX_MONEY:
            raise Rejected("BAD_COINBASE", "coinbase total exceeds MAX_MONEY")
        if not genesis and total > SUBSIDY + undo.fees:
            raise Rejected("EXCESS_COINBASE",
                           f"coinbase pays {total} but subsidy {SUBSIDY} + fees {undo.fees} = {SUBSIDY + undo.fees}")
        _apply_tx(st, cb, undo)
    except Rejected:
        _rollback(st, undo)
        undo.spent.clear(); undo.created.clear(); undo.fees = 0
        raise
