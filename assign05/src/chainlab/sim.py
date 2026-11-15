"""Two-miner fork simulation.

Phases (all deterministic: fixed keys, fixed timestamps):
  1  common block: Alice pays Bob 85
  2  fork at equal work: Miner A's block has Bob→Carol, Miner B's block has a
     CONFLICTING Bob→Dave. The node keeps the first one it saw.
  3  Miner B extends his branch: more work → reorg; Bob→Carol is dropped as a conflict.
  4  longer-but-lighter vs shorter-but-heavier: Miner A publishes 3 easy blocks
     (16-bit), Miner B 2 harder blocks (17-bit). B's 2 blocks carry more work
     and win; A's transaction that is still valid returns to the mempool and
     is mined again.
  5  invalid blocks on the tip: bad PoW, wrong Merkle root, excess coinbase,
     invalid transaction - each rejected, active chain and UTXO set unchanged.
  6  heavier branch whose 2nd block is invalid: the node starts the reorg,
     hits the bad block, rolls back and stays on the old chain.
Finally the node's UTXO set is compared with a fresh replay of the winning
chain from genesis, and the node is saved and reloaded.
"""

from __future__ import annotations

import os
from dataclasses import replace

from .block import Block, bits_of, mine, target_for_bits, work_of
from .chain import GENESIS_TIME, SUBSIDY, Chain, make_genesis
from .crypto import KeyPair, address_of_pkh
from .state import ChainState
from .tx import TxOut
from .wallet import build_payment

ALICE, BOB, CAROL, DAVE = (KeyPair.from_scalar(d) for d in (0xA11CE, 0xB0B, 0xCA401, 0xDA7E))
MINER_A, MINER_B = KeyPair.from_scalar(0xAAAA), KeyPair.from_scalar(0xBBBB)
NAMES = {k.pkh: n for k, n in ((ALICE, "Alice"), (BOB, "Bob"), (CAROL, "Carol"), (DAVE, "Dave"),
                               (MINER_A, "MinerA"), (MINER_B, "MinerB"))}


def T(height: int, offset: int = 0) -> int:
    return GENESIS_TIME + 600 * height + offset


class Sim:
    def __init__(self, out_dir: str | None = None, say=print):
        self.out_dir = out_dir
        self.say = say
        self.log: list[dict] = []
        self.labels: dict[str, str] = {}
        self.genesis = make_genesis([TxOut(40, ALICE.pkh), TxOut(70, ALICE.pkh), TxOut(50, BOB.pkh)])
        self.node = Chain(self.genesis, now=lambda: T(1000))
        self.labels[self.genesis.hash] = "G"
        self.checks: dict[str, bool] = {}

    # ------------------------------------------------------------------ helpers
    def balances(self) -> str:
        st = self.node.state
        return ", ".join(f"{n} {st.balance(p)}" for p, n in NAMES.items() if st.balance(p))

    def submit(self, label: str, block: Block, miner: str, note: str = "") -> object:
        self.labels[block.hash] = label
        before_tip, before_utxo = self.node.tip.hash, self.node.state.utxo_set_hash()
        r = self.node.submit(block, miner)
        results = [r] + r.children
        for res in results:
            lab = self.labels.get(res.hash, res.hash[:8])
            tip = self.node.tip
            rec = {"label": lab, "miner": miner, "status": res.status, "code": res.code, "reason": res.reason,
                   "height": res.height, "bits": round(bits_of(block.header.target)) if res.hash == block.hash
                   else round(bits_of(self.node.blocks[res.hash].header.target)),
                   "tip": self.labels.get(tip.hash, tip.hash[:8]), "tip_height": tip.height, "tip_work": tip.work,
                   "disconnected": [self.labels.get(h, h[:8]) for h in res.disconnected],
                   "connected": [self.labels.get(h, h[:8]) for h in res.connected],
                   "resurrected": len(res.resurrected), "conflicted": len(res.conflicted),
                   "unchanged": (before_tip == tip.hash and before_utxo == self.node.state.utxo_set_hash()),
                   "balances": self.balances(),
                   "note": note if res is r else "taken from the orphan pool; its branch is heavier, so a reorg was "
                                                 "attempted, failed at this block and was rolled back"}
            self.log.append(rec)
            extra = ""
            if res.status == "REORG":
                extra = f" | disconnected {rec['disconnected']} connected {rec['connected']}"
                if res.conflicted or res.resurrected:
                    extra += f" | stale txs: {len(res.resurrected)} back to mempool, {len(res.conflicted)} dropped (conflict)"
            if res.code:
                extra = f" [{res.code}] {res.reason}" + (" | active chain & UTXO set unchanged" if rec["unchanged"] else "")
            self.say(f"  {lab:<5} by {miner:<7} → {res.status:<11}{extra}")
            self.say(f"        tip {rec['tip']} h={tip.height} work={tip.work:,}  balances: {rec['balances']}")
        return r

    def mine(self, miner: KeyPair, bits: int, parent: str | None, ts: int, txs=None, payout=None) -> Block:
        return self.node.build_and_mine(miner.pkh, target_for_bits(bits), txs, parent=parent, timestamp=ts, payout=payout).block

    # ------------------------------------------------------------------ run
    def run(self) -> bool:
        n, say = self.node, self.say
        say(f"genesis G {self.genesis.hash[:16]}…  Alice 40 + 70, Bob 50")

        say("\nPhase 1 - common block")
        t1 = build_payment(n.state, ALICE, BOB.pkh, 85, 2).tx
        b1 = self.mine(MINER_A, 16, None, T(1), [t1])
        self.submit("1", b1, "MinerA", "Alice pays Bob 85")
        self.header_example = b1.header

        say("\nPhase 2 - two miners find competing blocks at height 2 (equal work)")
        st1 = n.state_at(b1.hash)
        to_carol = build_payment(st1, BOB, CAROL.pkh, 100, 1).tx
        to_dave = build_payment(st1, BOB, DAVE.pkh, 60, 1).tx           # spends Bob's 85 too: conflict
        b2a = self.mine(MINER_A, 16, b1.hash, T(2), [to_carol])
        b2b = self.mine(MINER_B, 16, b1.hash, T(2, 1), [to_dave])
        self.submit("2a", b2a, "MinerA", "Bob pays Carol 100")
        self.submit("2b", b2b, "MinerB", "conflicting: Bob pays Dave 60")
        self.checks["equal work keeps first-seen block"] = n.tip.hash == b2a.hash

        say("\nPhase 3 - Miner B extends his branch: more work wins, reorg")
        b3b = self.mine(MINER_B, 16, b2b.hash, T(3, 1), [])
        r = self.submit("3b", b3b, "MinerB")
        self.checks["reorg to heavier branch"] = r.status == "REORG" and n.tip.hash == b3b.hash
        self.checks["conflicting tx from stale block dropped"] = len(r.conflicted) == 1 and n.state.balance(CAROL.pkh) == 0
        self.checks["spent outputs restored / new branch applied"] = n.state.balance(DAVE.pkh) == 60

        say("\nPhase 4 - longer but lower-work branch vs shorter higher-work branch")
        dave_pays = build_payment(n.state, DAVE, CAROL.pkh, 30, 1).tx
        a4 = self.mine(MINER_A, 16, b3b.hash, T(4), [dave_pays])
        self.submit("4a", a4, "MinerA", "Dave pays Carol 30")
        a5 = self.mine(MINER_A, 16, a4.hash, T(5), [])
        self.submit("5a", a5, "MinerA")
        a6 = self.mine(MINER_A, 16, a5.hash, T(6), [])
        self.submit("6a", a6, "MinerA", "A's branch: 3 blocks × 16 bits")
        lighter_work = n.tip.work
        b4 = self.mine(MINER_B, 17, b3b.hash, T(4, 1), [])
        self.submit("4b", b4, "MinerB", "B's branch: 17-bit blocks (2× the work each)")
        b5 = self.mine(MINER_B, 17, b4.hash, T(5, 1), [])
        r = self.submit("5b", b5, "MinerB", "2 × 17 bits > 3 × 16 bits")
        self.checks["shorter higher-work branch beats longer lower-work branch"] = (
            n.tip.hash == b5.hash and n.tip.height == 5 and n.entries[a6.hash].height == 6 and n.tip.work > lighter_work)
        self.checks["still-valid tx from stale block returned to mempool"] = dave_pays.txid in n.mempool
        b6 = self.mine(MINER_B, 16, b5.hash, T(6, 1), None)               # takes txs from the mempool
        self.submit("6b", b6, "MinerB", "re-mines Dave pays Carol 30 from the mempool")
        self.checks["re-mined tx confirmed"] = n.state.balance(CAROL.pkh) == 30

        say("\nPhase 5 - invalid blocks on top of the tip are rejected whole")
        tip_before, utxo_before = n.tip.hash, n.state.utxo_set_hash()
        good = self.mine(MINER_A, 16, None, T(7), [])
        bad_pow = Block(replace(good.header, nonce=good.header.nonce + 1), good.txs)
        while bad_pow.header.meets_target():
            bad_pow = Block(replace(bad_pow.header, nonce=bad_pow.header.nonce + 1), good.txs)
        self.submit("x-pow", bad_pow, "MinerA", "nonce changed after mining")
        other = self.mine(MINER_A, 16, None, T(7, 2), [])
        wrong_root = mine(bytes.fromhex(n.tip.hash), list(other.txs), target_for_bits(16), T(7, 3)).block
        st = n.state
        extra = build_payment(st, CAROL, ALICE.pkh, 5, 1).tx
        wrong_root = Block(wrong_root.header, wrong_root.txs + (extra,))     # header commits to fewer txs
        self.submit("x-mrk", wrong_root, "MinerA", "a transaction added after mining")
        greedy = self.mine(MINER_A, 16, None, T(7, 4), [], payout=SUBSIDY + 1)
        self.submit("x-cb", greedy, "MinerA", f"coinbase pays {SUBSIDY + 1}, allowed {SUBSIDY}")
        from .chain import make_coinbase
        cb = make_coinbase(n.height + 1, [TxOut(SUBSIDY, MINER_A.pkh)])
        bad_tx = mine(bytes.fromhex(n.tip.hash), [cb, to_carol], target_for_bits(16), T(7, 5)).block
        self.submit("x-tx", bad_tx, "MinerA", "includes Bob→Carol again (inputs already spent)")
        self.checks["invalid blocks leave active chain and UTXO set unchanged"] = (
            n.tip.hash == tip_before and n.state.utxo_set_hash() == utxo_before)

        say("\nPhase 6 - heavier branch with an invalid block inside: reorg attempted, rolled back")
        cb1 = make_coinbase(5, [TxOut(SUBSIDY, MINER_A.pkh)])
        y1 = mine(bytes.fromhex(b4.hash), [cb1], target_for_bits(16), T(5, 7)).block
        cb2 = make_coinbase(6, [TxOut(SUBSIDY, MINER_A.pkh)])
        y2 = mine(bytes.fromhex(y1.hash), [cb2, to_carol], target_for_bits(19), T(6, 7)).block
        self.labels[y1.hash], self.labels[y2.hash] = "5y", "6y"
        say(f"  branch 4b→5y→6y work would be {n.entries[b4.hash].work + work_of(y1.header.target) + work_of(y2.header.target):,}"
            f" > active {n.tip.work:,}")
        self.submit("6y", y2, "MinerA", "arrives first: parent unknown")
        r = self.submit("5y", y1, "MinerA", "parent arrives; 6y is now processed")
        self.checks["failed reorg rolls back to the old chain"] = (
            n.tip.hash == tip_before and n.state.utxo_set_hash() == utxo_before and n.entries[y2.hash].invalid is not None)

        say("\nFinal verification")
        replay = ChainState()
        from .chain import Undo, _apply_block
        for h_, bh in enumerate(n.active):
            _apply_block(replay, n.blocks[bh], h_, Undo(), genesis=h_ == 0)
        self.checks["UTXO set after reorgs == fresh replay of the winning chain"] = replay.utxo_set_hash() == n.state.utxo_set_hash()
        if self.out_dir:
            os.makedirs(self.out_dir, exist_ok=True)
            p = os.path.join(self.out_dir, "node.json")
            n.save(p)
            again = Chain.load(p)
            self.checks["saved and reloaded node has same tip and UTXO set"] = (
                again.tip.hash == n.tip.hash and again.state.utxo_set_hash() == n.state.utxo_set_hash())
        for k, v in self.checks.items():
            say(f"  [{'PASS' if v else 'FAIL'}] {k}")
        say(f"\nactive chain: {' → '.join(self.labels.get(h, h[:6]) for h in n.active)}   final balances: {self.balances()}")
        return all(self.checks.values())


def run(out_dir: str | None = None, say=print) -> Sim:
    from .report import write_outputs
    s = Sim(out_dir, say)
    ok = s.run()
    if out_dir:
        write_outputs(s)
    s.ok = ok
    return s


def label_addr(pkh: bytes) -> str:
    return NAMES.get(pkh, address_of_pkh(pkh))
