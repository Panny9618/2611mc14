"""Acceptance checks: block validation, most-work selection, reorganisation."""

from dataclasses import replace

import pytest

from conftest import ALICE, BOB, CAROL, MA, MB, mine, snapshot
from chainlab.block import Block, mine as raw_mine, target_for_bits
from chainlab.chain import GENESIS_TIME, SUBSIDY, Chain, Undo, _apply_block, make_coinbase
from chainlab.state import ChainState
from chainlab.tx import OutPoint, TxOut, Unlock
from chainlab.wallet import build_payment


def replay_hash(ch):
    st = ChainState()
    for h, bh in enumerate(ch.active):
        _apply_block(st, ch.blocks[bh], h, Undo(), genesis=h == 0)
    return st.utxo_set_hash()


def rejected(ch, block, code):
    before = snapshot(ch)
    r = ch.submit(block)
    assert r.status == "REJECTED" and r.code == code, r.line()
    assert snapshot(ch) == before, "a rejected block must not change the active chain or UTXO set"


# ------------------------------------------------------------------ connecting
def test_extend_tip_and_coinbase_claims_fees(chain):
    tx = build_payment(chain.state, ALICE, BOB.pkh, 85, 2).tx
    b = mine(chain, txs=[tx])
    r = chain.submit(b)
    assert r.status == "CONNECTED" and chain.height == 1
    assert chain.state.balance(MA.pkh) == SUBSIDY + 2
    assert chain.state.balance(ALICE.pkh) == 23 and chain.state.balance(BOB.pkh) == 135


def test_spend_within_same_block_in_order(chain):
    t1 = build_payment(chain.state, ALICE, BOB.pkh, 85, 2).tx
    st = ChainState(); st.utxos = dict(chain.state.utxos)
    _apply_block(st, Block(None, (make_coinbase(1, [TxOut(1, b"x" * 20)]), t1)), 1, Undo())
    t2 = build_payment(st, BOB, CAROL.pkh, 100, 1).tx            # spends t1's output
    assert chain.submit(mine(chain, txs=[t1, t2])).status == "CONNECTED"
    assert chain.state.balance(CAROL.pkh) == 100


def test_duplicate_submission(chain):
    b = mine(chain)
    chain.submit(b)
    assert chain.submit(b).status == "DUPLICATE"


# ------------------------------------------------------------------ invalid blocks reject whole, chain unchanged
def test_invalid_pow(chain):
    b = mine(chain)
    bad = Block(replace(b.header, nonce=b.header.nonce + 1), b.txs)
    while bad.header.meets_target():
        bad = Block(replace(bad.header, nonce=bad.header.nonce + 1), b.txs)
    rejected(chain, bad, "BAD_POW")


def test_incorrect_merkle_root(chain):
    b = mine(chain)
    tx = build_payment(chain.state, ALICE, BOB.pkh, 5, 1).tx
    rejected(chain, Block(b.header, b.txs + (tx,)), "BAD_MERKLE_ROOT")


def test_excess_coinbase(chain):
    rejected(chain, mine(chain, payout=SUBSIDY + 1), "EXCESS_COINBASE")
    tx = build_payment(chain.state, ALICE, BOB.pkh, 85, 2).tx
    rejected(chain, mine(chain, txs=[tx], payout=SUBSIDY + 3), "EXCESS_COINBASE")
    assert chain.submit(mine(chain, txs=[tx], payout=SUBSIDY + 2)).status == "CONNECTED"


def test_invalid_transaction_rejects_whole_block(chain):
    good = build_payment(chain.state, ALICE, BOB.pkh, 85, 2).tx
    bad = build_payment(chain.state, BOB, CAROL.pkh, 10, 1).tx
    bad = bad.with_unlocks([Unlock(BOB.public_bytes, good.inputs[0].unlock.signature)])
    cb = make_coinbase(1, [TxOut(SUBSIDY, MA.pkh)])
    blk = raw_mine(bytes.fromhex(chain.tip.hash), [cb, good, bad], target_for_bits(8), GENESIS_TIME + 600).block
    rejected(chain, blk, "INVALID_TX")
    assert chain.state.balance(BOB.pkh) == 50                 # the valid tx in it was NOT applied


def test_double_spend_inside_block(chain):
    t1 = build_payment(chain.state, ALICE, BOB.pkh, 85, 2).tx
    t2 = build_payment(chain.state, ALICE, CAROL.pkh, 60, 1).tx      # spends the same 70
    cb = make_coinbase(1, [TxOut(SUBSIDY, MA.pkh)])
    blk = raw_mine(bytes.fromhex(chain.tip.hash), [cb, t1, t2], target_for_bits(8), GENESIS_TIME + 78).block
    rejected(chain, blk, "INVALID_TX")


@pytest.mark.parametrize("case", ["no_coinbase", "second_coinbase", "wrong_height", "duplicate_tx"])
def test_coinbase_and_sequence_rules(chain, case):
    tip = bytes.fromhex(chain.tip.hash)
    cb = make_coinbase(1, [TxOut(SUBSIDY, MA.pkh)])
    tx = build_payment(chain.state, ALICE, BOB.pkh, 85, 2).tx
    txs, code = {
        "no_coinbase": ([tx], "BAD_COINBASE"),
        "second_coinbase": ([cb, make_coinbase(1, [TxOut(1, MA.pkh)])], "BAD_COINBASE"),
        "wrong_height": ([make_coinbase(7, [TxOut(SUBSIDY, MA.pkh)])], "BAD_COINBASE_HEIGHT"),
        "duplicate_tx": ([cb, tx, tx], "DUPLICATE_TX"),
    }[case]
    rejected(chain, raw_mine(tip, txs, target_for_bits(8), GENESIS_TIME + 600).block, code)


def test_timestamps(chain):
    cb = make_coinbase(1, [TxOut(SUBSIDY, MA.pkh)])
    tip = bytes.fromhex(chain.tip.hash)
    rejected(chain, raw_mine(tip, [cb], target_for_bits(8), GENESIS_TIME).block, "TIME_TOO_OLD")
    rejected(chain, raw_mine(tip, [cb], target_for_bits(8), GENESIS_TIME + 10**7 + 7201).block, "TIME_TOO_NEW")


def test_target_above_pow_limit(chain):
    b = mine(chain)
    easy = Block(replace(b.header, target=(1 << 255)), b.txs)
    rejected(chain, easy, "BAD_TARGET")


# ------------------------------------------------------------------ fork choice
def test_equal_work_keeps_first_seen(chain):
    a = mine(chain, MA)
    b = mine(chain, MB)
    assert chain.submit(a).status == "CONNECTED"
    assert chain.submit(b).status == "SIDE_BRANCH"
    assert chain.tip.hash == a.hash


def test_longer_lower_work_branch_loses(chain):
    """3 blocks at 9 bits (work 3 x 512 = 1536) vs 2 blocks at 10 bits (work 2 x 1024 = 2048)."""
    g = chain.tip.hash
    light = []
    for _ in range(3):
        b = mine(chain, MA, bits=9, parent=light[-1].hash if light else g)
        chain.submit(b)
        light.append(b)
    h1 = mine(chain, MB, bits=10, parent=g)
    assert chain.submit(h1).status == "SIDE_BRANCH"               # 1024 < 1536
    h2 = mine(chain, MB, bits=10, parent=h1.hash)
    r = chain.submit(h2)
    assert r.status == "REORG" and chain.tip.hash == h2.hash
    assert chain.height == 2 and chain.entries[light[-1].hash].height == 3
    # a 4th light block only ties (2048 = 2048): equal work keeps the current tip
    l4 = mine(chain, MA, bits=9, parent=light[-1].hash)
    assert chain.submit(l4).status == "SIDE_BRANCH" and chain.tip.hash == h2.hash


def test_reorg_restores_spent_outputs_and_matches_replay(chain):
    base = mine(chain); chain.submit(base)
    pay = build_payment(chain.state, ALICE, BOB.pkh, 85, 2).tx
    spent = [i.prev for i in pay.inputs]
    a = mine(chain, MA, txs=[pay]); chain.submit(a)
    assert all(op not in chain.state.utxos for op in spent)
    b1 = mine(chain, MB, parent=base.hash); chain.submit(b1)
    b2 = mine(chain, MB, parent=b1.hash)
    r = chain.submit(b2)
    assert r.status == "REORG" and r.disconnected == [a.hash] and r.connected == [b1.hash, b2.hash]
    assert all(op in chain.state.utxos for op in spent)              # restored
    assert OutPoint(pay.txid, 0) not in chain.state.utxos            # created output removed
    assert chain.state.balance(ALICE.pkh) == 110 and chain.state.balance(MA.pkh) == SUBSIDY
    assert chain.state.utxo_set_hash() == replay_hash(chain)
    assert pay.txid in chain.mempool                                  # still valid: back to mempool


def test_reorg_drops_conflicting_tx(chain):
    base = mine(chain); chain.submit(base)
    to_bob = build_payment(chain.state, ALICE, BOB.pkh, 60, 1).tx
    to_carol = build_payment(chain.state, ALICE, CAROL.pkh, 60, 1).tx   # same coin
    chain.submit(mine(chain, MA, txs=[to_bob]))
    b1 = mine(chain, MB, parent=base.hash, txs=[to_carol]); chain.submit(b1)
    r = chain.submit(mine(chain, MB, parent=b1.hash))
    assert r.conflicted == [to_bob.txid] and to_bob.txid not in chain.mempool
    assert chain.state.balance(CAROL.pkh) == 60 and chain.state.balance(BOB.pkh) == 50


def test_many_reorgs_end_in_correct_utxo_set(chain):
    tips = [chain.tip.hash]
    for i in range(12):
        parent = tips[(i * 7) % len(tips)]
        b = mine(chain, [MA, MB][i % 2], bits=8 + (i % 3), parent=parent)
        chain.submit(b)
        tips.append(b.hash)
        assert chain.state.utxo_set_hash() == replay_hash(chain)
    best = max((e for e in chain.entries.values() if not e.invalid), key=lambda e: (e.work, -e.seq))
    assert chain.tip.hash == best.hash


def test_invalid_block_inside_heavier_branch_rolls_back(chain):
    base = mine(chain); chain.submit(base)
    a = mine(chain, MA); chain.submit(a)
    before = snapshot(chain)
    y1 = mine(chain, MB, parent=base.hash); chain.submit(y1)
    assert chain.tip.hash == a.hash
    cb = make_coinbase(3, [TxOut(SUBSIDY + 1000, MB.pkh)])                   # excess coinbase
    y2 = raw_mine(bytes.fromhex(y1.hash), [cb], target_for_bits(11), y1.header.timestamp + 600).block
    r = chain.submit(y2)
    assert r.status == "REJECTED" and r.code == "EXCESS_COINBASE"
    assert snapshot(chain) == before
    assert chain.entries[y2.hash].invalid and not chain.entries[y1.hash].invalid
    good = mine(chain, MB, bits=11, parent=y1.hash)
    assert chain.submit(good).status == "REORG" and chain.tip.hash == good.hash


def test_descendant_of_invalid_block_is_rejected(chain):
    cb = make_coinbase(1, [TxOut(SUBSIDY + 5, MA.pkh)])
    bad = raw_mine(bytes.fromhex(chain.tip.hash), [cb], target_for_bits(8), GENESIS_TIME + 600).block
    chain.submit(bad)
    cb2 = make_coinbase(2, [TxOut(SUBSIDY, MA.pkh)])
    child = raw_mine(bytes.fromhex(bad.hash), [cb2], target_for_bits(8), GENESIS_TIME + 1200).block
    r = chain.submit(child)
    assert r.status == "REJECTED" and r.code == "INVALID_PARENT"


def test_orphan_waits_for_parent(chain):
    p = mine(chain)
    cb = make_coinbase(2, [TxOut(SUBSIDY, MA.pkh)])
    c = raw_mine(bytes.fromhex(p.hash), [cb], target_for_bits(8), p.header.timestamp + 600).block
    assert chain.submit(c).status == "ORPHAN" and chain.height == 0
    r = chain.submit(p)
    assert r.children and r.children[0].status == "CONNECTED" and chain.tip.hash == c.hash


def test_save_and_load(chain, tmp_path):
    base = mine(chain); chain.submit(base)
    chain.submit(mine(chain, MA))
    chain.submit(mine(chain, MB, parent=base.hash))
    p = tmp_path / "node.json"
    chain.save(str(p))
    again = Chain.load(str(p))
    assert snapshot(again) == snapshot(chain) and len(again.entries) == len(chain.entries)
