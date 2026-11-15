import itertools

import pytest

from chainlab.block import target_for_bits
from chainlab.chain import GENESIS_TIME, Chain, make_genesis
from chainlab.crypto import KeyPair
from chainlab.tx import TxOut

ALICE, BOB, CAROL = (KeyPair.from_scalar(d) for d in (0xA11CE, 0xB0B, 0xCA401))
MA, MB = KeyPair.from_scalar(0xAAAA), KeyPair.from_scalar(0xBBBB)
_clock = itertools.count(1)


@pytest.fixture
def chain():
    g = make_genesis([TxOut(40, ALICE.pkh), TxOut(70, ALICE.pkh), TxOut(50, BOB.pkh)])
    return Chain(g, now=lambda: GENESIS_TIME + 10**7)


def mine(ch, miner=MA, bits=8, parent=None, txs=(), payout=None, ts=None):
    """Mine quickly at low difficulty; unique timestamps keep competing blocks distinct."""
    if ts is None:
        parent_ts = ch.entries[parent or ch.tip.hash].header.timestamp
        ts = parent_ts + 600 + next(_clock)          # unique, always after the parent
    return ch.build_and_mine(miner.pkh, target_for_bits(bits), list(txs), parent=parent, timestamp=ts, payout=payout).block


def snapshot(ch):
    return ch.tip.hash, ch.state.utxo_set_hash(), list(ch.active)
