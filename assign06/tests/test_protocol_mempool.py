import asyncio

import pytest

from netlab.chain import Chain
from netlab.crypto import KeyPair
from netlab.mempool import RBF_FACTOR, Mempool, tx_size
from netlab.node import ALICE, BOB, CAROL, DAVE, default_genesis
from netlab.protocol import (HEADER_LEN, MAGIC, MAX_PAYLOAD, FrameError, MessageError, checksum, encode, parse,
                             read_frame)
from netlab.state import Rejected
from netlab.wallet import build_payment


def frames(data: bytes):
    async def go():
        r = asyncio.StreamReader()
        r.feed_data(data)
        r.feed_eof()
        out = []
        while True:
            try:
                out.append(await read_frame(r))
            except asyncio.IncompleteReadError:
                return out
            except (FrameError, MessageError) as e:
                out.append(e)
                if isinstance(e, FrameError):
                    return out
    return asyncio.run(go())


# ------------------------------------------------------------------ framing
def test_frame_layout_and_roundtrip():
    f = encode("ping", {"nonce": 7})
    assert f[:4] == MAGIC and f[4:16] == b"ping".ljust(12, b"\0")
    body = f[HEADER_LEN:]
    assert int.from_bytes(f[16:20], "big") == len(body) and f[20:24] == checksum(body)
    (cmd, raw), = frames(f)
    assert cmd == "ping" and parse(cmd, raw) == {"nonce": 7}


def test_several_frames_in_one_stream():
    got = frames(encode("verack", {}) + encode("ping", {"nonce": 1}) + encode("getaddr", {}))
    assert [c for c, _ in got] == ["verack", "ping", "getaddr"]


def test_bad_magic_is_fatal():
    (e,) = frames(b"XXXX" + encode("ping", {"nonce": 1})[4:])
    assert isinstance(e, FrameError) and e.code == "BAD_MAGIC"


def test_oversize_rejected_before_reading_payload():
    hdr = MAGIC + b"block".ljust(12, b"\0") + (MAX_PAYLOAD + 1).to_bytes(4, "big") + b"\0" * 4
    (e,) = frames(hdr)                    # no payload follows, yet we fail immediately
    assert isinstance(e, FrameError) and e.code == "OVERSIZE"


def test_bad_checksum_is_recoverable():
    f = bytearray(encode("ping", {"nonce": 1}))
    f[20] ^= 0xFF
    got = frames(bytes(f) + encode("ping", {"nonce": 2}))
    assert isinstance(got[0], MessageError) and got[0].code == "BAD_CHECKSUM"
    assert got[1][0] == "ping"            # stream still aligned


@pytest.mark.parametrize("cmd,raw,code", [
    ("ping", b"{oops", "BAD_JSON"), ("ping", b"[1]", "BAD_SCHEMA"), ("ping", b'{"nonce":-1}', "BAD_SCHEMA"),
    ("inv", b'{"items":[]}', "BAD_SCHEMA"), ("inv", b'{"items":[{"type":"coin","id":"00"}]}', "BAD_SCHEMA"),
    ("version", b'{"version":1}', "BAD_SCHEMA"), ("hello", b"{}", "UNKNOWN_COMMAND"),
    ("verack", b'{"x":1}', "BAD_SCHEMA"), ("getblocks", b'{"locator":[]}', "BAD_SCHEMA"),
])
def test_schema_errors(cmd, raw, code):
    with pytest.raises(MessageError) as e:
        parse(cmd, raw)
    assert e.value.code == code


def test_inv_limit():
    items = [{"type": "tx", "id": "ab" * 32}] * 501
    with pytest.raises(MessageError):
        parse("inv", __import__("json").dumps({"items": items}).encode())


# ------------------------------------------------------------------ mempool
@pytest.fixture
def chain():
    return Chain(default_genesis())


def test_mempool_accepts_and_suppresses_duplicates(chain):
    mp = Mempool()
    tx = build_payment(chain.state, ALICE, BOB.pkh, 25, 1).tx
    assert mp.add(tx, chain.state)[0] == "ACCEPTED"
    with pytest.raises(Rejected) as e:
        mp.add(tx, chain.state)
    assert e.value.code == "DUPLICATE"


def test_mempool_rejects_invalid(chain):
    mp = Mempool()
    tx = build_payment(chain.state, ALICE, BOB.pkh, 25, 1).tx
    from dataclasses import replace
    from netlab.tx import TxOut
    bad = replace(tx, outputs=(TxOut(26, BOB.pkh),) + tx.outputs[1:], _cache={})
    with pytest.raises(Rejected) as e:
        mp.add(bad, chain.state)
    assert e.value.code == "BAD_SIGNATURE" and len(mp) == 0


def test_conflict_and_replace_by_fee(chain):
    mp = Mempool()
    low = build_payment(chain.state, BOB, CAROL.pkh, 20, 1).tx
    same_fee = build_payment(chain.state, BOB, DAVE.pkh, 20, 1).tx
    high = build_payment(chain.state, BOB, DAVE.pkh, 20, 10).tx
    mp.add(low, chain.state)
    with pytest.raises(Rejected) as e:
        mp.add(same_fee, chain.state)
    assert e.value.code == "CONFLICT"
    status, evicted = mp.add(high, chain.state)
    assert status == "REPLACED" and evicted == [low.txid] and low.txid not in mp and high.txid in mp
    assert mp.entries[high.txid].feerate >= RBF_FACTOR * (1 / tx_size(low))


def test_feerate_ordering(chain):
    mp = Mempool()
    a = build_payment(chain.state, ALICE, CAROL.pkh, 5, 1).tx       # spends Alice's 70
    b = build_payment(chain.state, BOB, CAROL.pkh, 5, 9).tx         # Bob's 50
    c = build_payment(chain.state, CAROL, DAVE.pkh, 5, 4).tx        # Carol's 30
    for t in (a, b, c):
        mp.add(t, chain.state)
    assert mp.select() == [b, c, a]


def test_expiry(chain):
    now = [1000.0]
    mp = Mempool(expiry=60, clock=lambda: now[0])
    tx = build_payment(chain.state, ALICE, BOB.pkh, 25, 1).tx
    mp.add(tx, chain.state)
    now[0] += 59
    assert mp.expire() == [] and tx.txid in mp
    now[0] += 2
    assert mp.expire() == [tx.txid] and len(mp) == 0


def test_capacity_evicts_lowest_feerate(chain):
    mp = Mempool(max_txs=2)
    a = build_payment(chain.state, ALICE, CAROL.pkh, 5, 1).tx
    b = build_payment(chain.state, BOB, CAROL.pkh, 5, 2).tx
    c = build_payment(chain.state, CAROL, DAVE.pkh, 5, 9).tx
    mp.add(a, chain.state); mp.add(b, chain.state)
    _, evicted = mp.add(c, chain.state)
    assert evicted == [a.txid] and set(mp.entries) == {b.txid, c.txid}


def test_revalidate_after_block(chain):
    from netlab.block import target_for_bits
    mp = Mempool()
    t1 = build_payment(chain.state, BOB, CAROL.pkh, 20, 1).tx
    other = build_payment(chain.state, ALICE, CAROL.pkh, 5, 1).tx
    mp.add(t1, chain.state); mp.add(other, chain.state)
    conflict = build_payment(chain.state, BOB, DAVE.pkh, 30, 1).tx
    m = chain.build_and_mine(KeyPair.from_scalar(9).pkh, target_for_bits(8), [conflict])
    chain.submit(m.block)
    gone, invalid = mp.revalidate(chain.state)
    assert gone == [t1.txid] and other.txid in mp


def test_unconfirmed_parent_refused(chain):
    from netlab.chain import Undo, _apply_tx
    from netlab.state import ChainState
    mp = Mempool()
    t1 = build_payment(chain.state, ALICE, BOB.pkh, 25, 1).tx
    mp.add(t1, chain.state)
    st = ChainState(); st.utxos = dict(chain.state.utxos)
    _apply_tx(st, t1, Undo())
    child = build_payment(st, BOB, CAROL.pkh, 70, 1).tx            # needs t1's output
    if any(i.prev.txid == t1.txid for i in child.inputs):
        with pytest.raises(Rejected) as e:
            mp.add(child, chain.state)
        assert e.value.code == "MISSING_INPUT"
