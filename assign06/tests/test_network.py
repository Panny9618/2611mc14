"""Small live networks on localhost TCP (in one process) plus the full experiment."""

import asyncio
import json
import os
import subprocess
import sys

import pytest

from netlab.experiment import run as run_experiment
from netlab.node import Node
from netlab.protocol import encode, read_frame


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 60))


async def until(pred, timeout=10.0):
    t0 = asyncio.get_running_loop().time()
    while not pred():
        if asyncio.get_running_loop().time() - t0 > timeout:
            raise AssertionError("condition not reached")
        await asyncio.sleep(0.03)


async def net(n=3, **kw):
    nodes = []
    for i in range(n):
        seeds = [("127.0.0.1", nodes[0].port)] if nodes else []
        node = Node(f"t{i}", seeds=seeds, **kw)
        await node.start()
        nodes.append(node)
    if n > 1:
        await until(lambda: all(len([p for p in x.peers.values() if p.ready]) >= 1 for x in nodes))
    return nodes


async def stop(nodes):
    for n in nodes:
        await n.stop()


async def raw_peer(port, name):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(encode("version", {"version": 1, "node_id": name, "listen_port": 0, "height": 0, "tip": "00" * 32, "agent": "t"}))
    await w.drain()
    got = []
    while len(got) < 2:
        got.append((await asyncio.wait_for(read_frame(r), 5))[0])
    w.write(encode("verack", {}))
    await w.drain()
    return r, w


async def closed(r, t=5):
    try:
        while True:
            await asyncio.wait_for(read_frame(r), t)
    except asyncio.TimeoutError:
        return False
    except Exception:
        return True


def test_handshake_discovery_and_tx_relay():
    async def go():
        nodes = await net(4)
        await until(lambda: all(len({i for i in n.addrbook.values() if i}) == 3 for n in nodes))
        r = await nodes[1].control_cmd({"cmd": "pay", "from_scalar": 0xA11CE, "to_scalar": 0xB0B, "amount": 5, "fee": 1})
        await until(lambda: all(r["txid"] in n.mempool for n in nodes))
        assert all(n.log.counts.get("in_tx", 0) <= 1 for n in nodes)          # body fetched at most once
        await stop(nodes)
    run(go())


def test_block_relay_and_catch_up_of_late_joiner():
    async def go():
        nodes = await net(2)
        for _ in range(3):
            await nodes[0].control_cmd({"cmd": "mine", "miner_scalar": 7, "bits": 8})
        await until(lambda: nodes[1].chain.height == 3)
        late = Node("late", seeds=[("127.0.0.1", nodes[1].port)])
        await late.start()
        await until(lambda: late.chain.tip.hash == nodes[0].chain.tip.hash)     # getblocks locator sync
        await stop(nodes + [late])
    run(go())


def test_malformed_and_oversize_frames_get_banned():
    async def go():
        (a,) = await net(1)
        r, w = await raw_peer(a.port, "evil")
        w.write(b"TOY6" + b"tx".ljust(12, b"\0") + (9 << 20).to_bytes(4, "big") + bytes(4))
        await w.drain()
        assert await closed(r)
        await until(lambda: a.is_banned("evil"))
        with pytest.raises(Exception):
            r2, _ = await raw_peer(a.port, "evil")
            assert await closed(r2, 2)
            raise ConnectionError
        await stop([a])
    run(go())


def test_rate_limit_and_scoring():
    async def go():
        (a,) = await net(1)
        r, w = await raw_peer(a.port, "spammer")
        try:
            for i in range(600):
                w.write(encode("ping", {"nonce": i}))
            await w.drain()
        except ConnectionError:
            pass
        await until(lambda: a.is_banned("spammer"))
        assert a.log.counts["misbehaviour"] >= 50
        await stop([a])
    run(go())


def test_small_errors_are_tolerated():
    async def go():
        (a,) = await net(1)
        r, w = await raw_peer(a.port, "clumsy")
        w.write(encode("hello", {}))                                    # +5 only
        w.write(encode("ping", {"nonce": 3}))
        await w.drain()
        cmds = []
        while "pong" not in cmds:
            cmds.append((await asyncio.wait_for(read_frame(r), 5))[0])
        assert not a.is_banned("clumsy")
        w.close()
        await stop([a])
    run(go())


def test_handshake_timeout_and_messages_before_handshake():
    import netlab.node as nodemod
    old = nodemod.HANDSHAKE_TIMEOUT
    nodemod.HANDSHAKE_TIMEOUT = 0.5

    async def go():
        (a,) = await net(1)
        r, w = await asyncio.open_connection("127.0.0.1", a.port)
        w.write(encode("ping", {"nonce": 1}))                            # not allowed yet
        await w.drain()
        assert await closed(r, 3)                                        # silent peer times out
        assert a.log.counts.get("misbehaviour", 0) >= 1
        await stop([a])
    try:
        run(go())
    finally:
        nodemod.HANDSHAKE_TIMEOUT = old


def test_invalid_block_bans_sender():
    async def go():
        nodes = await net(1)
        a = nodes[0]
        await a.control_cmd({"cmd": "mine", "miner_scalar": 7, "bits": 8})
        blk = a.chain.blocks[a.chain.tip.hash].to_dict()
        blk["header"]["nonce"] += 1
        r, w = await raw_peer(a.port, "liar")
        w.write(encode("block", {"block": blk}))
        await w.drain()
        await until(lambda: a.is_banned("liar"))
        await stop(nodes)
    run(go())


def test_partition_and_heal_converge():
    async def go():
        nodes = await net(4)
        await until(lambda: all(len({i for i in n.addrbook.values() if i}) == 3 for n in nodes))
        A, B = nodes[:2], nodes[2:]
        for n in A:
            await n.control_cmd({"cmd": "partition", "block": [x.id for x in B]})
        for n in B:
            await n.control_cmd({"cmd": "partition", "block": [x.id for x in A]})
        await until(lambda: all(not any(p in {x.id for x in (B if n in A else A)} for p in n.peers) for n in nodes))
        await A[0].control_cmd({"cmd": "mine", "miner_scalar": 1, "bits": 8})
        await B[0].control_cmd({"cmd": "mine", "miner_scalar": 2, "bits": 8})
        await until(lambda: B[1].chain.height == 1)
        await B[1].control_cmd({"cmd": "mine", "miner_scalar": 3, "bits": 8})
        for n in nodes:
            await n.control_cmd({"cmd": "heal"})
        await until(lambda: len({n.chain.tip.hash for n in nodes}) == 1, 20)
        assert nodes[0].chain.height == 2 and nodes[0].log.counts.get("reorg", 0) == 1
        await stop(nodes)
    run(go())


def test_full_experiment_inproc(tmp_path):
    ok = asyncio.run(run_experiment(str(tmp_path), inproc=True, say=lambda *_: None))
    assert ok
    summary = (tmp_path / "summary.md").read_text()
    assert "❌" not in summary
    recs = [json.loads(line) for line in (tmp_path / "logs" / "combined.jsonl").read_text().splitlines()]
    assert {"ts", "node", "peer", "object", "event"} <= set(recs[0])
    assert any(r["event"] == "reorg" for r in recs) and any(r["event"] == "mempool_readd" for r in recs)


def test_full_experiment_separate_processes(tmp_path):
    src = os.path.join(os.path.dirname(__file__), "..", "src")
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, [src, os.environ.get("PYTHONPATH")]))}
    r = subprocess.run([sys.executable, "-m", "netlab", "experiment", "--out", str(tmp_path)],
                       capture_output=True, text=True, env=env, timeout=180)
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-3000:]
    assert "[FAIL]" not in r.stdout and r.stdout.count("[PASS]") == 16
