"""Five-node experiment over localhost TCP.

Phases
  1 discovery     5 nodes start; each knows only n1 (the seed); getaddr/addr fills in the rest
  2 tx relay      a payment injected at n2 spreads by inv -> getdata -> tx
  3 block relay   n5 mines; every node converges on the block, mempools empty
  4 bad peers     a raw-socket attacker sends garbage, an oversized frame, bad checksums,
                  bad JSON, unknown commands, a ping flood and an invalid block to n3;
                  n3 disconnects/bans each identity and keeps working
  5 partition     {n1, n2} | {n3, n4, n5} with link latency; each side mines a block,
                  side B mines one more; side A also confirms a tx that conflicts with side B
  6 heal          links restored; all honest nodes converge on the most-work chain;
                  the still-valid tx from the stale block returns to every mempool,
                  the conflicting one is dropped
  7 confirm       the reconsidered tx is mined; all nodes agree again
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import time

from .block import Block
from .node import ALICE, BOB, CAROL, DAVE, Node
from .protocol import encode, read_frame

MINER_SCALARS = {"n1": 0x1111, "n2": 0x2222, "n3": 0x3333, "n4": 0x4444, "n5": 0x5555}
SIDE_A, SIDE_B = ["n1", "n2"], ["n3", "n4", "n5"]
IDS = SIDE_A + SIDE_B


class Ctl:
    def __init__(self, nid: str, port: int, cport: int):
        self.id, self.port, self.cport = nid, port, cport

    async def __call__(self, cmd: str, **kw) -> dict:
        r, w = await asyncio.open_connection("127.0.0.1", self.cport)
        w.write((json.dumps({"cmd": cmd, **kw}) + "\n").encode())
        await w.drain()
        line = await asyncio.wait_for(r.readline(), 30)
        w.close()
        resp = json.loads(line)
        if "error" in resp:
            raise RuntimeError(f"{self.id} {cmd}: {resp['error']}")
        return resp


class Experiment:
    def __init__(self, out_dir: str, inproc: bool = False, say=print):
        self.out, self.inproc, self.say = out_dir, inproc, say
        self.logs = os.path.join(out_dir, "logs")
        self.ctl: dict[str, Ctl] = {}
        self.procs, self.nodes = [], []
        self.checks: list[tuple[str, bool, str]] = []
        self.timings: dict[str, float] = {}
        self.notes: list[str] = []

    # ------------------------------------------------------------------ helpers
    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append((name, ok, detail))
        self.say(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))

    async def status(self, ids=IDS) -> dict[str, dict]:
        res = await asyncio.gather(*(self.ctl[i]("status") for i in ids))
        return dict(zip(ids, res))

    async def wait(self, pred, ids=IDS, timeout: float = 20.0) -> tuple[bool, float, dict]:
        t0 = time.monotonic()
        while True:
            st = await self.status(ids)
            if pred(st):
                return True, time.monotonic() - t0, st
            if time.monotonic() - t0 > timeout:
                return False, time.monotonic() - t0, st
            await asyncio.sleep(0.05)

    # ------------------------------------------------------------------ start / stop
    async def start(self) -> None:
        if os.path.exists(self.logs):
            shutil.rmtree(self.logs)
        os.makedirs(self.logs)
        seed_port = None
        for nid in IDS:
            seeds = [("127.0.0.1", seed_port)] if seed_port else []
            if self.inproc:
                node = Node(nid, seeds=seeds, log_dir=self.logs)
                await node.start()
                self.nodes.append(node)
                port, cport = node.port, node.control_port
            else:
                args = [sys.executable, "-m", "netlab", "node", "--id", nid, "--log-dir", self.logs]
                if seed_port:
                    args += ["--seed", f"127.0.0.1:{seed_port}"]
                env = {**os.environ, "PYTHONPATH": os.pathsep.join(filter(None, [
                    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), os.environ.get("PYTHONPATH")]))}
                p = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, env=env)
                line = (await asyncio.wait_for(p.stdout.readline(), 15)).decode().split()
                assert line[0] == "READY", line
                port, cport = int(line[2]), int(line[3])
                self.procs.append(p)
            self.ctl[nid] = Ctl(nid, port, cport)
            seed_port = seed_port or port
            self.say(f"  started {nid}: p2p port {port}, control port {cport}" + ("" if nid == "n1" else f", seed n1"))

    async def stop(self) -> None:
        for c in self.ctl.values():
            try:
                await c("stop")
            except Exception:
                pass
        for p in self.procs:
            try:
                await asyncio.wait_for(p.wait(), 5)
            except asyncio.TimeoutError:
                p.kill()
        for n in self.nodes:
            await n.stop()

    # ------------------------------------------------------------------ attacker
    async def _handshake(self, port: int, name: str):
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(encode("version", {"version": 1, "node_id": name, "listen_port": 0, "height": 0,
                                   "tip": "00" * 32, "agent": "attacker/0"}))
        await w.drain()
        got = set()
        while not {"version", "verack"} <= got:
            cmd, _ = await asyncio.wait_for(read_frame(r), 5)
            got.add(cmd)
            if cmd == "reject":
                raise ConnectionRefusedError("rejected during handshake")
        w.write(encode("verack", {}))
        await w.drain()
        return r, w

    @staticmethod
    async def _closed(r, timeout: float = 5.0) -> bool:
        try:
            while True:
                await asyncio.wait_for(read_frame(r), timeout)
        except (asyncio.IncompleteReadError, ConnectionError):
            return True
        except asyncio.TimeoutError:
            return False
        except Exception:
            return True

    async def attack(self, target: str) -> dict:
        port = self.ctl[target].port
        out = {}
        # 1. garbage bytes before any handshake
        r, w = await asyncio.open_connection("127.0.0.1", port)
        try:
            w.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n" + bytes(32))
            await w.drain()
            out["garbage_closed"] = await self._closed(r)
        except ConnectionError:
            out["garbage_closed"] = True
        # 2. valid handshake, then a frame claiming a 50 MB payload
        r, w = await self._handshake(port, "mallory1")
        try:
            w.write(b"TOY6" + b"block".ljust(12, b"\0") + (50 << 20).to_bytes(4, "big") + b"\0\0\0\0")
            await w.drain()
            out["oversize_closed"] = await self._closed(r)
        except ConnectionError:
            out["oversize_closed"] = True
        try:
            r2, w2 = await self._handshake(port, "mallory1")
            out["banned_reconnect_refused"] = await self._closed(r2, 3)
        except (ConnectionRefusedError, asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError):
            out["banned_reconnect_refused"] = True
        # 3. stream of malformed messages, then a ping flood
        r, w = await self._handshake(port, "mallory2")
        good = encode("ping", {"nonce": 1})
        w.write(good[:20] + b"\xde\xad\xbe\xef" + good[24:])                     # bad checksum
        body = b"{not json"
        import hashlib
        ck = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
        w.write(b"TOY6" + b"inv".ljust(12, b"\0") + len(body).to_bytes(4, "big") + ck + body)  # bad JSON
        w.write(encode("hello", {}))                                              # unknown command
        w.write(encode("inv", {"items": [{"type": "coin", "id": "zz"}]}))        # bad schema
        out["flood_closed"] = False
        try:
            await w.drain()
            for i in range(1000):                                                 # flood: >> 100 msgs/s
                if w.is_closing() or r.at_eof():
                    break
                w.write(encode("ping", {"nonce": i}))
                if i % 50 == 0:
                    await w.drain()
            out["flood_closed"] = await self._closed(r)
        except ConnectionError:
            out["flood_closed"] = True                                            # node hung up on us mid-flood
        # 4. an invalid block (proof of work broken after mining)
        blk = Block.from_dict((await self.ctl[target]("get_block", ref=1))["block"])
        from dataclasses import replace
        bad = Block(replace(blk.header, nonce=blk.header.nonce + 1), blk.txs)
        while bad.header.meets_target():
            bad = Block(replace(bad.header, nonce=bad.header.nonce + 1), blk.txs)
        r, w = await self._handshake(port, "mallory3")
        try:
            w.write(encode("block", {"block": bad.to_dict()}))
            await w.drain()
            out["invalid_block_closed"] = await self._closed(r)
        except ConnectionError:
            out["invalid_block_closed"] = True
        return out

    # ------------------------------------------------------------------ scenario
    async def run(self) -> bool:
        say = self.say
        say("Phase 1 - start 5 nodes; only n1 is given as a seed")
        await self.start()
        ok, t, st = await self.wait(lambda s: all(len(x["known_nodes"]) == 4 and len(x["peers"]) >= 2 for x in s.values()))
        self.timings["discovery"] = t
        edges = sorted({tuple(sorted((i, p))) for i, x in st.items() for p in x["peers"]})
        self.check("peer discovery: every node learned all 4 others from getaddr/addr", ok, f"{t:.2f} s; links {edges}")
        self.topology = edges
        for c in self.ctl.values():
            await c("latency", ms=25, jitter=15)
        self.notes.append("Link latency 25 ± 15 ms on every node from phase 2 on.")

        say("\nPhase 2 - transaction relay (inv -> getdata -> tx)")
        before = await self.status()
        t0 = await self.ctl["n2"]("pay", from_scalar=0xA11CE, to_scalar=0xB0B, amount=25, fee=1)
        tx0 = t0["txid"]
        ok, t, st = await self.wait(lambda s: all(tx0 in x["mempool"] for x in s.values()))
        self.timings["tx_propagation"] = t
        self.check("tx injected at n2 reached all 5 mempools", ok, f"{t:.2f} s")
        dup = {i: st[i]["counts"].get("in_tx", 0) - before[i]["counts"].get("in_tx", 0) for i in IDS}
        invs = {i: st[i]["counts"].get("in_inv", 0) - before[i]["counts"].get("in_inv", 0) for i in IDS}
        self.check("each node downloaded the tx body at most once (duplicate suppression)",
                   all(v <= 1 for v in dup.values()), f"tx bodies received {dup}; inv messages received {invs}")

        say("\nPhase 3 - block relay")
        b = await self.ctl["n5"]("mine", miner_scalar=MINER_SCALARS["n5"], bits=12)
        ok, t, st = await self.wait(lambda s: len({x["tip"] for x in s.values()}) == 1 and all(not x["mempool"] for x in s.values()))
        self.timings["block_propagation"] = t
        self.check("block mined at n5 reached all nodes; tx confirmed and removed from mempools", ok, f"{t:.2f} s, height 1")

        say("\nPhase 4 - misbehaving peer attacks n3")
        res = await self.attack("n3")
        ok, t, st = await self.wait(lambda s: {"mallory1", "mallory2", "mallory3"} <= set(s["n3"]["banned"]), ids=["n3"], timeout=10)
        n3 = st["n3"]
        self.check("garbage before handshake: connection closed", res["garbage_closed"])
        self.check("50 MB length prefix: closed before reading, peer banned, reconnect refused",
                   res["oversize_closed"] and res["banned_reconnect_refused"])
        self.check("bad checksum / bad JSON / unknown command / bad schema / 1000-ping flood: rate-limited, scored, banned",
                   res["flood_closed"])
        self.check("invalid block (broken PoW): peer banned", res["invalid_block_closed"])
        self.check("n3 banned all three identities and kept its honest peers", ok and len(n3["peers"]) >= 1,
                   f"banned {n3['banned']}; peers {n3['peers']}; misbehaviour events {n3['counts'].get('misbehaviour', 0)}")
        self.attack_counts = {k: v for k, v in n3["counts"].items() if k in ("misbehaviour", "ban", "disconnect")}

        say("\nPhase 5 - partition {n1,n2} | {n3,n4,n5}")
        for i in SIDE_A:
            await self.ctl[i]("partition", block=SIDE_B)
        for i in SIDE_B:
            await self.ctl[i]("partition", block=SIDE_A)
        ok, t, st = await self.wait(lambda s: all(not (set(x["peers"]) & set(SIDE_B if i in SIDE_A else SIDE_A)) for i, x in s.items()))
        self.check("partition in place (no links across the sides)", ok)
        a1 = await self.ctl["n1"]("pay", from_scalar=0xA11CE, to_scalar=0xDA7E, amount=30, fee=2)
        ax = await self.ctl["n1"]("pay", from_scalar=0xB0B, to_scalar=0xCA401, amount=20, fee=1)
        await self.wait(lambda s: {a1["txid"], ax["txid"]} <= set(s["n2"]["mempool"]), ids=["n2"])
        ba = await self.ctl["n2"]("mine", miner_scalar=MINER_SCALARS["n2"], bits=12)
        b1 = await self.ctl["n4"]("pay", from_scalar=0xB0B, to_scalar=0xDA7E, amount=45, fee=1)
        await self.wait(lambda s: all(b1["txid"] in x["mempool"] for x in s.values()), ids=SIDE_B)
        bb1 = await self.ctl["n4"]("mine", miner_scalar=MINER_SCALARS["n4"], bits=12)
        await self.wait(lambda s: all(x["tip"] == bb1["hash"] for x in s.values()), ids=SIDE_B)
        bb2 = await self.ctl["n5"]("mine", miner_scalar=MINER_SCALARS["n5"], bits=12)
        okA, _, sA = await self.wait(lambda s: all(x["tip"] == ba["hash"] for x in s.values()), ids=SIDE_A)
        okB, _, sB = await self.wait(lambda s: all(x["tip"] == bb2["hash"] for x in s.values()), ids=SIDE_B)
        self.ids = {"tx_side_a_valid_everywhere": a1["txid"], "tx_side_a_conflicting": ax["txid"],
                    "tx_side_b": b1["txid"], "block_A2": ba["hash"], "block_B2": bb1["hash"], "block_B3": bb2["hash"]}
        self.check("side A converged on its own block (height 2)", okA and sA["n1"]["height"] == 2)
        self.check("side B mined two blocks (height 3) and disagrees with side A", okB and sB["n3"]["height"] == 3)

        say("\nPhase 6 - heal the partition")
        for c in self.ctl.values():
            await c("heal")
        ok, t, st = await self.wait(lambda s: len({x["tip"] for x in s.values()}) == 1 and len({x["utxo_hash"] for x in s.values()}) == 1
                                    and all(a1["txid"] in x["mempool"] for x in s.values()), timeout=30)
        self.timings["convergence_after_heal"] = t
        self.check("all 5 nodes converged on the most-work chain (side B's tip, height 3)", ok and st["n1"]["tip"] == bb2["hash"],
                   f"{t:.2f} s; same tip and same UTXO-set hash on every node")
        self.check("tx from the stale block that is still valid returned to every mempool",
                   all(a1["txid"] in x["mempool"] for x in st.values()))
        self.check("conflicting tx from the stale block was dropped everywhere",
                   all(ax["txid"] not in x["mempool"] for x in st.values()))
        n1c = st["n1"]["counts"]
        self.notes.append(f"n1 during the run: {n1c.get('reorg', 0)} reorg, {n1c.get('mempool_readd', 0)} tx re-added to the mempool "
                          f"from the stale block, {n1c.get('mempool_removed', 0)} txs removed from the mempool because a block "
                          f"confirmed or conflicted with them.")

        say("\nPhase 7 - confirm the reconsidered transaction")
        c = await self.ctl["n2"]("mine", miner_scalar=MINER_SCALARS["n2"], bits=12)
        ok, t, st = await self.wait(lambda s: all(x["tip"] == c["hash"] and not x["mempool"] for x in s.values()))
        self.check("final block from n2 accepted by all; mempools empty; all UTXO sets identical",
                   ok and len({x["utxo_hash"] for x in st.values()}) == 1,
                   f"height {st['n1']['height']}, balances {st['n1']['balances']}")
        self.final = st
        await self.stop()
        self.write_summary()
        return all(ok for _, ok, _ in self.checks)

    # ------------------------------------------------------------------ outputs
    def write_summary(self) -> None:
        recs = []
        for f in sorted(os.listdir(self.logs)):
            if f.endswith(".jsonl") and f != "combined.jsonl":
                with open(os.path.join(self.logs, f), encoding="utf-8") as fh:
                    recs += [json.loads(line) for line in fh]
        recs.sort(key=lambda r: r["ts"])
        with open(os.path.join(self.logs, "combined.jsonl"), "w", encoding="utf-8") as fh:
            for r in recs:
                fh.write(json.dumps(r) + "\n")
        lines = ["# Assignment 6 — Experiment summary", "",
                 f"Mode: {'one process, 5 nodes' if self.inproc else '5 separate OS processes'} over localhost TCP. "
                 f"Generated by `p2p experiment`.", "",
                 "## Checks", ""]
        lines += [f"- {'✅' if ok else '❌'} **{n}**" + (f" — {d}" if d else "") for n, ok, d in self.checks]
        lines += ["", "## Timings", ""] + [f"- {k.replace('_', ' ')}: {v:.2f} s" for k, v in self.timings.items()]
        lines += ["", "## Topology after discovery", "", ", ".join(f"{a}–{b}" for a, b in self.topology)]
        lines += ["", "## Objects", ""] + [f"- {k}: `{v[:16]}…`" for k, v in self.ids.items()]
        lines += ["", "## Message counts per node (whole run)", "",
                  "| Node | inv in | getdata out | tx in | block in | reorgs | mempool re-adds | misbehaviour | bans |",
                  "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
        for i, s in self.final.items():
            c = s["counts"]
            lines.append(f"| {i} | {c.get('in_inv', 0)} | {c.get('out_getdata', 0)} | {c.get('in_tx', 0)} | {c.get('in_block', 0)} "
                         f"| {c.get('reorg', 0)} | {c.get('mempool_readd', 0)} | {c.get('misbehaviour', 0)} | {c.get('ban', 0)} |")
        lines += ["", "## Notes", ""] + [f"- {n}" for n in self.notes]
        lines += ["", f"Structured logs: `logs/n1.jsonl` … `logs/n5.jsonl` and `logs/combined.jsonl` ({len(recs):,} events, "
                      "fields: ts, time, node, peer, object, event, …).", ""]
        with open(os.path.join(self.out, "summary.md"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))


async def run(out_dir: str, inproc: bool = False, say=print) -> bool:
    exp = Experiment(out_dir, inproc, say)
    try:
        ok = await exp.run()
    except BaseException:
        await exp.stop()
        raise
    say(f"\nwrote {out_dir}/summary.md and {out_dir}/logs/")
    return ok
