"""A network node: the Assignment 5 chain + mempool + TCP peers.

Connection lifecycle
  1. TCP connect (outbound) or accept (inbound).
  2. Handshake: both sides send `version` (protocol version, node id, listen port,
     height, tip) and answer with `verack`. Only version/verack are allowed
     before that; the handshake must finish within HANDSHAKE_TIMEOUT.
  3. After the handshake: `getaddr` (peer discovery), `getblocks` with a block
     locator (catch up on missing blocks) and an `inv` of our mempool.

Relay: a new tx or block is announced with `inv` (id only). A peer that lacks
it answers `getdata`, and only then is the full `tx` / `block` sent. Each
peer remembers which ids it already knows, so nothing is announced twice to the
same peer. Requests that are not answered within GETDATA_TIMEOUT are retried
with another peer that announced the item.

Defences
  framing   length prefix with a 1 MiB limit, checked before reading the payload
  schema    every message is checked against its schema
  rate      token bucket per peer (RATE msgs/s, BURST); excess messages dropped
  timeouts  handshake, idle connection, ping/pong, getdata
  scoring   misbehaviour points per peer; at 100 the peer is disconnected and banned
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import time
from collections import OrderedDict

from . import __version__
from .block import Block, target_for_bits
from .chain import Chain, make_genesis
from .crypto import KeyPair
from .mempool import Mempool
from .protocol import MAX_INV, PROTOCOL_VERSION, FrameError, MessageError, encode, parse, read_frame
from .state import Rejected
from .tx import Transaction, TxFormatError, TxOut
from .wallet import InsufficientFunds, build_payment

HOST = "127.0.0.1"
HANDSHAKE_TIMEOUT = 5.0
IDLE_TIMEOUT = 30.0
PING_INTERVAL = 5.0
PONG_TIMEOUT = 10.0
GETDATA_TIMEOUT = 3.0
RATE, BURST = 100.0, 200.0
BAN_SCORE = 100

# misbehaviour points
PENALTY = {"BAD_MAGIC": 100, "OVERSIZE": 100, "BAD_CHECKSUM": 25, "BAD_JSON": 25, "BAD_SCHEMA": 25,
           "BAD_COMMAND": 25, "UNKNOWN_COMMAND": 5, "BEFORE_HANDSHAKE": 10, "DUPLICATE_VERSION": 10,
           "RATE_LIMITED": 2, "UNSOLICITED": 5, "INVALID_TX": 20, "INVALID_BLOCK": 100, "MALFORMED_OBJECT": 25}
# rejections that prove the sender relayed something invalid (not just late or conflicting)
BAD_TX_CODES = {"MALFORMED", "INVALID_VALUE", "VALUE_OVERFLOW", "DUPLICATE_INPUT", "VALUE_CREATED", "MISSING_UNLOCK",
                "WRONG_KEY", "NON_CANONICAL_SIGNATURE", "BAD_SIGNATURE", "NO_INPUTS", "NO_OUTPUTS"}
BAD_BLOCK_CODES = {"BAD_POW", "BAD_TARGET", "BAD_MERKLE_ROOT", "BAD_COINBASE", "BAD_TX_COUNT", "DUPLICATE_TX",
                   "INVALID_TX", "EXCESS_COINBASE", "BAD_COINBASE_HEIGHT", "TIME_TOO_OLD", "BAD_VERSION", "INVALID_PARENT"}
LOGGED_CMDS = {"version", "verack", "getaddr", "addr", "inv", "getdata", "notfound", "tx", "block", "getblocks", "reject"}

# Fixed, test-only keys for the shared genesis (public knowledge - never use for real value).
ALICE, BOB, CAROL, DAVE = (KeyPair.from_scalar(d) for d in (0xA11CE, 0xB0B, 0xCA401, 0xDA7E))


def default_genesis() -> Block:
    return make_genesis([TxOut(40, ALICE.pkh), TxOut(70, ALICE.pkh), TxOut(50, BOB.pkh), TxOut(30, CAROL.pkh)])


class Log:
    def __init__(self, node_id: str, path: str | None):
        self.node_id = node_id
        if path:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.f = open(path, "a", encoding="utf-8") if path else None
        self.counts: dict[str, int] = {}

    def __call__(self, event: str, peer: str | None = None, obj: str | None = None, **kw) -> None:
        self.counts[event] = self.counts.get(event, 0) + 1
        if self.f:
            t = time.time()
            rec = {"ts": round(t, 6), "time": time.strftime("%H:%M:%S", time.localtime(t)) + f".{int(t % 1 * 1000):03d}",
                   "node": self.node_id, "peer": peer, "object": obj, "event": event, **kw}
            self.f.write(json.dumps(rec) + "\n")
            self.f.flush()


class Peer:
    def __init__(self, node: "Node", reader, writer, outbound: bool, dial: tuple[str, int] | None):
        self.node, self.reader, self.writer, self.outbound, self.dial = node, reader, writer, outbound, dial
        r = writer.get_extra_info("peername") or ("?", 0)
        self.remote = f"{r[0]}:{r[1]}"
        self.id: str | None = None
        self.listen: tuple[str, int] | None = None
        self.got_version = self.got_verack = False
        self.score = 0
        self.tokens, self.refilled = BURST, time.monotonic()
        self.known: OrderedDict[str, None] = OrderedDict()
        self.queue: asyncio.Queue = asyncio.Queue()
        self.last_recv = time.monotonic()
        self.ping_nonce: int | None = None
        self.ping_sent = 0.0
        self.last_ping = time.monotonic()
        self.closed = False
        self.sender = asyncio.create_task(self._send_loop())

    @property
    def ready(self) -> bool:
        return self.got_version and self.got_verack and not self.closed

    @property
    def label(self) -> str:
        return self.id or self.remote

    def know(self, item: str) -> None:
        self.known[item] = None
        if len(self.known) > 20000:
            self.known.popitem(last=False)

    def take_token(self) -> bool:
        now = time.monotonic()
        self.tokens = min(BURST, self.tokens + (now - self.refilled) * RATE)
        self.refilled = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False

    def send(self, cmd: str, payload: dict, obj: str | None = None) -> None:
        if self.closed:
            return
        self.queue.put_nowait((encode(cmd, payload), time.monotonic()))
        self.node.log.counts[f"out_{cmd}"] = self.node.log.counts.get(f"out_{cmd}", 0) + 1
        if cmd in LOGGED_CMDS:
            self.node.log(f"send_{cmd}", self.label, obj)

    async def _send_loop(self) -> None:
        try:
            while True:
                data, t0 = await self.queue.get()
                delay = self.node.link_delay()
                wait = t0 + delay - time.monotonic()
                if wait > 0:
                    await asyncio.sleep(wait)
                self.writer.write(data)
                await self.writer.drain()
        except (ConnectionError, asyncio.CancelledError, RuntimeError):
            pass

    def close(self, reason: str) -> None:
        if self.closed:
            return
        self.closed = True
        self.node.log("disconnect", self.label, reason=reason, score=self.score)
        self.sender.cancel()
        try:
            self.writer.close()
        except RuntimeError:
            pass


class Node:
    def __init__(self, node_id: str, port: int = 0, control_port: int = 0, seeds: list[tuple[str, int]] | None = None,
                 log_dir: str | None = None, genesis: Block | None = None, max_outbound: int = 2,
                 ban_seconds: float = 60.0, mempool_expiry: float = 600.0, seed: int = 0):
        self.id, self.port, self.control_port = node_id, port, control_port
        self.log = Log(node_id, os.path.join(log_dir, f"{node_id}.jsonl") if log_dir else None)
        self.chain = Chain(genesis or default_genesis())
        self.mempool = Mempool(expiry=mempool_expiry)
        self.peers: dict[str, Peer] = {}                      # ready-or-handshaking peers by node id
        self.conns: set[Peer] = set()
        self.addrbook: dict[tuple[str, int], str | None] = {s: None for s in (seeds or [])}
        self.dialing: set[tuple[str, int]] = set()
        self.banned: dict[str, float] = {}
        self.blocked: set[str] = set()
        self.max_outbound, self.ban_seconds = max_outbound, ban_seconds
        self.latency_ms, self.jitter_ms = 0.0, 0.0
        self.rng = random.Random(seed or hash(node_id))
        self.inflight: dict[str, tuple[str, float]] = {}       # "tx:<id>" -> (peer id, time requested)
        self.announcers: dict[str, list[str]] = {}
        self.seen_tx: OrderedDict[str, None] = OrderedDict()
        self.tasks: list[asyncio.Task] = []
        self.started = time.time()

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> None:
        self.server = await asyncio.start_server(self._on_inbound, HOST, self.port)
        self.port = self.server.sockets[0].getsockname()[1]
        self.control = await asyncio.start_server(self._on_control, HOST, self.control_port)
        self.control_port = self.control.sockets[0].getsockname()[1]
        self.tasks.append(asyncio.create_task(self._maintenance()))
        self.log("listen", port=self.port, control_port=self.control_port, genesis=self.chain.active[0])

    async def stop(self) -> None:
        for t in self.tasks:
            t.cancel()
        for p in list(self.conns):
            p.close("shutdown")
        self.server.close()
        self.control.close()

    def link_delay(self) -> float:
        return max(0.0, (self.latency_ms + self.rng.uniform(-self.jitter_ms, self.jitter_ms)) / 1000)

    # ------------------------------------------------------------------ connections
    async def _on_inbound(self, reader, writer) -> None:
        await self._run_peer(Peer(self, reader, writer, outbound=False, dial=None))

    async def _dial(self, addr: tuple[str, int]) -> None:
        self.dialing.add(addr)
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(*addr), 3)
        except (OSError, asyncio.TimeoutError):
            self.dialing.discard(addr)
            return
        peer = Peer(self, reader, writer, outbound=True, dial=addr)
        self.log("connect_out", f"{addr[0]}:{addr[1]}")
        peer.send("version", self._version_payload())
        self.dialing.discard(addr)
        await self._run_peer(peer)

    def _version_payload(self) -> dict:
        return {"version": PROTOCOL_VERSION, "node_id": self.id, "listen_port": self.port,
                "height": self.chain.height, "tip": self.chain.tip.hash, "agent": f"netlab/{__version__}"}

    async def _run_peer(self, peer: Peer) -> None:
        self.conns.add(peer)
        if not peer.outbound:
            self.log("accept_in", peer.remote)
        try:
            while not peer.closed:
                timeout = HANDSHAKE_TIMEOUT if not peer.ready else IDLE_TIMEOUT
                try:
                    cmd, raw = await asyncio.wait_for(read_frame(peer.reader), timeout)
                except asyncio.TimeoutError:
                    peer.close("handshake timeout" if not peer.ready else "idle timeout")
                    break
                except FrameError as e:
                    self.misbehave(peer, e.code, str(e))
                    peer.close(f"framing error {e.code}")
                    break
                except MessageError as e:
                    self.misbehave(peer, e.code, str(e))
                    continue
                except (asyncio.IncompleteReadError, ConnectionError):
                    peer.close("connection closed by peer")
                    break
                peer.last_recv = time.monotonic()
                if not peer.take_token():
                    self.misbehave(peer, "RATE_LIMITED", f"dropped {cmd}: more than {RATE:.0f} msgs/s")
                    continue
                try:
                    payload = parse(cmd, raw)
                except MessageError as e:
                    self.misbehave(peer, e.code, str(e))
                    peer.send("reject", {"message": cmd[:12], "code": e.code, "reason": str(e)[:200]})
                    continue
                self.log.counts[f"in_{cmd}"] = self.log.counts.get(f"in_{cmd}", 0) + 1
                if not peer.ready and cmd not in ("version", "verack"):
                    self.misbehave(peer, "BEFORE_HANDSHAKE", f"{cmd} before handshake")
                    continue
                await self._dispatch(peer, cmd, payload)
        finally:
            peer.close("ended")
            self.conns.discard(peer)
            if peer.id and self.peers.get(peer.id) is peer:
                del self.peers[peer.id]

    def misbehave(self, peer: Peer, code: str, detail: str) -> None:
        pts = PENALTY.get(code, 10)
        peer.score += pts
        self.log("misbehaviour", peer.label, code=code, points=pts, score=peer.score, detail=detail[:200])
        if peer.score >= BAN_SCORE and not peer.closed:
            if peer.id:
                self.banned[peer.id] = time.time() + self.ban_seconds
                self.log("ban", peer.id, seconds=self.ban_seconds, score=peer.score)
            peer.send("reject", {"message": "", "code": "BANNED", "reason": f"misbehaviour score {peer.score}"})
            peer.close(f"banned (score {peer.score})")

    def is_banned(self, node_id: str) -> bool:
        until = self.banned.get(node_id)
        return until is not None and until > time.time()

    # ------------------------------------------------------------------ dispatch
    async def _dispatch(self, peer: Peer, cmd: str, p: dict) -> None:
        if cmd in LOGGED_CMDS and cmd not in ("tx", "block", "inv", "getdata"):
            self.log(f"recv_{cmd}", peer.label)
        handler = getattr(self, f"_on_{cmd}")
        await handler(peer, p)

    async def _on_version(self, peer: Peer, p: dict) -> None:
        if peer.got_version:
            return self.misbehave(peer, "DUPLICATE_VERSION", "second version message")
        pid = p["node_id"]
        if p["version"] != PROTOCOL_VERSION:
            peer.send("reject", {"message": "version", "code": "OBSOLETE", "reason": f"need protocol {PROTOCOL_VERSION}"})
            return peer.close(f"protocol version {p['version']}")
        if pid == self.id:
            return peer.close("connected to self")
        if self.is_banned(pid):
            peer.send("reject", {"message": "version", "code": "BANNED", "reason": "you are banned"})
            return peer.close("banned peer tried to connect")
        if pid in self.blocked:
            return peer.close("partitioned (blocked)")
        old = self.peers.get(pid)
        if old and not old.closed:
            keep_new = (self.id if peer.outbound else pid) == min(self.id, pid)
            if not keep_new:
                return peer.close("duplicate connection")
            old.close("replaced by duplicate connection")
        peer.id = pid
        peer.listen = (HOST, p["listen_port"])
        self.peers[pid] = peer
        if p["listen_port"]:
            self.addrbook = {a: i for a, i in self.addrbook.items() if a != peer.listen}
            self.addrbook[peer.listen] = pid
        if not peer.outbound:
            peer.send("version", self._version_payload())
        peer.send("verack", {})
        peer.got_version = True
        if peer.got_verack:
            self._on_ready(peer)

    async def _on_verack(self, peer: Peer, p: dict) -> None:
        peer.got_verack = True
        if peer.got_version:
            self._on_ready(peer)

    def _on_ready(self, peer: Peer) -> None:
        self.log("handshake_done", peer.id, outbound=peer.outbound)
        peer.send("getaddr", {})
        if peer.listen and peer.listen[1]:                  # gossip the new node's address to everyone else
            self._gossip_addr([{"node_id": peer.id, "host": peer.listen[0], "port": peer.listen[1]}], exclude=peer)
        peer.send("getblocks", {"locator": self.locator()})
        ids = list(self.mempool.entries)[:MAX_INV]
        if ids:
            for i in ids:
                peer.know(i)
            peer.send("inv", {"items": [{"type": "tx", "id": i} for i in ids]}, obj=f"{len(ids)} mempool txs")

    async def _on_getaddr(self, peer: Peer, p: dict) -> None:
        peers = [{"node_id": self.id, "host": HOST, "port": self.port}]
        peers += [{"node_id": i, "host": a[0], "port": a[1]} for a, i in self.addrbook.items() if i and i != peer.id]
        peer.send("addr", {"peers": peers[:100]})

    async def _on_addr(self, peer: Peer, p: dict) -> None:
        new = []
        for a in p["peers"]:
            addr = (a["host"], a["port"])
            if a["node_id"] != self.id and addr not in self.addrbook:
                self.addrbook[addr] = a["node_id"]
                new.append(a)
                self.log("addr_learned", peer.id, node=a["node_id"], port=a["port"])
        if new:
            self._gossip_addr(new, exclude=peer)

    def _gossip_addr(self, entries: list[dict], exclude: Peer | None) -> None:
        """Forward addresses we just learned (each address is forwarded once, so gossip stops)."""
        for p in self.peers.values():
            if p.ready and p is not exclude:
                p.send("addr", {"peers": [e for e in entries if e["node_id"] != p.id][:100]})

    async def _on_inv(self, peer: Peer, p: dict) -> None:
        want = []
        for it in p["items"]:
            key = f"{it['type']}:{it['id']}"
            peer.know(it["id"])
            if self._have(it["type"], it["id"]):
                self.log.counts["inv_already_have"] = self.log.counts.get("inv_already_have", 0) + 1
                continue
            self.announcers.setdefault(key, [])
            if peer.id not in self.announcers[key]:
                self.announcers[key].append(peer.id)
            if key not in self.inflight:
                self.inflight[key] = (peer.id, time.monotonic())
                want.append(it)
        self.log("recv_inv", peer.id, f"{len(p['items'])} items", requested=len(want))
        if want:
            peer.send("getdata", {"items": want}, obj=", ".join(f"{w['type']}:{w['id'][:12]}" for w in want[:5]))

    async def _on_getdata(self, peer: Peer, p: dict) -> None:
        missing = []
        for it in p["items"]:
            if it["type"] == "tx" and it["id"] in self.mempool:
                peer.send("tx", {"tx": self.mempool.get(it["id"]).to_dict()}, obj=f"tx:{it['id']}")
            elif it["type"] == "block" and it["id"] in self.chain.blocks:
                peer.send("block", {"block": self.chain.blocks[it["id"]].to_dict()}, obj=f"block:{it['id']}")
            else:
                missing.append(it)
            peer.know(it["id"])
        if missing:
            peer.send("notfound", {"items": missing})

    async def _on_notfound(self, peer: Peer, p: dict) -> None:
        for it in p["items"]:
            key = f"{it['type']}:{it['id']}"
            if self.inflight.get(key, (None,))[0] == peer.id:
                del self.inflight[key]
                self._retry(key)

    async def _on_tx(self, peer: Peer, p: dict) -> None:
        try:
            tx = Transaction.from_dict(p["tx"])
            txid = tx.txid
        except (TxFormatError, ValueError, KeyError) as e:
            return self.misbehave(peer, "MALFORMED_OBJECT", f"tx: {e}")
        key = f"tx:{txid}"
        if self.inflight.pop(key, (None,))[0] != peer.id:
            self.misbehave(peer, "UNSOLICITED", f"tx {txid[:12]} was not requested from this peer")
        self.announcers.pop(key, None)
        self.log("recv_tx", peer.id, f"tx:{txid}")
        peer.know(txid)
        self.process_tx(tx, peer)

    async def _on_block(self, peer: Peer, p: dict) -> None:
        try:
            block = Block.from_dict(p["block"])
            h = block.hash
        except (ValueError, KeyError) as e:
            return self.misbehave(peer, "MALFORMED_OBJECT", f"block: {e}")
        key = f"block:{h}"
        if self.inflight.pop(key, (None,))[0] != peer.id:
            self.misbehave(peer, "UNSOLICITED", f"block {h[:12]} was not requested from this peer")
        self.announcers.pop(key, None)
        self.log("recv_block", peer.id, f"block:{h}")
        peer.know(h)
        self.process_block(block, peer)

    async def _on_getblocks(self, peer: Peer, p: dict) -> None:
        idx = {h: i for i, h in enumerate(self.chain.active)}
        start = next((idx[h] for h in p["locator"] if h in idx), 0)
        hashes = self.chain.active[start + 1:start + 1 + MAX_INV]
        if hashes:
            for h in hashes:
                peer.know(h)
            peer.send("inv", {"items": [{"type": "block", "id": h} for h in hashes]}, obj=f"{len(hashes)} blocks after height {start}")

    async def _on_ping(self, peer: Peer, p: dict) -> None:
        peer.send("pong", {"nonce": p["nonce"]})

    async def _on_pong(self, peer: Peer, p: dict) -> None:
        if p["nonce"] == peer.ping_nonce:
            peer.ping_nonce = None

    async def _on_reject(self, peer: Peer, p: dict) -> None:
        self.log("peer_rejected_us", peer.label, p.get("id"), code=p.get("code"), reason=str(p.get("reason"))[:200])

    # ------------------------------------------------------------------ objects
    def _have(self, kind: str, oid: str) -> bool:
        if kind == "tx":
            return oid in self.mempool or oid in self.seen_tx
        return oid in self.chain.entries or oid in self.chain.rejected or \
            any(b.hash == oid for lst in self.chain.orphans.values() for b, _ in lst)

    def _retry(self, key: str) -> None:
        kind, oid = key.split(":", 1)
        for pid in self.announcers.get(key, []):
            p = self.peers.get(pid)
            if p and p.ready and pid != self.inflight.get(key, (None,))[0]:
                self.inflight[key] = (pid, time.monotonic())
                p.send("getdata", {"items": [{"type": kind, "id": oid}]}, obj=key)
                self.log("request_retry", pid, key)
                return

    def relay(self, kind: str, oid: str, exclude: Peer | None = None) -> None:
        n = 0
        for p in list(self.peers.values()):
            if p is exclude or not p.ready or oid in p.known:
                continue
            p.know(oid)
            p.send("inv", {"items": [{"type": kind, "id": oid}]}, obj=f"{kind}:{oid}")
            n += 1
        self.log("relay", None, f"{kind}:{oid}", to=n)

    def process_tx(self, tx: Transaction, source: Peer | None) -> dict:
        txid = tx.txid
        self.seen_tx[txid] = None
        if len(self.seen_tx) > 50000:
            self.seen_tx.popitem(last=False)
        try:
            status, evicted = self.mempool.add(tx, self.chain.state)
        except Rejected as e:
            self.log("tx_rejected", source.id if source else None, f"tx:{txid}", code=e.code, reason=e.reason[:200])
            if source:
                if e.code in BAD_TX_CODES:
                    self.misbehave(source, "INVALID_TX", f"[{e.code}] {e.reason}")
                source.send("reject", {"message": "tx", "code": e.code, "reason": e.reason[:200], "id": txid})
            return {"txid": txid, "status": "REJECTED", "code": e.code, "reason": e.reason}
        self.log("tx_accepted", source.id if source else None, f"tx:{txid}", status=status, evicted=evicted,
                 feerate=round(self.mempool.entries[txid].feerate, 4))
        self.relay("tx", txid, exclude=source)
        return {"txid": txid, "status": status, "evicted": evicted}

    def process_block(self, block: Block, source: Peer | None) -> dict:
        old_tip = self.chain.tip.hash
        r = self.chain.submit(block, miner=source.id if source else self.id)
        todo, out = [r], []
        while todo:
            res = todo.pop(0)
            todo.extend(res.children)
            self.log(f"block_{res.status.lower()}", source.id if source else None, f"block:{res.hash}",
                     height=res.height, code=res.code, reason=(res.reason or "")[:200])
            out.append({"hash": res.hash, "status": res.status, "code": res.code, "height": res.height})
            if res.status in ("CONNECTED", "REORG", "SIDE_BRANCH"):
                self.relay("block", res.hash, exclude=source)
            if res.status == "REORG":
                self.log("reorg", None, f"block:{res.hash}", disconnected=res.disconnected, connected=res.connected,
                         back_to_mempool=res.resurrected, dropped_conflicting=res.conflicted)
            if res.status == "ORPHAN" and source:
                source.send("getblocks", {"locator": self.locator()})
            if res.status == "REJECTED" and source and res.code in BAD_BLOCK_CODES:
                self.misbehave(source, "INVALID_BLOCK", f"[{res.code}] {res.reason}")
        if self.chain.tip.hash != old_tip:
            self._tip_changed()
        return {"results": out, "tip": self.chain.tip.hash, "height": self.chain.height}

    def _tip_changed(self) -> None:
        gone, invalid = self.mempool.revalidate(self.chain.state)
        for t in gone + invalid:
            self.log("mempool_removed", None, f"tx:{t}", reason="confirmed or inputs spent" if t in gone else "invalid")
        stale = list(self.chain.mempool.values())          # txs of disconnected blocks still valid on the new tip
        self.chain.mempool.clear()
        for tx in stale:
            try:
                self.mempool.add(tx, self.chain.state)
                self.log("mempool_readd", None, f"tx:{tx.txid}", reason="from a block that was reorganised away")
                self.relay("tx", tx.txid)
            except Rejected as e:
                self.log("mempool_drop", None, f"tx:{tx.txid}", code=e.code)

    def locator(self) -> list[str]:
        a, out, step, i = self.chain.active, [], 1, len(self.chain.active) - 1
        while i > 0 and len(out) < 63:
            out.append(a[i])
            if len(out) >= 10:
                step *= 2
            i -= step
        out.append(a[0])
        return out

    # ------------------------------------------------------------------ maintenance
    async def _maintenance(self) -> None:
        while True:
            await asyncio.sleep(0.25)
            now_m, now = time.monotonic(), time.time()
            out = sum(1 for p in self.conns if p.outbound and not p.closed) + len(self.dialing)
            if out < self.max_outbound:
                connected = {p.id for p in self.conns if p.id and not p.closed}
                cands = [a for a, i in self.addrbook.items()
                         if a not in self.dialing and i != self.id and i not in connected
                         and (i is None or (i not in self.blocked and not self.is_banned(i)))]
                self.rng.shuffle(cands)
                for a in cands[: self.max_outbound - out]:
                    asyncio.create_task(self._dial(a))
            if now_m - getattr(self, "_last_getaddr", 0) > 10 and self.peers:
                self._last_getaddr = now_m                     # occasional refresh from a random peer
                ready = [p for p in self.peers.values() if p.ready]
                if ready:
                    self.rng.choice(ready).send("getaddr", {})
            for p in list(self.peers.values()):
                if not p.ready:
                    continue
                if p.ping_nonce is not None and now_m - p.ping_sent > PONG_TIMEOUT:
                    p.close("ping timeout")
                elif p.ping_nonce is None and now_m - p.last_ping > PING_INTERVAL:
                    p.ping_nonce, p.ping_sent, p.last_ping = self.rng.getrandbits(48), now_m, now_m
                    p.send("ping", {"nonce": p.ping_nonce})
            for key, (pid, t) in list(self.inflight.items()):
                if now_m - t > GETDATA_TIMEOUT:
                    del self.inflight[key]
                    self.log("request_timeout", pid, key)
                    self._retry(key)
            for t in self.mempool.expire():
                self.log("mempool_expired", None, f"tx:{t}")
            for i, until in list(self.banned.items()):
                if until <= now:
                    del self.banned[i]
                    self.log("unban", i)

    # ------------------------------------------------------------------ control port (JSON lines)
    async def _on_control(self, reader, writer) -> None:
        try:
            while line := await reader.readline():
                try:
                    req = json.loads(line)
                    resp = await self.control_cmd(req)
                except Exception as e:                    # report any error back to the caller
                    resp = {"error": f"{type(e).__name__}: {e}"}
                writer.write((json.dumps(resp) + "\n").encode())
                await writer.drain()
                if req.get("cmd") == "stop":
                    break
        finally:
            writer.close()

    async def control_cmd(self, req: dict) -> dict:
        cmd = req.get("cmd")
        if cmd == "status":
            return self.status()
        if cmd == "pay":
            names = {"alice": ALICE, "bob": BOB, "carol": CAROL, "dave": DAVE}
            kp = names[req["from"]] if "from" in req else KeyPair.from_scalar(req["from_scalar"])
            to = names[req["to"]] if "to" in req else KeyPair.from_scalar(req["to_scalar"])
            try:
                p = build_payment(self.chain.state, kp, to.pkh, req["amount"], req["fee"])
            except InsufficientFunds as e:
                return {"status": "REJECTED", "code": "INSUFFICIENT_FUNDS", "reason": str(e)}
            return self.process_tx(p.tx, None)
        if cmd == "submit_tx":
            return self.process_tx(Transaction.from_dict(req["tx"]), None)
        if cmd == "mine":
            miner = KeyPair.from_scalar(req.get("miner_scalar", 1))
            txs = self.mempool.select(req.get("max_txs", 500))
            m = self.chain.build_and_mine(miner.pkh, target_for_bits(req.get("bits", 12)), txs)
            self.log("mined", None, f"block:{m.block.hash}", attempts=m.attempts, txs=len(m.block.txs) - 1)
            res = self.process_block(m.block, None)
            return {"hash": m.block.hash, "attempts": m.attempts, "txs": [t.txid for t in m.block.txs], **res}
        if cmd == "get_block":
            return {"block": self.chain.blocks[self.chain.find(str(req["ref"]))].to_dict()}
        if cmd == "partition":
            self.blocked = set(req["block"])
            for pid in list(self.peers):
                if pid in self.blocked:
                    self.peers[pid].close("partition")
            self.log("partition", None, None, blocked=sorted(self.blocked))
            return {"blocked": sorted(self.blocked)}
        if cmd == "heal":
            self.log("heal", None, None, unblocked=sorted(self.blocked))
            self.blocked = set()
            return {"blocked": []}
        if cmd == "latency":
            self.latency_ms, self.jitter_ms = float(req["ms"]), float(req.get("jitter", 0))
            self.log("latency_set", None, None, ms=self.latency_ms, jitter=self.jitter_ms)
            return {"latency_ms": self.latency_ms, "jitter_ms": self.jitter_ms}
        if cmd == "stop":
            asyncio.get_running_loop().call_later(0.05, lambda: asyncio.ensure_future(self.stop()))
            return {"stopping": True}
        return {"error": f"unknown control command {cmd!r}"}

    def status(self) -> dict:
        st = self.chain.state
        names = {ALICE.pkh: "Alice", BOB.pkh: "Bob", CAROL.pkh: "Carol", DAVE.pkh: "Dave"}
        bal: dict[str, int] = {}
        for o in st.utxos.values():
            n = names.get(o.pkh, "miners")
            bal[n] = bal.get(n, 0) + o.value
        return {"id": self.id, "port": self.port, "height": self.chain.height, "tip": self.chain.tip.hash,
                "work": self.chain.tip.work, "utxo_hash": st.utxo_set_hash(), "mempool": sorted(self.mempool.entries),
                "peers": sorted(p.id for p in self.peers.values() if p.ready),
                "outbound": sorted(p.id for p in self.peers.values() if p.ready and p.outbound),
                "known_nodes": sorted({i for i in self.addrbook.values() if i}),
                "banned": sorted(i for i in self.banned if self.is_banned(i)), "blocked": sorted(self.blocked),
                "known_blocks": len(self.chain.entries), "balances": bal, "counts": dict(self.log.counts)}


async def run_node(**kw) -> None:
    node = Node(**kw)
    await node.start()
    print(f"READY {node.id} {node.port} {node.control_port}", flush=True)
    stop = asyncio.Event()
    orig = node.stop

    async def stop_and_signal():
        await orig()
        stop.set()
    node.stop = stop_and_signal
    await stop.wait()
