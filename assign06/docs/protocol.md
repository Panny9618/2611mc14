# Assignment 6 — Network Protocol Specification (version 1)

**Roll:** 2611MC03

## 1. Transport and framing

TCP on localhost. Every message is one frame. Integers are big-endian.

| Offset | Size | Field | Rule |
|---:|---:|---|---|
| 0 | 4 | magic | `TOY6`. Anything else → close the connection (`BAD_MAGIC`, +100) |
| 4 | 12 | command | ASCII, NUL-padded |
| 16 | 4 | length | payload size; **> 1 MiB → close before reading the payload** (`OVERSIZE`, +100) |
| 20 | 4 | checksum | `SHA256(SHA256(payload))[0:4]`; mismatch → drop that message (`BAD_CHECKSUM`, +25) |
| 24 | n | payload | UTF-8 JSON object, checked against the command's schema (`BAD_JSON` / `BAD_SCHEMA`, +25) |

The length prefix keeps the stream aligned, so a bad checksum, bad JSON or a schema error affects only
that one message. A bad magic or an oversized length means the stream can no longer be trusted, so the
connection is closed.

## 2. Messages

| Command | Payload | Purpose |
|---|---|---|
| `version` | `version, node_id, listen_port, height, tip, agent` | handshake: protocol version 1 and identity |
| `verack` | `{}` | handshake acknowledgement |
| `getaddr` | `{}` | peer discovery request |
| `addr` | `peers: [{node_id, host, port}]` (≤ 100) | known peers; new addresses are forwarded once (gossip) |
| `inv` | `items: [{type: "tx"\|"block", id}]` (1–500) | **announce** objects by id only |
| `getdata` | same as `inv` | request full objects that were announced |
| `notfound` | same as `inv` | requested object is not available |
| `tx` | `tx: {...}` | full transaction (Assignment 4 format) |
| `block` | `block: {...}` | full block (Assignment 5 format) |
| `getblocks` | `locator: [hash…]` (≤ 64) | "send me the blocks after the first of these you know" |
| `ping` / `pong` | `nonce` | liveness |
| `reject` | `message, code, reason, id` | **error response**: why a message or object was refused |

### Handshake

```
A (dials)                         B (accepts)
  ── version ──────────────────▶
  ◀────────────────── version ──
  ◀─────────────────── verack ──
  ── verack ───────────────────▶
  ── getaddr, getblocks(locator), inv(mempool) ──▶   (both directions)
```

Rules:
- Only `version` and `verack` are allowed before the handshake completes. Anything else scores +10 and
  is ignored.
- The handshake must finish within **5 s**.
- A different protocol version gets `reject OBSOLETE` and the connection is closed.
- A connection to yourself is closed.
- A banned or partition-blocked node id is refused.
- If two connections reach the same peer, both sides keep the one dialled by the smaller node id, so
  they always agree on which to keep.

### Relay (inventory first)

```
node X has a new tx/block ── inv(id) ──▶ peer Y
                          ◀── getdata(id) ── Y doesn't have it and hasn't asked anyone yet
                          ── tx/block ─────▶ Y validates; if accepted, Y announces inv to its other peers
```

- Each peer connection remembers the ids already exchanged, so an id is never announced twice to the
  same peer.
- A node requests each id from only one peer at a time. If there is no answer within **3 s**, it asks
  another peer that announced the same id.
- A `tx` or `block` that was not requested costs the sender +5.

### Catch-up

After the handshake, and whenever a block's parent is unknown (an orphan), a node sends `getblocks`
with a **block locator**: its last 10 active hashes, then exponentially sparser ones back to genesis.
The peer finds the first locator hash on its own active chain and announces (`inv`) up to 500 blocks
after it. This is how the two sides of a healed partition exchange their branches.

## 3. Local policy and defences

| Mechanism | Setting |
|---|---|
| Rate limiting | token bucket per peer: 100 messages/s, burst 200. Excess messages are dropped, +2 each |
| Timeouts | handshake 5 s · idle connection 30 s · ping every 5 s, no pong in 10 s → disconnect · getdata 3 s → retry elsewhere |
| Misbehaviour score | bad magic / oversize +100 · bad checksum, JSON, schema or command +25 · malformed tx/block +25 · invalid tx (bad signature, value creation, …) +20 · **invalid block +100** · unknown command +5 · unsolicited object +5 · message before handshake +10 |
| Ban | score ≥ 100 → `reject BANNED`, disconnect, refuse that node id for 60 s |
| Not penalised | late or conflicting txs (`DUPLICATE`, `CONFLICT`, `MISSING_INPUT`, `DOUBLE_SPEND`), because these happen naturally on a network |
| Outbound peers | each node dials up to 2 peers from its address book (seeded only with n1) and accepts inbound connections |

## 4. Mempool

| Rule | Behaviour |
|---|---|
| Validation | every tx is checked against the tip's UTXO set with the Assignment 4 rules |
| Duplicate suppression | a known txid is not re-processed or re-relayed |
| Fee-rate ordering | fee-rate = fee ÷ (body bytes + 97 per signature); miners take the highest first (ties by txid) |
| Conflict handling | a tx spending an outpoint already used in the pool is refused (`CONFLICT`), unless its fee-rate is at least **1.25×** every conflicting tx's (replace-by-fee) |
| Expiry | dropped after 600 s |
| Capacity | 5,000 txs; when full, the lowest fee-rate tx is evicted (or the newcomer refused) |
| New tip | confirmed txs, and txs whose inputs are now spent, are removed |
| Reorganisation | txs from disconnected blocks that are still valid are **re-added and re-announced**; conflicting ones are dropped |

Simplification: a mempool tx may spend only confirmed outputs (no chains of unconfirmed txs).

## 5. Structured logs

One JSON object per line in `logs/<node>.jsonl`, plus a time-sorted `logs/combined.jsonl`:

```json
{"ts": 1762800540.063, "time": "19:49:00.063", "node": "n1", "peer": "n4",
 "object": "block:000003a5…", "event": "block_reorg", "height": 3, "code": null}
```

Events include:
- **connections:** `listen`, `connect_out`, `accept_in`, `handshake_done`, `disconnect` (reason),
  `addr_learned`
- **relay:** `send_*` / `recv_*`, `relay`, `request_timeout`, `request_retry`
- **transactions and blocks:** `tx_accepted` / `tx_rejected`, `block_connected` / `block_reorg` /
  `block_side_branch` / `block_orphan` / `block_rejected`, `reorg`, `mined`
- **mempool:** `mempool_readd`, `mempool_drop`, `mempool_removed`, `mempool_expired`
- **defences:** `misbehaviour` (code, points, score), `ban`, `unban`
- **experiment controls:** `partition`, `heal`, `latency_set`

Filter them with `p2p logs logs/combined.jsonl --node n1 --event reorg --object <id prefix>`.
