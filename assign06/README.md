# Assignment 6 — A Peer-to-Peer Mempool and Block Relay Network (`p2p`)

**Roll:** 2611MC03 · **Stack:** Python 3.11+ asyncio (localhost TCP) · `cryptography` · pytest

Five instances of the Assignment 5 node, each a **separate OS process**, connect over localhost TCP.
They discover each other, relay transactions and blocks (inventory first), & keep working when peers
send malformed, oversized or repeated input. They also survive latency and a network partition, and
converge again afterwards. Wire format and policy: **`docs/protocol.md`**.

## 1. Setup and run

```bash
cd assign06
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[test]"
pytest -q                            # 33 tests, ~10 s (includes the full experiment twice)
p2p experiment --out examples/experiment     # 5 processes, the whole scenario, ~3 s
```

`p2p experiment` writes `examples/experiment/summary.md` (every check, timings, message counts) and
`examples/experiment/logs/*.jsonl`. Add `--inproc` to run all five nodes in one process; they still use
real TCP.

### Running nodes by hand (5 terminals, or background jobs)

```bash
p2p node --id n1 --port 9001 --control-port 9101 --log-dir logs &
p2p node --id n2 --port 9002 --control-port 9102 --seed 127.0.0.1:9001 --log-dir logs &
p2p node --id n3 --port 9003 --control-port 9103 --seed 127.0.0.1:9001 --log-dir logs &
p2p node --id n4 --port 9004 --control-port 9104 --seed 127.0.0.1:9001 --log-dir logs &
p2p node --id n5 --port 9005 --control-port 9105 --seed 127.0.0.1:9001 --log-dir logs &

p2p ctl --port 9103 status                               # peers, tip, mempool, bans, counters
p2p ctl --port 9102 pay from=alice to=bob amount=25 fee=1
p2p ctl --port 9104 mine bits=12
p2p ctl --port 9101 partition 'block=["n3","n4","n5"]'   # cut links;  heal = p2p ctl --port 9101 heal
p2p ctl --port 9101 latency ms=50 jitter=20
p2p logs logs/n1.jsonl --event block
for i in 1 2 3 4 5; do p2p ctl --port 910$i stop; done
```

The control port is a local JSON-lines interface used to drive experiments. It is separate from the
P2P port. Genesis gives the fixed test-only keys Alice 40 + 70, Bob 50 and Carol 30.

## 2. Tasks → implementation

| Task | Implementation |
|---|---|
| 1. Versioned messages: handshake, discovery, inventory, request, tx, block, ping, error | `version`/`verack`, `getaddr`/`addr`, `inv`, `getdata`/`notfound`, `tx`, `block`, `getblocks`, `ping`/`pong`, `reject` — `src/netlab/protocol.py` |
| 2. Length-prefix framing with a maximum size | 24-byte header (magic, command, length, checksum); 1 MiB limit checked **before** reading the payload |
| 3. Mempool: validation, duplicate suppression, fee-rate ordering, expiry, conflicts | `src/netlab/mempool.py` (replace-by-fee at 1.25×, expiry 600 s, capacity eviction) |
| 4. Inventory before full objects | `inv` → `getdata` → `tx`/`block`; per-peer known-inventory sets; one in-flight request per object, retried after 3 s |
| 5. Rate limiting, timeouts, malformed-message handling, peer scoring | token bucket 100/s; handshake, idle, ping and getdata timeouts; misbehaviour points with a ban at 100 — `src/netlab/node.py` |
| 6. Latency, temporary partition, reconnection, convergence | `latency` and `partition`/`heal` controls; the address book redials automatically; `getblocks` locator sync |
| 7. Structured logs: node ID, peer ID, object ID, event, timestamp | JSONL per node + `combined.jsonl`; `p2p logs` filter |

## 3. The experiment (from the assignment)

```
Phase 1  discovery     n2–n5 know only n1; getaddr/addr + gossip teach every node all 4 others
Phase 2  tx relay      Alice→Bob injected at n2 reaches all 5 mempools; each node downloads it once
Phase 3  block relay   n5 mines; all 5 tips agree, mempools empty
Phase 4  bad peer      garbage, a 50 MB length prefix, bad checksum / JSON / schema / unknown command,
                       a 1000-ping flood, an invalid block → n3 bans mallory1-3 and keeps its honest peers
Phase 5  partition     {n1,n2} | {n3,n4,n5} with 25±15 ms latency.
                       Side A: Alice→Dave 30 and Bob→Carol 20 mined in one block (height 2).
                       Side B: a conflicting Bob→Dave 45, one block, then an additional block (height 3).
Phase 6  heal          all 5 converge on side B's chain (more work); same tip and UTXO-set hash everywhere.
                       Alice→Dave (still valid) returns to every mempool; Bob→Carol (conflict) is dropped.
Phase 7  confirm       n2 mines the reconsidered tx; all 5 agree, mempools empty.
```

Results from the committed run (`examples/experiment/summary.md`): all 16 checks pass. Discovery took
0.53 s, tx propagation 0.16 s, block propagation 0.21 s, and convergence after healing 0.37 s. Times vary
slightly from run to run.

## 4. Layout

```
assign06/
├── readme.md · pyproject.toml · requirements.txt · DEMO_SCRIPT.md · .gitignore
├── src/netlab/  protocol.py · mempool.py · node.py · experiment.py · cli.py
│                chain.py · block.py · state.py · tx.py · wallet.py · crypto.py · base58.py  (Assignment 5)
├── tests/       test_protocol_mempool.py · test_network.py
├── docs/        protocol.md
└── examples/experiment/  summary.md · logs/n1..n5.jsonl · logs/combined.jsonl
```
