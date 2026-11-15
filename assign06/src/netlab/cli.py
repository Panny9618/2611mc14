"""p2p: command-line interface.

    p2p experiment --out examples/experiment     # 5 node processes, full scenario (default)
    p2p experiment --inproc                      # same scenario, 5 nodes in one process
    p2p node --id n1 [--port 0] [--control-port 0] [--seed 127.0.0.1:PORT] [--log-dir logs]
    p2p ctl --port CONTROL_PORT status|mine|pay|partition|heal|latency ...
    p2p logs logs/combined.jsonl [--node n1] [--event reorg] [--object <prefix>]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Sequence

from . import __version__


def cmd_experiment(a) -> int:
    from .experiment import run
    ok = asyncio.run(run(a.out, inproc=a.inproc))
    return 0 if ok else 1


def cmd_node(a) -> int:
    from .node import run_node
    seeds = []
    for s in a.seed or []:
        h, _, p = s.rpartition(":")
        seeds.append((h, int(p)))
    try:
        asyncio.run(run_node(node_id=a.id, port=a.port, control_port=a.control_port, seeds=seeds,
                             log_dir=a.log_dir, max_outbound=a.max_outbound))
    except KeyboardInterrupt:
        pass
    return 0


def cmd_ctl(a) -> int:
    from .experiment import Ctl
    kw = {}
    for kv in a.args:
        k, _, v = kv.partition("=")
        try:
            kw[k] = json.loads(v)
        except json.JSONDecodeError:
            kw[k] = v
    try:
        resp = asyncio.run(Ctl("node", 0, a.port)(a.command, **kw))
    except OSError:
        print(f"p2p: error: no node is listening on control port {a.port}", file=sys.stderr)
        return 2
    except RuntimeError as e:
        print(f"p2p: error: {e}", file=sys.stderr)
        return 2
    print(json.dumps(resp, indent=2))
    return 0


def cmd_logs(a) -> int:
    with open(a.file, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if a.node and r["node"] != a.node or a.event and a.event not in r["event"] \
                    or a.object and not (r.get("object") or "").split(":")[-1].startswith(a.object):
                continue
            extra = {k: v for k, v in r.items() if k not in ("ts", "time", "node", "peer", "object", "event")}
            print(f"{r['time']}  {r['node']:<3} {str(r['peer'] or '-'):<9} {r['event']:<18} "
                  f"{(r['object'] or '')[:30]:<30} {json.dumps(extra) if extra else ''}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="p2p", description="Peer-to-peer mempool and block relay network.")
    p.add_argument("--version", action="version", version=f"p2p {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("experiment", help="run the 5-node partition experiment")
    sp.add_argument("--out", default="examples/experiment")
    sp.add_argument("--inproc", action="store_true", help="run all nodes in one process (still real TCP)")
    sp.set_defaults(func=cmd_experiment)

    sp = sub.add_parser("node", help="run one node until stopped")
    sp.add_argument("--id", required=True); sp.add_argument("--port", type=int, default=0)
    sp.add_argument("--control-port", type=int, default=0); sp.add_argument("--seed", action="append")
    sp.add_argument("--log-dir"); sp.add_argument("--max-outbound", type=int, default=2)
    sp.set_defaults(func=cmd_node)

    sp = sub.add_parser("ctl", help="send a control command to a running node")
    sp.add_argument("--port", type=int, required=True, help="the node's control port")
    sp.add_argument("command"); sp.add_argument("args", nargs="*", help="key=value (JSON values)")
    sp.set_defaults(func=cmd_ctl)

    sp = sub.add_parser("logs", help="filter a JSONL log")
    sp.add_argument("file"); sp.add_argument("--node"); sp.add_argument("--event"); sp.add_argument("--object")
    sp.set_defaults(func=cmd_logs)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        return a.func(a)
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
