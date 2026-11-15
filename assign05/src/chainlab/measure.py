"""Hash rate and expected vs observed attempts at several toy targets.

For target t the probability a single hash is <= t is (t+1)/2^256, so the
number of attempts is geometric with mean 2^256/(t+1) (= 2^bits for our
targets) and standard deviation about the same as the mean. The mean of n
blocks therefore has a standard error of roughly mean/sqrt(n).
"""

from __future__ import annotations

import math
import platform
import sys

from .block import mine, target_for_bits
from .chain import make_coinbase
from .tx import TxOut


def run(plan: list[tuple[int, int]], say=print) -> list[dict]:
    rows = []
    for bits, n in plan:
        target = target_for_bits(bits)
        expected = (1 << 256) / (target + 1)
        attempts, secs = [], 0.0
        prev = bytes(32)
        for i in range(n):
            cb = make_coinbase(i + 1, [TxOut(50, bytes(20))])
            r = mine(prev, [cb], target, 1_767_225_600 + i)
            attempts.append(r.attempts)
            secs += r.seconds
            prev = r.block.header.hash
        mean = sum(attempts) / n
        sd = math.sqrt(sum((a - mean) ** 2 for a in attempts) / (n - 1)) if n > 1 else float("nan")
        row = {"bits": bits, "target": f"{target:064x}", "blocks": n, "expected": expected, "observed_mean": mean,
               "ratio": mean / expected, "stderr_pct": 100 / math.sqrt(n), "observed_sd": sd,
               "min": min(attempts), "max": max(attempts), "hashes": sum(attempts), "seconds": secs,
               "hashrate": sum(attempts) / secs}
        rows.append(row)
        say(f"  {bits} bits: {n} blocks, expected {expected:,.0f}, observed mean {mean:,.0f} "
            f"(ratio {mean / expected:.2f}, ±{100 / math.sqrt(n):.0f}% expected noise), {row['hashrate']:,.0f} H/s")
    return rows


def markdown(rows: list[dict]) -> str:
    out = ["| Target | Leading zero bits | Blocks | Expected attempts | Observed mean | Observed / expected | Expected noise (1 s.e.) | Min – max | Hash rate |",
           "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in rows:
        out.append(f"| `{r['target'][:12]}…` | {r['bits']} | {r['blocks']} | {r['expected']:,.0f} | {r['observed_mean']:,.0f} | "
                   f"{r['ratio']:.2f} | ±{r['stderr_pct']:.0f}% | {r['min']:,} – {r['max']:,} | {r['hashrate']:,.0f} H/s |")
    total_h = sum(r["hashes"] for r in rows)
    total_s = sum(r["seconds"] for r in rows)
    out.append(f"\nOverall: {total_h:,} hashes in {total_s:.1f} s = **{total_h / total_s:,.0f} hashes/s** "
               f"(single Python thread, double SHA-256 of a 116-byte header, Python {sys.version.split()[0]} on {platform.machine()}).")
    return "\n".join(out)
