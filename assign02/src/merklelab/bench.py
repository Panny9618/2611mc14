"""Construction time and proof size measurements."""

from __future__ import annotations

import platform
import random
import sys
import time

from .proof import Proof, verify
from .tree import MerkleTree, expected_sides


def run_bench(sizes: list[int], proofs: int = 1000, seed: int = 2611) -> list[dict]:
    rng = random.Random(seed)
    rows = []
    for n in sizes:
        leaves = [f"tx-{i:08d}".encode() for i in range(n)]
        repeats = 5 if n <= 10_000 else 1
        best = float("inf")
        for _ in range(repeats):
            t0 = time.perf_counter()
            tree = MerkleTree(leaves)
            best = min(best, time.perf_counter() - t0)

        idx = [rng.randrange(n) for _ in range(min(proofs, max(n, 1)))]
        t0 = time.perf_counter()
        ps = [tree.prove(i) for i in idx]
        prove_t = (time.perf_counter() - t0) / len(ps)
        t0 = time.perf_counter()
        for i, p in zip(idx, ps):
            verify(leaves[i], p, tree.root)
        verify_t = (time.perf_counter() - t0) / len(ps)

        sib_counts = [len(expected_sides(i, n)) for i in range(n)] if n <= 200_000 else [len(p.siblings) for p in ps]
        json_sizes = [len(p.to_json(indent=None).encode()) for p in ps]
        rows.append({
            "leaves": n,
            "depth": tree.depth,
            "build_ms": best * 1000,
            "build_us_per_leaf": best * 1e6 / n,
            "min_siblings": min(sib_counts),
            "max_siblings": max(sib_counts),
            "proof_hash_bytes_max": 32 * max(sib_counts),
            "proof_json_bytes_avg": sum(json_sizes) / len(json_sizes),
            "prove_us": prove_t * 1e6,
            "verify_us": verify_t * 1e6,
        })
    return rows


def format_markdown(rows: list[dict]) -> str:
    head = ("| Leaves | Depth | Build time | per leaf | Siblings (min–max) | Proof hashes (max) "
            "| Proof JSON (avg) | Prove | Verify |\n"
            "|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    lines = [head]
    for r in rows:
        lines.append(
            f"| {r['leaves']:,} | {r['depth']} | {r['build_ms']:.2f} ms | {r['build_us_per_leaf']:.2f} µs "
            f"| {r['min_siblings']}–{r['max_siblings']} | {r['proof_hash_bytes_max']} B "
            f"| {r['proof_json_bytes_avg']:.0f} B | {r['prove_us']:.1f} µs | {r['verify_us']:.1f} µs |")
    env = f"Python {sys.version.split()[0]} on {platform.system()} {platform.machine()}"
    return "\n".join(lines) + f"\n\n_Measured with {env}._"
