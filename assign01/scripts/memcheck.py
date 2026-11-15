"""Acceptance check: hashing a 100 MB file must not grow memory by ~100 MB.

Usage:  python scripts/memcheck.py [--size-mb 100] [--keep]

It writes a file of random bytes, then hashes a 1 KB file and the big file in
two fresh child processes running `hashlab file`. Each child reports
  * tracemalloc peak  - Python-level allocations (works on every OS)
  * ru_maxrss         - peak resident memory of the process (Linux/macOS)
The script also cross-checks the digest against hashlib on the whole file and,
when present, the independent `sha256sum`/`shasum` utility.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

CHILD = r"""
import io, json, sys, tracemalloc, contextlib
tracemalloc.start()
from hashlab.cli import main
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    rc = main(["file", sys.argv[1], "--json"])
_, peak = tracemalloc.get_traced_memory()
out = json.loads(buf.getvalue())
out["tracemalloc_peak_bytes"] = peak
try:
    import resource
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    out["max_rss_bytes"] = rss if sys.platform == "darwin" else rss * 1024
except ImportError:
    out["max_rss_bytes"] = None
print(json.dumps(out))
"""


def measure(path: str) -> dict:
    r = subprocess.run([sys.executable, "-c", CHILD, path], capture_output=True, text=True, check=True)
    return json.loads(r.stdout)


def external_sha256(path: str) -> str | None:
    for cmd in (["sha256sum", path], ["shasum", "-a", "256", path]):
        if shutil.which(cmd[0]):
            return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.split()[0]
    return None


def mb(n: int | None) -> str:
    return "n/a" if n is None else f"{n / 1024 / 1024:.1f} MB"


def run(size_mb: int = 100, keep: bool = False) -> dict:
    tmp = tempfile.mkdtemp(prefix="hashlab-mem-")
    small, big = os.path.join(tmp, "small.bin"), os.path.join(tmp, "big.bin")
    with open(small, "wb") as f:
        f.write(os.urandom(1024))
    ref = hashlib.sha256()
    with open(big, "wb") as f:
        for _ in range(size_mb):
            block = os.urandom(1024 * 1024)
            ref.update(block)
            f.write(block)
    try:
        base, large = measure(small), measure(big)
        result = {
            "file_bytes": large["bytes"],
            "digest": large["sha256"],
            "matches_hashlib": large["sha256"] == ref.hexdigest(),
            "external_tool_digest": external_sha256(big),
            "tracemalloc_peak_small": base["tracemalloc_peak_bytes"],
            "tracemalloc_peak_big": large["tracemalloc_peak_bytes"],
            "max_rss_small": base["max_rss_bytes"],
            "max_rss_big": large["max_rss_bytes"],
        }
        rss_growth = None if base["max_rss_bytes"] is None else large["max_rss_bytes"] - base["max_rss_bytes"]
        result["rss_growth"] = rss_growth
        result["passed"] = (
            result["matches_hashlib"]
            and (result["external_tool_digest"] in (None, large["sha256"]))
            and large["tracemalloc_peak_bytes"] < 16 * 1024 * 1024
            and (rss_growth is None or rss_growth < 16 * 1024 * 1024)
        )
        return result
    finally:
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            print(f"kept files in {tmp}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--size-mb", type=int, default=100)
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    r = run(a.size_mb, a.keep)
    print(f"hashed file           : {r['file_bytes']:,} bytes")
    print(f"sha256 (hashlab)      : {r['digest']}")
    print(f"sha256 (sha256sum)    : {r['external_tool_digest'] or 'tool not found'}")
    print(f"matches hashlib       : {r['matches_hashlib']}")
    print(f"python peak, 1 KB file: {mb(r['tracemalloc_peak_small'])}")
    print(f"python peak, big file : {mb(r['tracemalloc_peak_big'])}")
    print(f"max RSS, 1 KB file    : {mb(r['max_rss_small'])}")
    print(f"max RSS, big file     : {mb(r['max_rss_big'])}")
    print(f"RSS growth            : {mb(r['rss_growth'])}  (limit 16 MB; reading the whole file would be ~{a.size_mb} MB)")
    print("RESULT:", "PASS" if r["passed"] else "FAIL")
    return 0 if r["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
