"""merkle: command-line interface.

Exit codes: 0 ok / proof valid, 1 proof does not verify (root mismatch),
2 malformed input (bad file, bad hex, malformed proof).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Sequence

from . import __version__
from .proof import Proof, ProofError, verify
from .tree import MerkleTree

_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2})*")


class InputError(ValueError):
    pass


# --------------------------------------------------------------------------- input

def parse_hex(s: str, what: str) -> bytes:
    body = s[2:] if s[:2] in ("0x", "0X") else s
    if not _HEX_RE.fullmatch(body):
        raise InputError(f"{what}: malformed hex {s!r}")
    return bytes.fromhex(body)


def read_leaves(path: str, hex_mode: bool) -> list[bytes]:
    """One leaf per line.

    * File is UTF-8; lines are split on LF ('\\n'); one final LF is optional.
    * CR ('\\r') is rejected so Windows line endings can't silently change leaves.
    * Text mode: each leaf is the UTF-8 bytes of the line (no newline).
    * --hex mode: each line is hex (optional 0x) and is decoded to bytes.
    * A blank line in the middle is a valid empty leaf.
    """
    try:
        raw = sys.stdin.buffer.read() if path == "-" else open(path, "rb").read()
    except OSError as e:
        raise InputError(f"cannot read {path!r}: {e.strerror}") from None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise InputError(f"{path}: not valid UTF-8") from None
    if "\r" in text:
        raise InputError(f"{path}: contains CR characters (Windows line endings); convert to LF")
    if text == "":
        return []
    lines = text.split("\n")
    if text.endswith("\n"):
        lines.pop()
    if not hex_mode:
        return [ln.encode("utf-8") for ln in lines]
    return [parse_hex(ln, f"{path} line {n + 1}") for n, ln in enumerate(lines)]


def fail(msg: str, code: int = 2) -> int:
    print(f"merkle: error: {msg}", file=sys.stderr)
    return code


# --------------------------------------------------------------------------- commands

def cmd_root(a) -> int:
    t = MerkleTree(read_leaves(a.leaves, a.hex))
    out = {"tree_size": t.size, "depth": t.depth, "root": t.root.hex()}
    if a.json:
        print(json.dumps(out))
    else:
        for k, v in out.items():
            print(f"{k}: {v}")
    return 0


def cmd_prove(a) -> int:
    t = MerkleTree(read_leaves(a.leaves, a.hex))
    try:
        p = t.prove(a.index)
    except ValueError as e:
        return fail(str(e))
    text = p.to_json()
    if a.output:
        with open(a.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(text + "\n")
        print(f"wrote proof for leaf {a.index} of {t.size} ({len(p.siblings)} siblings) to {a.output}", file=sys.stderr)
        print(f"root: {t.root.hex()}", file=sys.stderr)
    else:
        print(text)
    return 0


def cmd_verify(a) -> int:
    leaf = a.leaf.encode("utf-8") if a.leaf is not None else parse_hex(a.leaf_hex, "--leaf-hex")
    root = parse_hex(a.root, "--root")
    if len(root) != 32:
        raise InputError("--root must be 32 bytes (64 hex characters)")
    try:
        raw = sys.stdin.buffer.read() if a.proof == "-" else open(a.proof, "rb").read()
    except OSError as e:
        raise InputError(f"cannot read {a.proof!r}: {e.strerror}") from None
    try:
        p = Proof.from_json(raw)
        verify(leaf, p, root)
    except ProofError as e:
        print(f"INVALID: {e}")
        return 1 if e.kind == "invalid" else 2
    print(f"VALID: leaf {p.leaf_index} of {p.tree_size} is included under root {root.hex()}")
    return 0


def cmd_tree(a) -> int:
    leaves = read_leaves(a.leaves, a.hex)
    t = MerkleTree(leaves)
    if t.size == 0:
        print(f"empty tree, root = SHA-256(\"\") = {t.root.hex()}")
        return 0
    if a.index is not None and not 0 <= a.index < t.size:
        return fail(f"--index {a.index} out of range for {t.size} leaves")
    path, sib = set(), {}
    if a.index is not None:
        path = set(t.path_positions(a.index))
        i = a.index
        for lvl, level in enumerate(t.levels[:-1]):
            if i % 2 == 1:
                sib[(lvl, i - 1)] = f"SIBLING {len(sib) + 1} (left)"
            elif i + 1 < len(level):
                sib[(lvl, i + 1)] = f"SIBLING {len(sib) + 1} (right)"
            i //= 2
    w = a.width
    for lvl in range(len(t.levels) - 1, -1, -1):
        level = t.levels[lvl]
        name = "root" if lvl == len(t.levels) - 1 else ("leaves" if lvl == 0 else f"level {lvl}")
        print(f"{name} ({len(level)} node{'s' if len(level) != 1 else ''})")
        for pos, h in enumerate(level):
            promoted = lvl > 0 and pos == len(level) - 1 and len(t.levels[lvl - 1]) % 2 == 1
            note = []
            if (lvl, pos) in path:
                note.append("<== target leaf" if lvl == 0 else "<== on path")
            if (lvl, pos) in sib:
                note.append(sib[(lvl, pos)])
            if promoted:
                note.append("(promoted, unpaired)")
            label = f'  "{leaves[pos].decode("utf-8", "replace")}"' if lvl == 0 and not a.hex else ""
            print(f"  [{pos}] {h.hex()[:w]}{label}  {' '.join(note)}".rstrip())
    return 0


def cmd_bench(a) -> int:
    from .bench import format_markdown, run_bench
    sizes = [int(x) for x in a.sizes.split(",")]
    rows = run_bench(sizes, a.proofs)
    print(format_markdown(rows))
    return 0


# --------------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="merkle", description="Merkle tree root / inclusion proof / verification.")
    p.add_argument("--version", action="version", version=f"merkle {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def leaves_args(sp):
        sp.add_argument("leaves", help="file with one leaf per line ('-' = stdin)")
        sp.add_argument("--hex", action="store_true", help="each line is hex-encoded bytes")

    sp = sub.add_parser("root", help="compute the Merkle root")
    leaves_args(sp)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_root)

    sp = sub.add_parser("prove", help="produce an inclusion proof (JSON)")
    leaves_args(sp)
    sp.add_argument("--index", type=int, required=True, help="0-based leaf index")
    sp.add_argument("-o", "--output", help="write proof to this file instead of stdout")
    sp.set_defaults(func=cmd_prove)

    sp = sub.add_parser("verify", help="verify a proof using only leaf, proof and root")
    g = sp.add_mutually_exclusive_group(required=True)
    g.add_argument("--leaf", help="leaf as text (UTF-8)")
    g.add_argument("--leaf-hex", help="leaf as hex bytes")
    sp.add_argument("--proof", required=True, help="proof JSON file ('-' = stdin)")
    sp.add_argument("--root", required=True, help="expected root, 64 hex characters")
    sp.set_defaults(func=cmd_verify)

    sp = sub.add_parser("tree", help="print every level; with --index, mark the proof path")
    leaves_args(sp)
    sp.add_argument("--index", type=int)
    sp.add_argument("--width", type=int, default=16, help="hex characters shown per hash")
    sp.set_defaults(func=cmd_tree)

    sp = sub.add_parser("bench", help="timing and proof-size report")
    sp.add_argument("--sizes", default="8,1024,100000")
    sp.add_argument("--proofs", type=int, default=1000, help="proofs sampled per size")
    sp.set_defaults(func=cmd_bench)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        return a.func(a)
    except InputError as e:
        return fail(str(e))


if __name__ == "__main__":
    sys.exit(main())
