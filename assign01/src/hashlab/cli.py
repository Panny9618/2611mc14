"""Command-line interface for hashlab.

Exit codes: 0 success, 1 file/IO error, 2 invalid input or usage.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import __version__
from .canonical import CanonicalJSONError, canonical_digest
from .core import CHUNK_SIZE, DIGEST_BITS, Digest, HexError, avalanche, digest_bytes, digest_chunks, digest_file, iter_stream, parse_hex, text_to_bytes
from .similar import cases


# --------------------------------------------------------------------------- output helpers

def _print_digest(d: Digest, as_json: bool, extra: dict | None = None) -> None:
    out = {**(extra or {}), **d.as_dict()}
    if as_json:
        print(json.dumps(out))
    else:
        for k, v in out.items():
            print(f"{k}: {v}")


def _fail(msg: str, code: int = 2) -> int:
    print(f"hashlab: error: {msg}", file=sys.stderr)
    return code


def _read_input_bytes(args: argparse.Namespace) -> bytes:
    """Bytes for commands that accept --text / --hex / --file."""
    if args.text is not None:
        return text_to_bytes(args.text)
    if args.hex is not None:
        return parse_hex(args.hex)
    if args.file == "-":
        return sys.stdin.buffer.read()
    with open(args.file, "rb") as f:
        return f.read()


# --------------------------------------------------------------------------- commands

def cmd_text(args: argparse.Namespace) -> int:
    _print_digest(digest_bytes(text_to_bytes(args.value)), args.json)
    return 0


def cmd_hex(args: argparse.Namespace) -> int:
    try:
        data = parse_hex(args.value)
    except HexError as e:
        return _fail(f"malformed hex: {e}")
    _print_digest(digest_bytes(data), args.json)
    return 0


def cmd_file(args: argparse.Namespace) -> int:
    try:
        if args.path == "-":
            d = digest_chunks(iter_stream(sys.stdin.buffer, args.chunk_size))
        else:
            d = digest_file(args.path, args.chunk_size)
    except OSError as e:
        return _fail(f"cannot read {args.path!r}: {e.strerror}", 1)
    _print_digest(d, args.json, {"file": args.path})
    return 0


def cmd_avalanche(args: argparse.Namespace) -> int:
    try:
        data = _read_input_bytes(args)
    except HexError as e:
        return _fail(f"malformed hex: {e}")
    except OSError as e:
        return _fail(f"cannot read {args.file!r}: {e.strerror}", 1)
    if not data:
        return _fail("input is empty; there is no bit to flip")

    if args.sweep:
        nbits = len(data) * 8
        dists = [avalanche(data, b).changed_bits for b in range(nbits)]
        stats = {
            "input_bits": nbits,
            "min_changed": min(dists),
            "max_changed": max(dists),
            "mean_changed": round(sum(dists) / nbits, 2),
            "mean_percent": round(100 * sum(dists) / nbits / DIGEST_BITS, 2),
        }
        if args.json:
            print(json.dumps(stats))
        else:
            print(f"flipped each of {nbits} input bits once")
            for k in ("min_changed", "max_changed", "mean_changed", "mean_percent"):
                print(f"{k}: {stats[k]}")
            print("ideal: about 128 of 256 digest bits (50%) change per flip")
        return 0

    try:
        r = avalanche(data, args.bit)
    except ValueError as e:
        return _fail(str(e))
    byte_i = args.bit // 8
    out = {
        "bit": args.bit,
        "byte_index": byte_i,
        "byte_before": f"0x{r.original_bytes[byte_i]:02x}",
        "byte_after": f"0x{r.flipped_bytes[byte_i]:02x}",
        "sha256_before": r.original.hex,
        "sha256_after": r.flipped.hex,
        "changed_bits_in_digest": r.changed_bits,
        "changed_percent": round(100 * r.changed_bits / DIGEST_BITS, 2),
    }
    if args.json:
        print(json.dumps(out))
    else:
        for k, v in out.items():
            print(f"{k}: {v}")
    return 0


def cmd_canonical(args: argparse.Namespace) -> int:
    try:
        if args.string is not None:
            raw = args.string.encode("utf-8")
        elif args.path == "-":
            raw = sys.stdin.buffer.read()
        else:
            with open(args.path, "rb") as f:
                raw = f.read()
    except OSError as e:
        return _fail(f"cannot read {args.path!r}: {e.strerror}", 1)
    try:
        canon, d = canonical_digest(raw)
    except CanonicalJSONError as e:
        return _fail(str(e))
    if args.output:
        with open(args.output, "wb") as f:
            f.write(canon)
    _print_digest(d, args.json, {"canonical": canon.decode("utf-8")})
    return 0


def cmd_similar(args: argparse.Namespace) -> int:
    rows = []
    for c in cases():
        rows.append({
            "case": c.title,
            "left": c.left_label, "left_bytes": len(c.left), "left_hex": c.left.hex(),
            "left_sha256": c.left_digest.hex,
            "right": c.right_label, "right_bytes": len(c.right), "right_hex": c.right.hex(),
            "right_sha256": c.right_digest.hex,
            "same_bytes": c.same, "lesson": c.lesson,
        })
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    for r in rows:
        print(r["case"])
        for side in ("left", "right"):
            hx = r[f"{side}_hex"]
            hx = hx if len(hx) <= 80 else hx[:77] + "..."
            print(f"  {r[side]:<28} {r[f'{side}_bytes']:>3} bytes  hex={hx}")
            print(f"  {'':<28} sha256={r[f'{side}_sha256']}")
        print(f"  => {'SAME hash' if r['same_bytes'] else 'DIFFERENT hash'}. {r['lesson']}\n")
    return 0


# --------------------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hashlab", description="SHA-256 diagnostics for bytes, files and canonical JSON.")
    p.add_argument("--version", action="version", version=f"hashlab {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_json(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--json", action="store_true", help="machine-readable JSON output")

    sp = sub.add_parser("text", help="hash a UTF-8 string exactly as given (no newline added)")
    sp.add_argument("value")
    add_json(sp)
    sp.set_defaults(func=cmd_text)

    sp = sub.add_parser("hex", help="hash a hexadecimal byte string, e.g. 0x616263")
    sp.add_argument("value")
    add_json(sp)
    sp.set_defaults(func=cmd_hex)

    sp = sub.add_parser("file", help="hash a file by streaming it in chunks ('-' = stdin)")
    sp.add_argument("path")
    sp.add_argument("--chunk-size", type=int, default=CHUNK_SIZE, help=argparse.SUPPRESS)
    add_json(sp)
    sp.set_defaults(func=cmd_file)

    sp = sub.add_parser("avalanche", help="flip one input bit and count changed digest bits")
    src = sp.add_mutually_exclusive_group(required=True)
    src.add_argument("--text")
    src.add_argument("--hex")
    src.add_argument("--file", help="path or '-' for stdin (read fully; intended for small inputs)")
    mode = sp.add_mutually_exclusive_group(required=True)
    mode.add_argument("--bit", type=int, help="bit index, MSB-first: bit i is in byte i//8")
    mode.add_argument("--sweep", action="store_true", help="flip every bit once and report statistics")
    add_json(sp)
    sp.set_defaults(func=cmd_avalanche)

    sp = sub.add_parser("canonical-json", help="canonicalise a JSON object and hash its UTF-8 bytes")
    src = sp.add_mutually_exclusive_group(required=True)
    src.add_argument("path", nargs="?", help="JSON file or '-' for stdin")
    src.add_argument("--string", help="JSON given directly on the command line")
    sp.add_argument("-o", "--output", help="also write the canonical bytes to this file")
    add_json(sp)
    sp.set_defaults(func=cmd_canonical)

    sp = sub.add_parser("similar", help="show look-alike inputs that hash differently")
    add_json(sp)
    sp.set_defaults(func=cmd_similar)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
