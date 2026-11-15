# Assignment 1 — Bytes, Hashes, and Reproducible Data (`hashlab`)

**Roll:** 2611MC03 · **Stack:** Python 3.11+ (standard library only) · **Tests:** pytest

`hashlab` is a command-line tool that turns text, hex or a file into bytes and prints SHA-256 diagnostics.
SHA-256 itself is **not** re-implemented: it comes from Python's `hashlib` (OpenSSL). The work here is
deciding exactly which bytes get hashed, and showing why that matters for a blockchain

## 1. Setup

```bash
cd assign01
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[test]"             # installs the `hashlab` command + pytest
```

No third-party runtime dependencies. `requirements.txt` lists only `pytest`.
Without installing, you can also run `PYTHONPATH=src python -m hashlab ...`.

## 2. Commands

| Command | What it does |
|---|---|
| `hashlab text "Alice pays Bob 10"` | Hash the UTF-8 bytes of the string, exactly as typed (no newline added) |
| `hashlab hex 0x416c696365` | Hash raw bytes given in hexadecimal |
| `hashlab file path/to/file` | Hash a file by streaming it in 1 MiB chunks (`-` = stdin) |
| `hashlab avalanche --text "..." --bit 7` | Flip one input bit, print both digests and the Hamming distance |
| `hashlab avalanche --text "..." --sweep` | Flip every input bit once; print min/mean/max changed digest bits |
| `hashlab canonical-json tx.json` | Canonicalise a JSON object, print it, hash its UTF-8 bytes (`-o out.json` saves it) |
| `hashlab similar` | Show look-alike inputs (newline, CRLF, Unicode, int vs string, key order) and their hashes |

Every command accepts `--json` for machine-readable output. Exit codes: `0` ok, `1` file error, `2` invalid input.

Every hash command prints:

```
bytes: 17
sha256: 69ad18dfd1ac4b3d711b02ee62caa00a82f0f67cc11ebacdd0c0ede0d8b6eaed
sha256_base64: aa0Y39GsSz1xGwLuYsqgCoLw9nzBHrrN0MDt4Ni26u0=
```

> Note: the assignment sheet shows `bytes: 18` for `"Alice pays Bob 10"`. The string is 17 characters;
> 18 is what you get from `echo "Alice pays Bob 10" | ...`, because `echo` appends a newline (0x0A).
> `hashlab text` hashes exactly what was typed, so it reports 17. `hashlab text $'Alice pays Bob 10\n'` reports 18.

## 3. Design decisions

### Hex input rules
* Optional `0x`/`0X` prefix; then only `0-9 a-f A-F`.
* Even number of digits (whole bytes). Empty string = zero bytes.
* Rejected (exit 2): odd length, spaces, `:` separators, non-hex letters, full-width digits, a second `0x`.

### Bit numbering for `avalanche`
Bit `i` is in byte `i // 8`; inside a byte, bit 0 is the **most significant** bit (MSB-first, the way a byte is
written in binary). Example: `--bit 7` on `"Alice..."` changes `A` (0x41 = `01000001`) into `@` (0x40).
Ideal behaviour: about 128 of 256 digest bits (50%) change. `--sweep` shows the mean is ≈128.

### Canonical JSON rules
| Rule | Decision |
|---|---|
| R1 | Input must be valid UTF-8, no byte-order mark |
| R2 | Top-level value must be an object |
| R3 | Duplicate keys rejected (otherwise `{"amount":10,"amount":1000}` is ambiguous) |
| R4 | Integers only. `1.5`, `1.0`, `1e3`, `NaN`, `Infinity` rejected — use smallest integer units. `-0` → `0` |
| R5 | Keys sorted by Unicode code point, recursively |
| R6 | Array order preserved |
| R7 | No whitespace: separators `,` and `:`; no trailing newline |
| R8 | Output is UTF-8; non-ASCII not `\u`-escaped; only `"`, `\` and U+0000–U+001F escaped |
| R9 | No Unicode normalisation (NFC and NFD stay different); lone surrogates rejected |
| R10 | `true`, `false`, `null` lowercase |

Rejecting rather than "fixing" ambiguous input is deliberate: a signer and a verifier must never disagree
about what bytes were signed.

### Streaming
`hashlab file` reads 1 MiB at a time and feeds `hashlib.sha256().update()`, so memory stays constant.

## 4. Tests and acceptance checks

```bash
pytest -q                      # 74 tests (includes the 100 MB memory test)
pytest -q -m "not slow"        # skip the 100 MB test
python scripts/memcheck.py     # readable 100 MB memory report
```

| Acceptance check | How it is shown |
|---|---|
| Matches an independent SHA-256 utility | `test_matches_independent_utility` compares with `sha256sum`/`shasum`; NIST vectors (`""`, `abc`, 448-bit, one million `a`) |
| Rejects malformed hex | `test_hex_malformed_rejected` (10 cases), CLI exit code 2 |
| Distinguishes a trailing newline | `test_text_is_utf8_exact_and_newline_matters`, `hashlab similar` case 1 |
| 100 MB file without ~100 MB memory growth | `scripts/memcheck.py`: measured RSS growth ≈ 2 MB, Python peak ≈ 5 MB |

Sample `memcheck.py` output:

```
hashed file           : 104,857,600 bytes
sha256 (hashlab)      : 12de7fe3...f145746
sha256 (sha256sum)    : 12de7fe3...f145746
max RSS, 1 KB file    : 21.3 MB
max RSS, big file     : 23.3 MB
RSS growth            : 2.1 MB  (limit 16 MB; reading the whole file would be ~100 MB)
RESULT: PASS
```

## 5. Layout

```
assign01/
├── readme.md            this file
├── pyproject.toml       package + `hashlab` entry point
├── requirements.txt
├── DEMO_SCRIPT.md       what to say and type in the video
├── src/hashlab/         core.py (bytes, hashing, avalanche) · canonical.py · similar.py · cli.py
├── tests/               test_core.py · test_canonical.py · test_cli.py
├── scripts/memcheck.py  100 MB memory acceptance check
└── examples/            JSON and text files used in the demo
```
