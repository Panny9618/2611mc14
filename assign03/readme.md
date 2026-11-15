# Assignment 3 — Keys, Addresses, and Signed Transactions (`wallet`)

**Roll:** 2611MC03 · **Stack:** Python 3.11+ · `cryptography` (OpenSSL) · pytest

An educational wallet for a toy chain. It generates secp256k1 keys from OS randomness, derives
Base58Check addresses, builds a canonical binary transaction, signs it with ECDSA (low-S), and verifies
it independently. **No elliptic-curve arithmetic or random-number generation is implemented here:**
ECDSA comes from the maintained `cryptography` library, and the randomness comes from the OS.

## 1. Setup

```bash
cd assign03
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[test]"             # installs `wallet`, cryptography and pytest
pytest -q                            # 136 tests
```

## 2. Commands

| Command | Purpose |
|---|---|
| `wallet keygen --name alice` | New key pair → `keys/alice.pub.json` (public) and `keys/alice.key.json` (private, mode 0600, TEST-ONLY warning). Prints only public data |
| `wallet address --pub keys/alice.pub.json` | Derive an address and show version, public-key hash and checksum |
| `wallet address --check <ADDRESS>` | Validate an address (characters, length, checksum, network) |
| `wallet tx --from keys/alice.pub.json --to <ADDR> --amount 1250000 --nonce 7 --memo "rent" -o tx.json` | Build an unsigned canonical transaction |
| `wallet bytes --tx tx.json` | Byte-level dump of exactly what gets signed, plus txid |
| `wallet sign --key keys/alice.key.json --tx tx.json -o signed.json` | Sign (shows a summary, asks you to confirm the recipient; `--yes` for scripts) |
| `wallet verify --signed signed.json [--nonces state.json --record]` | Independent verification with a precise rejection reason; `--nonces` enables replay protection |

Exit codes: `0` ok · `1` verification rejected · `2` other error. Default network: `course-testnet`.

## 3. Design summary

| Item | Choice |
|---|---|
| Curve / signature | secp256k1, ECDSA with SHA-256, via `cryptography` |
| Randomness | `secrets.token_bytes(32)` (OS CSPRNG), redrawn until 1 ≤ d < n |
| Public key | 33-byte compressed SEC1 |
| Address | `Base58Check(version ‖ SHA-256(pubkey)[:20])`, version `0x6f` testnet (`m…`/`n…`), `0x00` mainnet (`1…`) |
| Transaction | fixed binary layout: magic `CTX\0`, version, network id, sender, recipient, u64 amount, u64 nonce, memo hash — 110 bytes on testnet |
| Signature encoding | exactly 64-byte `r‖s` as 128 lowercase hex, **low-S only** |
| Replay protection | signed nonce + per-sender store: nonce must exceed the last accepted one |

Full byte-level specification: **`docs/transaction_format.md`**. Threat model: **`docs/threat_model.md`**.

## 4. Acceptance checks

| Requirement | How it is met / shown |
|---|---|
| Instructor can verify using only public data and the spec | `examples/` has public keys and a signed transaction, no private keys. `scripts/independent_verify.py` does **not** import the wallet; it is written from the spec alone, and the tests check it agrees with `wallet verify` on evry example |
| Changing any signed field must fail | `test_changing_any_signed_field_fails`, `test_changing_recipient_fails`, `test_changing_sender_fails` |
| Same tx with different whitespace / key order → same signed bytes | `test_whitespace_and_key_order_give_same_bytes`; `examples/attacks/reordered_whitespace.json` stays VALID |

Rejections, each with its own code (`examples/attacks/` has a file for each):

| Case | Code | Example |
|---|---|---|
| Changed amount / recipient | `BAD_SIGNATURE` | `tampered_amount.json`, `tampered_recipient.json` |
| Wrong network | `WRONG_NETWORK` | `wrong_network.json`, or `--network course-mainnet` |
| Wrong signer | `WRONG_SIGNER` | `wrong_signer.json` |
| Replayed nonce | `REPLAYED_NONCE` | verify the same file twice with `--nonces state.json --record` |
| Malformed address | `MALFORMED_ADDRESS` | `malformed_address.json` |
| Invalid checksum | `INVALID_CHECKSUM` | `bad_checksum.json` |
| Non-canonical signature | `NON_CANONICAL_SIGNATURE` | `high_s.json`, `der_signature.json`, `uppercase_signature.json` |

Regenerate attack files from any signed transaction with
`python scripts/make_attacks.py signed.json attacks/`.

## 5. Test vectors

`vectors/tx_vector.json` uses the private scalars 1 and 2 (public keys G and 2G, public knowledge, never
for real use) and gives the exact addresses, the 110 signed bytes and the txid. Base58 is checked against
Bitcoin Core's published vectors.

## 6. Layout

```
assign03/
├── readme.md · pyproject.toml · requirements.txt · DEMO_SCRIPT.md · .gitignore (keys/ never committed)
├── src/toywallet/  base58.py · address.py · keys.py · tx.py · signing.py · nonces.py · cli.py
├── tests/          test_address.py · test_keys.py · test_tx.py · test_signing.py · test_cli.py
├── docs/           transaction_format.md · threat_model.md
├── scripts/        independent_verify.py · make_attacks.py
├── vectors/        tx_vector.json
└── examples/       alice.pub.json · bob.pub.json · tx.json · signed_tx.json · attacks/*.json
```
