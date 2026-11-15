# Assignment 4 — A UTXO Ledger and Transaction Validator (`ledger`)

**Roll:** 2611MC03 · **Stack:** Python 3.11+ · `cryptography` (secp256k1 ECDSA) · pytest

An in-memory UTXO ledger. A transaction consumes existing outputs and creates new ones. Every accepted
transaction must preserve value, be authorised by the owners of what it spends, and must not double-spend.
There is no mining or networking yet; the initial coins come from a genesis set.

## 1. Setup

```bash
cd assign04
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[test]"
pytest -q                            # 53 tests
ledger scenario --out examples/scenario   # regenerate the trace and snapshots
```

## 2. Data model

| Concept | Definition |
|---|---|
| **Outpoint** | `txid` (32 bytes) + `output_index` (u32) — names one output of one transaction |
| **Output** | integer `value` (1 … MAX_MONEY = 2.1×10¹⁵ units) + a locking condition |
| **Locking condition** | **P2PKH**: the 20-byte hash `SHA-256(public_key)[:20]`. To spend, show a public key with that hash and a valid signature from it |
| **UTXO set** | map *outpoint → output* of everything not yet spent |
| **txid** | `SHA-256(canonical body)`. The body holds version, inputs and outputs, but **not** signatures, so a signature can never change a txid |
| **Signature (per input *i*)** | low-S ECDSA over `"UTXSIG\0\0" ‖ body ‖ i ‖ spent output's value and lock`. It covers every input and output, and the exact coin and value being spent |

Canonical body (big-endian):

```
"UTX\0" | version u8 | n_in u16 | n_in × (prev_txid 32 | prev_index u32)
        | n_out u16 | n_out × (value u64 | lock_type u8 = 0x01 | pkh 20)
```

Exampl: one input and one output → 74 bytes; two inputs and two outputs → 139 bytes.

## 3. Validation rules (in order — all checks run before any state change)

| # | Code | Rejects |
|---:|---|---|
| 1 | `MALFORMED` | bad JSON or structure, unknown fields, non-integer values, invalid public key |
| 2 | `NO_INPUTS` / `NO_OUTPUTS` | empty input or output list (only genesis has no inputs) |
| 3 | `INVALID_VALUE` | an output that is negative, zero, above MAX_MONEY or does not fit in u64 |
| 4 | `VALUE_OVERFLOW` | the running sum of outputs exceeds MAX_MONEY (arithmetic overflow) |
| 5 | `DUPLICATE_INPUT` | the same outpoint twice in one transaction |
| 6 | `DOUBLE_SPEND` | an outpoint already consumed by an accepted transaction (the message names the spender) |
| 7 | `MISSING_INPUT` | an outpoint that never existed |
| 8 | `VALUE_CREATED` | Σ outputs > Σ inputs, i.e. excessive creation of value (e.g. too much change) |
| 9 | `MISSING_UNLOCK` · `WRONG_KEY` · `NON_CANONICAL_SIGNATURE` · `BAD_SIGNATURE` | missing unlock; public key does not match the P2PKH lock; high-S or out-of-range signature; signature does not verify |
| 10 | `INCORRECT_CHANGE` | with `--expect-fee F`: the change makes the implied fee differ from *F* |

`fee = Σ inputs − Σ outputs` (zero allowed). Fees are tracked in `total_fees`, and the invariant
`Σ UTXOs + total_fees = genesis total` is checked when a snapshot loads.

**Atomicity.** `apply()` first runs every check. Only then does it build the new UTXO set and swap it in
with plain assignments that cannot fail half-way. A rejection therefore leaves the ledger byte-for-byte
unchanged: the tests compare the UTXO set, the spent index, the applied list and the fees before and
after every rejection, and the trace shows the same UTXO-set hash before and after.

## 4. Wallet side: coin selection and change

**Strategy: largest-first (deterministic).**
1. Sort the sender's UTXOs by value, largest first. Ties are broken by `(txid, index)` ascending, so the
   result never depends on dictionary order or randomness.
2. Take coins until they cover `amount + fee`.
3. `change = selected − amount − fee`. Add a change output back to the sender if it is greater than 0,
   and none if it is exactly 0.
4. Output order is fixed: payment first, then change.

Trade-off: largest-first uses few inputs, so transactions are small and cheap. The cost is that big coins
get broken up and small coins are left behind.

The assignment's example: Alice holds 40 and 70 and pays Bob 85 with fee 2. She selects 70, then 40
(110 ≥ 87), and creates outputs **85 → Bob** and **23 → Alice (change)**, with fee 2. Submitting the same
signed transaction again is rejected as `DOUBLE_SPEND (this exact transaction was already accepted)`,
so Bob is not paid twice.

## 5. Commands

```bash
ledger keygen --name alice                                  # keys/alice.key.json (0600)
ledger init    --state state.json --give <ADDR>:40 --give <ADDR>:70
ledger balance --state state.json                           # per address, plus the supply check
ledger utxos   --state state.json [--address A]
ledger pay     --state state.json --key keys/alice.key.json --to <ADDR> --amount 85 --fee 2 -o tx.json
ledger show    --tx tx.json                                 # txid, inputs, outputs, body hex
ledger submit  --state state.json --tx tx.json [--expect-fee 2] [--trace trace.jsonl]
ledger scenario --out examples/scenario                     # scripted trace + snapshots
```

`submit` saves the state only when the transaction is accepted, and prints the UTXO-set hash before and
after. Exit codes: `0` accepted · `1` rejected · `2` usage error.

## 6. Persistence

`Ledger.save()` writes a JSON snapshot atomically (temporary file, then `os.replace`). It contains the
sorted UTXO set, the spent index, the applied txids, the fees and a `utxo_set_hash` commitment.
`Ledger.load()` recomputes the hash and the supply invariant, and refuses a tampered or inconsistent
file. Tests check that save → load gives identical logical contents, that the result is independent of
the entry order in the file, and that a reloaded ledger still rejects old double spends.

## 7. Deliverables

| Deliverable | Where |
|---|---|
| Validator | `src/utxolab/ledger.py` |
| Wallet-side transaction builder | `src/utxolab/wallet.py` (largest-first, change, signing) |
| Tests (53, ≥ 20 required) | `tests/` |
| Sample ledger snapshots | `examples/scenario/snapshots/00_genesis.json … 04_final.json` |
| Trace of accepted and rejected transactions with reasons | `examples/scenario/trace.md` (readable), `trace.jsonl` (machine-readable) |

### Trace summary (`examples/scenario/trace.md`)

| # | Submission | Result |
|---:|---|---|
| 1 | Alice pays Bob 85, fee 2 (70 + 40 → 85 + 23 change) | ✅ ACCEPTED, fee 2 |
| 2 | Same signed transaction again | ❌ `DOUBLE_SPEND` |
| 3 | Spend an outpoint that never existed | ❌ `MISSING_INPUT` |
| 4 | Same outpoint twice in one tx | ❌ `DUPLICATE_INPUT` |
| 5 | Mallory spends Bob's coin with her key | ❌ `WRONG_KEY` |
| 6 | Mallory attaches Bob's public key to her signature | ❌ `BAD_SIGNATURE` |
| 7 | Output redirected after Bob signed | ❌ `BAD_SIGNATURE` |
| 8 | Negative output value | ❌ `INVALID_VALUE` |
| 9 | Output value 2⁶⁴ | ❌ `INVALID_VALUE` |
| 10 | Outputs summing past MAX_MONEY | ❌ `VALUE_OVERFLOW` |
| 11 | Too much change (creates 5 units) | ❌ `VALUE_CREATED` |
| 12 | Too little change for the stated fee | ❌ `INCORRECT_CHANGE` |
| 13 | No signature | ❌ `MISSING_UNLOCK` |
| 14 | High-S twin signature | ❌ `NON_CANONICAL_SIGNATURE` |
| 15 | Bob pays Carol 100, fee 1 (85 + 50 → 100 + 34 change) | ✅ ACCEPTED, fee 1 |
| 16 | Alice pays Carol 20, fee 3 from 23 (no change output) | ✅ ACCEPTED, fee 3 |
| 17 | Bob re-spends the 85 already spent | ❌ `DOUBLE_SPEND` |

Final: Alice 0, Bob 34, Carol 120, fees 6. 154 + 6 = 160 (genesis), so supply is conserved. Every
rejection left the UTXO-set hash unchanged.

## 8. Layout

```
assign04/
├── readme.md · pyproject.toml · requirements.txt · DEMO_SCRIPT.md · .gitignore
├── src/utxolab/  tx.py · ledger.py · wallet.py · crypto.py · base58.py · scenario.py · cli.py
├── tests/        test_validator.py · test_wallet_tx_persist.py · test_cli_scenario.py
└── examples/scenario/  trace.md · trace.jsonl · snapshots/*.json
```
