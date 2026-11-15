# Transaction Format Specification (byte level)

**Roll:** 2611MC03 · Assignment 3 · version 1

This document is enough to verify a signed transaction without the wallet code.
`scripts/independent_verify.py` is written only from this page, and the tests check that it agrees
with `wallet verify` on every example.

## 1. Primitives

| Item | Definition |
|---|---|
| Curve | secp256k1 (order *n* = `FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141`) |
| Private key | integer *d* with 1 ≤ *d* < *n*, drawn from the OS CSPRNG (re-draw if out of range) |
| Public key | 33-byte compressed SEC1 point: `0x02`/`0x03` (parity of y) ‖ 32-byte x. Uncompressed keys are rejected |
| Integers | unsigned, big-endian, fixed width |
| Hash | SHA-256 |

## 2. Addresses

```
PKH      = SHA-256(compressed_public_key)[0:20]                       20 bytes
payload  = version_byte ‖ PKH                                         21 bytes
checksum = SHA-256(SHA-256(payload))[0:4]                             4 bytes
address  = Base58(payload ‖ checksum)    Bitcoin alphabet, each leading 0x00 byte → '1'
```

| network_id | version byte | address starts with |
|---|---|---|
| `course-testnet` | `0x6f` | `m` or `n` |
| `course-mainnet` | `0x00` | `1` |

An address is valid only if: every character is in the Base58 alphabet
(`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`, no `0 O I l`), it decodes to exactly
25 bytes, the checksum matches, and the version byte is in the table **and equals the transaction's network**.

## 3. Signed message (the canonical transaction bytes)

| Offset | Size | Field | Encoding / rule |
|---:|---:|---|---|
| 0 | 4 | magic | ASCII `CTX` + `0x00` → `43 54 58 00` (domain separation) |
| 4 | 1 | version | u8, must be `1` |
| 5 | 1 | network_len | u8, *L* = byte length of network_id, 1–32 |
| 6 | *L* | network_id | ASCII, characters `[a-z0-9-]` only |
| 6+*L* | 21 | sender | address payload (version ‖ PKH) — **not** the Base58 text |
| 27+*L* | 21 | recipient | address payload (version ‖ PKH) |
| 48+*L* | 8 | amount_units | u64, 1 … 2⁶⁴−1, smallest integer unit (no decimals ever) |
| 56+*L* | 8 | nonce | u64, 0 … 2⁶⁴−1 |
| 64+*L* | 32 | memo_hash | raw 32 bytes (SHA-256 of the UTF-8 memo; the memo itself is not signed or sent) |
| 96+*L* | — | end | **110 bytes** for `course-testnet` (*L* = 14) |

`txid = SHA-256(signed bytes)`, shown as lowercase hex.

Because the signed message is built field-by-field from fixed-width values, JSON details (key order,
whitespace, indentation, line endings) can never change it. Two JSON objects describing the same
transaction always give identical bytes.

## 4. JSON container

Unsigned transaction — exactly these seven keys, no others, no duplicates:

```json
{
  "version": 1,
  "network_id": "course-testnet",
  "sender": "<Base58Check address>",
  "recipient": "<Base58Check address>",
  "amount_units": 1250000,
  "nonce": 7,
  "memo_hash": "<64 lowercase hex>"
}
```

JSON rules: integers must be JSON integers (not strings, not `true`, not `1.0`/`1e6`); `memo_hash` is
64 lowercase hex; floats, `NaN`, `Infinity` and duplicate keys are rejected.

Signed transaction — exactly three keys:

```json
{ "tx": { ...as above... }, "public_key": "<66 lowercase hex>", "signature": "<128 lowercase hex>" }
```

## 5. Signature

* Algorithm: ECDSA on secp256k1 with SHA-256, over the bytes of section 3.
* Encoding: exactly 64 bytes `r ‖ s`, each a 32-byte big-endian integer, written as **128 lowercase hex**.
* Canonical form: 1 ≤ *r* < *n* and 1 ≤ *s* ≤ ⌊*n*/2⌋ (**low-S**).

Rejected as `NON_CANONICAL_SIGNATURE`: DER encoding, uppercase hex, a `0x` prefix, wrong length,
*r* or *s* equal to 0 or ≥ *n*, and the high-S twin (*r*, *n* − *s*). The high-S twin is mathematically
valid ECDSA, so without this rule anyone could alter a signature without the key (malleability).

## 6. Verification procedure (in this order)

1. Parse the JSON strictly (section 4). Failure → `MALFORMED`.
2. `tx.network_id` must equal the verifier's network. Failure → `WRONG_NETWORK`.
3. Decode sender and recipient (section 2). Bad characters/length/version → `MALFORMED_ADDRESS`;
   bad checksum → `INVALID_CHECKSUM`; address of another network → `WRONG_NETWORK`.
4. Parse `public_key` as a compressed point on secp256k1. Failure → `MALFORMED_PUBLIC_KEY`.
5. Parse `signature` (section 5). Failure → `NON_CANONICAL_SIGNATURE`.
6. `Base58Check(network_version ‖ SHA-256(public_key)[0:20])` must equal `sender`. Failure → `WRONG_SIGNER`.
7. ECDSA-verify the signature over the bytes of section 3. Failure → `BAD_SIGNATURE`.
8. Replay check (stateful verifiers): the nonce must be **strictly greater** than the last nonce
   accepted from this sender. Failure → `REPLAYED_NONCE`. Record the nonce after acceptance.

## 7. Worked example (`vectors/tx_vector.json`)

Keys: private scalars 1 and 2 — public knowledge, for testing only.

```
sender    mgvcECAzwwFKK3qmz5qkv1UzSBJRc91a46   (public key 0279be66…f81798 = generator G)
recipient mwj1NnJUH1LMGnfndpWN5aytwWoCuU1gbR   (public key 02c6047f…709ee5 = 2G)
amount    1,250,000   nonce 7   memo "rent for November"

offset field          bytes
     0 magic          43545800
     4 version        01
     5 network_len    0e
     6 network_id     636f757273652d746573746e6574             "course-testnet"
    20 sender         6f 0f715baf5d4c2ed329785cef29e562f73488c8a2   version 0x6f ‖ PKH
    41 recipient      6f b1c9938f01121e159887ac2c8d393a22e4476ff8   version 0x6f ‖ PKH
    62 amount_units   00000000001312d0                          1,250,000
    70 nonce          0000000000000007                          7
    78 memo_hash      b300e20c1c69562a3648bb22067ab521623feedc9d002b5d669618944dbfd620
total 110 bytes

signed bytes (hex):
43545800010e636f757273652d746573746e65746f0f715baf5d4c2ed329785cef29e562f73488c8a26fb1c9938f01121e
159887ac2c8d393a22e4476ff800000000001312d00000000000000007b300e20c1c69562a3648bb22067ab521623feedc
9d002b5d669618944dbfd620

txid = 1de8afe92fa231ae051d326ca7572333816ff05d6252474cd032924d9b6f150a
```

`wallet bytes --tx <file>` prints this dump for any transaction or signed-transaction file.
