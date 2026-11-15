# Threat Model — Educational Wallet

**Roll:** 2611MC03 · Assignment 3

**Assets:** the private key (whoever holds it can spend), the integrity of each transaction (recipient,
amount, network, nonce), and the user's intent (sending to the address they meant).

**Out of scope:** this is a teaching wallet for a toy chain. It has no hardware isolation, no encrypted
key storage and no protection against malware that runs as the same OS user. These limits are stated
below, not hidden.

| Threat | What could go wrong | What this wallet does | What remains / real-world fix |
|---|---|---|---|
| **Key theft** | Someone copies the private key file or reads it from the screen, a log or a Git repo, and signs transactions. | Only the public key and address are printed or exported by default. Private key files are created atomically (`O_EXCL`) with mode `0600` and never overwritten. The wallet **refuses to load** a key that group/others can read. `.gitignore` excludes `keys/` and `*.key.json`, and `examples/` holds public data only. Every key file carries a `TEST-ONLY` warning, and loading prints one. | The key is stored unencrypted, so malware running as the user, a backup or root can read it. Real wallets encrypt keys with a passphrase (scrypt/Argon2), or keep them in a hardware wallet or secure enclave so the key never leaves the device. |
| **Weak randomness** | A predictable private key, or a reused ECDSA nonce *k*, reveals the private key. | The private scalar comes from the OS CSPRNG (`secrets.token_bytes` → `getrandom`/`urandom`) with rejection sampling, so there is no modulo bias. No home-made RNG, no `random` module, no seeds. ECDSA and its per-signature *k* are produced by OpenSSL through `cryptography`. Tests check that 50 generated keys are distinct and in range. | A VM cloned with its RNG state or an early-boot low-entropy system can still be a risk. Production wallets use deterministic *k* (RFC 6979) or hedged signing so a bad RNG cannot leak the key through *k*. |
| **Replay** | An old, validly signed transaction is submitted again, paying the recipient twice, or a testnet signature is replayed on mainnet. | The nonce is inside the signed bytes, and the verifier keeps a per-sender nonce store, rejecting any nonce ≤ the last accepted (`REPLAYED_NONCE`). `network_id` and the address version bytes are also signed, so a signature cannot move between networks (`WRONG_NETWORK`). The `CTX\0` magic prefix separates transaction signatures from any other signed message. | The nonce store is a local file. On a real chain, every node enforces the same rule as part of consensus state, and Assignment 4's UTXO model prevents double spends by consuming outputs. |
| **Clipboard replacement** | Malware watches the clipboard and swaps a pasted address for the attacker's, often with matching first and last characters. | Base58Check catches typos (any single-character change fails the checksum, tested for every position) but **not** a deliberate swap to a valid address. So before signing, the wallet prints the full recipient, amount, network and nonce, and in interactive use requires the user to type the last 6 characters of the recipient. Scripts must pass `--yes` explicitly. | Typing 6 characters only helps if the user checks them against a trusted source, not the poisoned clipboard. Real fixes are an address book, verifying on a hardware wallet's own screen, and comparing the **full** address. |
| **Phishing** | A fake site or message tricks the user into signing a transaction they don't understand, revealing the key, or using a fake wallet. | The wallet never asks for or prints the private key. It signs only a transaction whose sender matches the loaded key (`WRONG_SIGNER`), and it shows every field in plain form before signing. `wallet bytes` shows exactly what is being signed. The memo is committed only as a hash, so a memo cannot hide instructions in the signed data. | No software can stop a user who willingly pastes their key into a website. User education matters: no legitimate service ever needs your private key. Signed messages should state plainly what they authorise, which is the idea behind EIP-712 in Assignment 7. |
| **Accidental mainnet use** | A test key or test script sends real funds, or a testnet address is pasted into a mainnet transaction. | Addresses encode their network (testnet starts with `m`/`n`, mainnet with `1`), and mixing them is rejected. Keys are bound to one network. Signing a `course-mainnet` transaction fails with `MAINNET_BLOCKED` unless `--allow-mainnet` is given. Verifiers reject transactions for a network other than their own. The default network is testnet. | A user can still pass `--allow-mainnet`. Real wallets also use separate key derivation paths per network (BIP-44 coin type) so testnet and mainnet keys are never the same key. |

## Additional design defences

* **Signature malleability:** only the low-S, fixed 64-byte `r‖s` lowercase-hex form is accepted. The
  high-S twin, DER and other encodings are rejected (`NON_CANONICAL_SIGNATURE`), so a third party cannot
  alter a signature, and any ID computed over it, without the key.
* **Canonical bytes:** a fixed binary layout is signed, not JSON text, so reformatting cannot create two
  "different" versions of one transaction.
* **Strict parsing:** duplicate JSON keys, unknown fields, floats and out-of-range integers are rejected,
  so two parsers cannot disagree about what was signed.
