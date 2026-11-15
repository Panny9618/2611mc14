# Assignment 2 — Performance Report

**Roll:** 2611MC03

## Method

* Command: `merkle bench --sizes 8,1024,100000,1000000` (code in `src/merklelab/bench.py`).
* Leaves are the UTF-8 strings `tx-00000000`, `tx-00000001`, …
* **Build time** = constructing every level of the tree (all leaf hashes + all internal hashes).
  Best of 5 runs for ≤ 10,000 leaves, a single run above that.
* **Prove / Verify** = average over 1,000 random leaf indexes (fixed seed 2611).
* **Siblings (min–max)** is computed over *every* index for ≤ 200,000 leaves, and over the
  1,000 sampled proofs for 1,000,000 leaves.
* **Proof hashes** = sibling hashes only (32 bytes each). **Proof JSON** = the full proof file,
  without indentation (hex doubles the size, plus keys and direction strings).

## Results

| Leaves | Depth | Build time | per leaf | Siblings (min–max) | Proof hashes (max) | Proof JSON (avg) | Prove | Verify |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 8 | 3 | 0.01 ms | 0.81 µs | 3–3 | 96 B | 331 B | 10.6 µs | 5.5 µs |
| 1,024 | 10 | 0.74 ms | 0.72 µs | 10–10 | 320 B | 997 B | 6.7 µs | 7.7 µs |
| 100,000 | 17 | 86.37 ms | 0.86 µs | 10–17 | 544 B | 1658 B | 20.7 µs | 12.6 µs |
| 1,000,000 | 20 | 924.71 ms | 0.92 µs | 19–20 | 640 B | 1946 B | 81.9 µs | 19.7 µs |

_Measured with Python 3.13.18 on Linux x86_64. Absolute times will differ on other machines; the shape will not._

## Observations

1. **Construction is linear.** A tree of *n* leaves needs *n* leaf hashes and *n − 1* node
   hashes, so build time per leaf stays roughly constant (≈ 0.7–0.9 µs) from 8 to 1,000,000 leaves.
   Going from 100,000 to 1,000,000 leaves (10×) takes ≈ 10.7× longer.
2. **Proofs are logarithmic.** The number of siblings is at most ⌈log₂ n⌉: 3, 10, 17 and 20.
   Making the transaction set 1,000× larger (1,024 → 1,000,000) only doubles the proof
   (10 → 20 hashes, 320 B → 640 B). This is why a light client can check that one transaction is
   in a block without downloading the block.
3. **Odd sizes give shorter proofs for some leaves.** For 1,024 (a power of two) every proof has
   exactly 10 siblings. For 100,000 the minimum is 10: the last leaves sit in a small right-hand
   subtree whose nodes are promoted (not paired) at several levels, and promoted levels contribute
   no sibling. This is also why the verifier must know `tree_size`: the expected number and
   direction of siblings depends on both the index and the size, and `merkle verify` rejects any
   proof whose length or directions differ.
4. **Verification is cheap.** Verifying is one leaf hash plus one node hash per sibling, ≈ 20 µs
   even for a million leaves. "Prove" at 1,000,000 leaves is slower than verify only because of
   cache misses when reading the stored levels (≈ 64 MB of hashes), not because of more hashing.
5. **JSON overhead.** The JSON proof is ≈ 3× the raw sibling bytes (hex encoding plus field
   names). A binary encoding would be 33 bytes per sibling (1 direction byte + 32 hash bytes),
   but the assignment requires JSON.

## Memory

The library stores every level so that proofs need no recomputation: about 2n hashes × 32 bytes
of hash data (≈ 64 MB for 1,000,000 leaves, plus Python object overhead). A verifier stores nothing
but the root.
