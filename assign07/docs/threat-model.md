# Escrow — Threat Model

**Roll:** 2611MC03 · Assignment 7

**Assets:** the deposited ETH; the correctness of who receives it; availability (the money can always
reach someone entitled to it).
**Trust assumptions:** the buyer and seller trust the arbiter to judge honestly, and only for the
duration of `disputeTimeout`. Nobody trusts anybody else. There is no owner or admin, and nothing can
be upgraded.

## Threats and mitigations

| # | Threat | Mitigation in the contract | Test evidence |
|---|---|---|---|
| T1 | **Unauthorised transition**: a stranger, the arbiter or the wrong party releases, disputes, resolves or cancels | Every mutator checks `msg.sender` against an immutable role (`only`, `onlyParties`) and the current state (`inState`). Custom errors `Unauthorized`, `InvalidState` | `test_*_RevertsNotBuyer/Unauthorized`, `testFuzz_UnauthorizedCallersRejected` (1000 random callers) |
| T2 | **Redirecting funds**: someone makes the money go to themselves | Payees are fixed at deployment. Transitions only credit `buyer` or `seller`. `withdraw` pays only the caller's own credit; `withdrawTo` lets only the owner of a credit choose a destination. A relayer of a signed release cannot change the recipient | `test_StrangerCannotRedirectFunds`, `test_SignedRelease_RelayerPaysGas`, `invariant_UnauthorizedNeverCredited` |
| T3 | **Paying twice** (terminal state pays again, double withdrawal) | `amount` is credited exactly once, on the single transition into a paying terminal state; terminal states reject all transitions. The credit is zeroed **before** the ETH transfer | `test_Terminal_*`, `test_Withdraw_PaysPayeeOnce`, `testFuzz_LifecyclePaysExactlyOnce`, `invariant_Conservation`. A mutation that skips zeroing is caught by 3 tests |
| T4 | **Reentrancy**: a payee contract re-enters `withdraw` from its `receive` | Checks-effects-interactions plus OpenZeppelin `nonReentrant`. The only external call is the last statement | `test_Reentrancy_SwallowedReentryGetsNothingExtra`, `test_Reentrancy_RevertingReentryRestoresCredit` |
| T5 | **Funds locked**: a payee cannot receive ETH, the arbiter disappears, or the buyer never acts | Pull payments: a reverting recipient blocks only its own withdrawal, and the credit is restored. `withdrawTo` sends it elsewhere. From Funded, either party can dispute; from Disputed, either party can refund the buyer after `disputeTimeout` (≥ comparison, not equality) | `test_RejectingPayee_CanUseWithdrawTo`, `test_Timeout_*` |
| T6 | **Repeated or wrong funding**, accounting drift | `fund` only in Created, only by the buyer, only exactly `amount`. `receive`/`fallback` revert, so stray ETH cannot enter. `liabilities()` exposes what is owed | `test_Fund_*`, `test_DirectEthRejected`, `invariant_BalanceEqualsLiabilities` (12,800 random calls) |
| T7 | **Role overlap / zero addresses**: a party judging its own dispute, or funds credited to `address(0)` | The constructor rejects zero addresses, `buyer == seller` and an arbiter equal to either party | `test_Constructor_*`, `testFuzz_ConstructorRoleRules` |
| T8 | **Signature replay or forgery** (EIP-712 release) | The domain binds `chainId` and `verifyingContract`; the message has a `nonce` (incremented) and a `deadline` (`block.timestamp ≤ deadline`). The signature must recover to `buyer`. OpenZeppelin ECDSA rejects malleable high-s signatures and bad lengths | `test_SignedRelease_*` (wrong signer, expired, changed deadline, other escrow, other chain, high-s, garbage) |
| T9 | **Front-running** | Nothing to gain: every transition is permissioned, and the only parameter-free race is a dispute vs a release, both legitimate choices of the parties. A relayer front-running a signed release produces the same result | — |
| T10 | **Timestamp manipulation** | Validators can shift `block.timestamp` by seconds. The only time rules are the dispute timeout (days) and the signature deadline, so this is harmless. No equality comparisons on time | `test_Timeout_WorksAtAndAfterDeadline` |
| T11 | **Forced ETH** via `selfdestruct` or a coinbase reward | Can only make `balance > liabilities`; it cannot reduce what is owed. Such ETH is stranded, a documented limitation. No logic relies on `address(this).balance` | — |
| T12 | **Gas griefing / DoS** | No loops, no unbounded storage, no push payments; every function is O(1) | gas report |

## Avoided patterns (assignment checklist)

- `tx.origin`: not used; authorisation is always `msg.sender`.
- Unbounded loops: none in the contract.
- Timestamp equality: deadlines use `<` / `>` comparisons.
- Unchecked low-level calls: the single `call` checks `ok` and reverts with `TransferFailed`.
- Hidden behaviour in copied code: only OpenZeppelin's `ReentrancyGuard`, `EIP712` and `ECDSA` are used,
  unmodified (`lib/VENDORED.md`). All escrow logic is in `src/Escrow.sol`.

## Stretch goal: new trust and replay assumptions of `releaseWithSig`

- **Who can trigger it:** anyone holding the buyer's signature can submit it until `deadline`. The
  buyer must treat a signed release as a release, though it can only ever pay the seller.
- **Cancelling a signature:** the buyer can't revoke it before `deadline` except by disputing first,
  which moves the escrow out of Funded so the signature no longer applies. Short deadlines limit exposure.
- **Replay:**
  - another chain → different `chainId` → `InvalidSignature`
  - another escrow → different `verifyingContract` → `InvalidSignature`
  - the same escrow → the state is no longer Funded, and the `nonce` has advanced
- **Relayer:** pays the gas and gains nothing. There is no fee field, so it cannot extract value.

## Out of scope

The arbiter's honesty (by design, a trusted third party). Off-chain delivery of the goods. Keys being
stolen from the parties' wallets. Upgrades (the contract is immutable; a new deal is a new deployment).
