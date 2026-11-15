# Escrow — Specification

**Roll:** 2611MC03 · Assignment 7 · written before the Solidity code; the contract implements exactly this.

## 1. Purpose

A **buyer** pays for something from a **seller**. The money is held by a contract instead of either
party. The buyer releases it when satisfied; if they disagree, an **arbiter** decides who gets it. Before
the buyer pays, buyer and seller can both agree to call the deal off. One contract instance = one deal.

## 2. Parties and parameters (fixed at deployment, immutable)

| Name | Meaning | Rules |
|---|---|---|
| `buyer` | funds the escrow, may release, may dispute | non-zero |
| `seller` | receives payment on release, may dispute | non-zero, ≠ buyer |
| `arbiter` | resolves disputes only | non-zero, ≠ buyer, ≠ seller (a party must not judge its own dispute) |
| `amount` | exact wei the buyer must deposit | > 0 |
| `disputeTimeout` | seconds the arbiter has to resolve a dispute | > 0 |

Violating any rule makes deployment revert (`ZeroAddress`, `RoleOverlap`, `ZeroAmount`, `ZeroTimeout`).

## 3. States and transitions

| From | Action | Who | Condition | To | Money effect |
|---|---|---|---|---|---|
| Created | `fund()` | buyer | `msg.value == amount` | **Funded** | contract holds `amount` |
| Created | `approveCancel()` | buyer, seller | each approves once; the second approval completes it | **Cancelled** | none (nothing was deposited) |
| Funded | `release()` | buyer | — | **Released** | seller credited `amount` |
| Funded | `releaseWithSig(deadline, sig)` | anyone (relayer) | valid EIP-712 signature by buyer, not expired, current nonce | **Released** | seller credited `amount` |
| Funded | `raiseDispute()` | buyer, seller | — | **Disputed** | none; `disputedAt = now` |
| Disputed | `resolve(false)` | arbiter | — | **ResolvedToBuyer** | buyer credited `amount` |
| Disputed | `resolve(true)` | arbiter | — | **ResolvedToSeller** | seller credited `amount` |
| Disputed | `resolveAfterTimeout()` | buyer, seller | `now ≥ disputedAt + disputeTimeout` | **ResolvedToBuyer** | buyer credited `amount` |
| Released, ResolvedToBuyer, ResolvedToSeller, Cancelled | *anything that changes state* | — | — | revert `InvalidState` | none |

This is the required table: Created → Funded or Cancelled; Funded → Released or Disputed; Disputed →
ResolvedToBuyer or ResolvedToSeller; terminal states have no further transitions.

Not state changes (allowed in any state):

| Action | Who | Effect |
|---|---|---|
| `withdraw()` | anyone with a credit | sends the caller's whole credit to the caller |
| `withdrawTo(to)` | anyone with a credit | sends it to `to ≠ 0` (for payees that cannot receive ETH themselves) |
| views | anyone | `state`, `credits(a)`, `liabilities()`, `isTerminal()`, `releaseNonce`, `disputeDeadline()` |

## 4. Money rules

1. **Pull payments.** A resolution never sends ETH. It only increases `credits[payee]` (and `totalCredits`).
   Payees withdraw themselves. One reverting or malicious recipient therefore cannot block a state change.
2. **Checks-effects-interactions** in `withdraw`: check credit > 0 → set credit to 0 and lower
   `totalCredits` → then make the single external call. A failed call reverts everything (the credit comes
   back, nothing is lost). `withdraw` is also `nonReentrant`.
3. **Liabilities** = `amount` while Funded or Disputed, plus `totalCredits`. After every action,
   `address(this).balance == liabilities()` (the only exception is ETH force-sent by `selfdestruct`, which
   can only make the balance larger).
4. **No double payment.** `amount` is credited exactly once — by the single transition into a paying
   terminal state — and a credit is zeroed before it is paid.
5. **No stray ETH.** Plain transfers to the contract (`receive`/`fallback`) revert with `DirectPaymentRejected`.
6. **No locked funds.** Every funded state has an exit: Funded → Released (buyer) or Disputed (either party);
   Disputed → resolved by the arbiter, or after `disputeTimeout` by either party (refund). Credits can
   always be withdrawn, to another address if needed.

## 5. Signed release (stretch goal: EIP-712)

The buyer can sign instead of sending a transaction; anyone may submit the signature and pay the gas.

```
domain  = EIP712Domain(name "Escrow", version "1", chainId, verifyingContract = this escrow)
message = Release(uint256 nonce, uint256 deadline)
```

Accepted only if: state is Funded, `block.timestamp ≤ deadline`, the signature recovers to `buyer`
(OpenZeppelin ECDSA, which rejects malleable high-s signatures), and `nonce == releaseNonce`, which then
increments. Replay is impossible across chains (chainId), across escrows (verifyingContract), and on this
escrow (nonce + state). New trust assumption: whoever holds the buyer's signature can trigger the release
before `deadline`, but only to the seller — the signature cannot redirect funds.

## 6. Custom errors and events

Errors: `ZeroAddress`, `RoleOverlap`, `ZeroAmount`, `ZeroTimeout`, `Unauthorized(caller)`,
`InvalidState(current)`, `WrongAmount(sent, expected)`, `AlreadyApproved(party)`, `DisputeNotExpired(deadline)`,
`SignatureExpired(deadline)`, `InvalidSignature()`, `NothingToWithdraw()`, `TransferFailed()`,
`DirectPaymentRejected()`.

Events: `StateChanged(from, to)` on every transition, plus `Funded(buyer, amount)`, `CancelApproved(by)`,
`Released(by)`, `DisputeRaised(by)`, `DisputeResolved(by, toSeller)`, `Credited(payee, amount)`,
`Withdrawn(payee, to, amount)`.

## 7. Explicitly avoided

`tx.origin` (authorization uses `msg.sender`), loops of any kind, timestamp equality (deadlines use
`≥`/`≤`), unchecked low-level calls (the one `call` checks its result), push payments, owner/admin keys
(no one can change parties, amount or rules after deployment).
