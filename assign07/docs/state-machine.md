# Escrow — State Machine

![State machine](state-machine.png)

The same diagram as Mermaid:

```mermaid
stateDiagram-v2
    [*] --> Created: deploy(buyer, seller, arbiter, amount, timeout)
    Created --> Funded: fund() [buyer, msg.value == amount]
    Created --> Cancelled: approveCancel() by buyer AND seller
    Funded --> Released: release() [buyer] / releaseWithSig() [buyer's EIP-712 signature]
    Funded --> Disputed: raiseDispute() [buyer or seller]
    Disputed --> ResolvedToSeller: resolve(true) [arbiter]
    Disputed --> ResolvedToBuyer: resolve(false) [arbiter] / resolveAfterTimeout() [now ≥ deadline]
    Released --> [*]
    ResolvedToBuyer --> [*]
    ResolvedToSeller --> [*]
    Cancelled --> [*]
```

| State | Contract holds | Who can be credited next | Terminal |
|---|---|---|---|
| Created | 0 | — | no |
| Funded | `amount` | seller (release) | no |
| Disputed | `amount` | buyer or seller (arbiter / timeout) | no |
| Released | credit of seller until withdrawn | — | **yes** |
| ResolvedToBuyer | credit of buyer until withdrawn | — | **yes** |
| ResolvedToSeller | credit of seller until withdrawn | — | **yes** |
| Cancelled | 0 | — | **yes** |
