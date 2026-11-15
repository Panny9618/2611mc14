#!/usr/bin/env python3
"""Deploy to a local Anvil node and drive every path of the escrow with real transactions.

    python3 script/run_local.py            # starts Anvil if none is running on :8545

Four escrows are deployed (forge script) and exercised (cast send), each from the
right account:
  happy    fund -> release -> seller withdraws
  dispute  fund -> seller disputes -> arbiter resolves to buyer -> buyer withdraws
  cancel   buyer approves cancel -> seller approves cancel
  signed   fund -> relayer submits the buyer's EIP-712 signature -> seller withdraws
Then it checks events, final balances, gas used, contract balance == liabilities,
and the deployed bytecode, and writes:
  deployments/anvil/receipts/*.json    raw transaction receipts
  deployments/anvil/summary.md         readable report
The keys are Anvil's public development keys - test only, never use them elsewhere.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RPC = os.environ.get("RPC_URL", "http://127.0.0.1:8545")
OUT = os.path.join(ROOT, "deployments", "anvil")
REC = os.path.join(OUT, "receipts")

# Anvil's default, publicly known development accounts (test mnemonic). NEVER use on a real network.
KEYS = {
    "deployer": "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "buyer": "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "seller": "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "arbiter": "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
}
EVENTS = ["StateChanged(uint8,uint8)", "Funded(address,uint256)", "CancelApproved(address)", "Released(address)",
          "DisputeRaised(address)", "DisputeResolved(address,bool)", "Credited(address,uint256)",
          "Withdrawn(address,address,uint256)"]
STATES = ["Created", "Funded", "Released", "Disputed", "ResolvedToBuyer", "ResolvedToSeller", "Cancelled"]
AMOUNT = 10**18


def q(v) -> int:
    """A JSON-RPC quantity: hex string ("0x1f"), decimal string or int (formats differ across Foundry versions)."""
    if isinstance(v, int):
        return v
    v = str(v).strip()
    return int(v, 16) if v.lower().startswith("0x") else int(v)


def sh(*args: str, env: dict | None = None) -> str:
    r = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, env={**os.environ, **(env or {})})
    if r.returncode != 0:
        raise SystemExit(f"command failed: {' '.join(args[:4])} ...\n{r.stdout}\n{r.stderr}")
    return r.stdout.strip()


def cast(*args: str) -> str:
    return sh("cast", *args, "--rpc-url", RPC) if args[0] not in ("keccak", "wallet", "sig-event", "abi-encode") else sh("cast", *args)


def chain_id() -> int | None:
    """The RPC's chain id, or None if nothing answers. Checks the output, not just the exit code,
    because some Foundry wrappers (e.g. the npm packages) exit 0 even when the call failed."""
    r = subprocess.run(["cast", "chain-id", "--rpc-url", RPC], cwd=ROOT, capture_output=True, text=True)
    out = r.stdout.strip()
    return int(out) if r.returncode == 0 and out.isdigit() else None


def ensure_anvil() -> subprocess.Popen | None:
    if chain_id() is not None:
        return None
    for tool in ("anvil", "cast", "forge"):
        if not shutil.which(tool):
            raise SystemExit(f"{tool} not found - install Foundry first (see readme)")
    log = open(os.path.join(ROOT, ".anvil.log"), "w")
    p = subprocess.Popen(["anvil", "--hardfork", "osaka", "--port", RPC.rsplit(":", 1)[1]], stdout=log, stderr=log)
    for _ in range(100):
        time.sleep(0.2)
        if chain_id() is not None:
            return p
        if p.poll() is not None:
            break
    p.terminate()
    raise SystemExit("anvil did not start - see .anvil.log (try running `anvil --hardfork osaka` by hand)")


def main() -> int:
    anvil = ensure_anvil()
    try:
        return run()
    finally:
        if anvil:
            anvil.terminate()


def run() -> int:
    chain = chain_id()
    if chain != 31337:
        raise SystemExit(f"refusing to run against chain id {chain}: this script uses public test keys")
    if os.path.exists(OUT):
        shutil.rmtree(OUT)
    os.makedirs(REC)
    addr = {n: cast("wallet", "address", "--private-key", k) for n, k in KEYS.items()}
    topic = {cast("keccak", e): e.split("(")[0] for e in EVENTS}
    start_bal = {n: int(cast("balance", a)) for n, a in addr.items()}
    rows, checks, escrows = [], [], {}
    cost = {n: 0 for n in addr}                     # wei spent on gas by each account

    def deploy(label: str) -> str:
        sh("forge", "script", "script/Deploy.s.sol", "--rpc-url", RPC, "--broadcast", "--private-key", KEYS["deployer"],
           env={"BUYER": addr["buyer"], "SELLER": addr["seller"], "ARBITER": addr["arbiter"], "LABEL": label,
                "AMOUNT_WEI": str(AMOUNT), "TIMEOUT_SECONDS": str(7 * 24 * 3600)})
        a = json.load(open(os.path.join(ROOT, "deployments", f"{label}.json")))["address"]
        bf = os.path.join(ROOT, "broadcast", "Deploy.s.sol", "31337", "run-latest.json")
        b = json.load(open(bf))
        r = b["receipts"][0]
        json.dump(r, open(os.path.join(REC, f"{label}-00-deploy.json"), "w"), indent=2)
        rows.append((label, "deploy", "deployer", r["transactionHash"], q(r["gasUsed"]), q(r["status"]), "—"))
        cost["deployer"] += q(r["gasUsed"]) * q(r["effectiveGasPrice"])
        escrows[label] = a
        return a

    def send(label: str, step: int, who: str, sig: str, *args: str, value: int = 0) -> dict:
        a = escrows[label]
        cmd = ["send", a, sig, *args, "--private-key", KEYS[who], "--json"]
        if value:
            cmd += ["--value", str(value)]
        r = json.loads(cast(*cmd))
        name = sig.split("(")[0]
        json.dump(r, open(os.path.join(REC, f"{label}-{step:02d}-{name}.json"), "w"), indent=2)
        evs = [topic.get(lg["topics"][0], "?") for lg in r["logs"]]
        rows.append((label, name, who, r["transactionHash"], q(r["gasUsed"]), q(r["status"]), ", ".join(evs)))
        cost[who] += q(r["gasUsed"]) * q(r["effectiveGasPrice"])
        if q(r["status"]) != 1:
            raise SystemExit(f"{label} {name} failed")
        bal, liab = int(cast("balance", a)), int(cast("call", a, "liabilities()(uint256)").split()[0])
        checks.append((f"{label}: after {name} contract balance {bal} == liabilities {liab}", bal == liab))
        return {"events": evs}

    def state(label: str) -> str:
        return STATES[int(cast("call", escrows[label], "state()(uint8)"))]

    # ---------------------------------------------------------------- happy path
    deploy("happy")
    e = send("happy", 1, "buyer", "fund()", value=AMOUNT)
    checks.append(("happy: fund emitted StateChanged + Funded", e["events"] == ["StateChanged", "Funded"]))
    e = send("happy", 2, "buyer", "release()")
    checks.append(("happy: release emitted StateChanged, Released, Credited", e["events"] == ["StateChanged", "Released", "Credited"]))
    e = send("happy", 3, "seller", "withdraw()")
    checks.append(("happy: withdraw emitted Withdrawn", e["events"] == ["Withdrawn"]))
    checks.append(("happy: final state Released", state("happy") == "Released"))

    # ---------------------------------------------------------------- dispute path
    deploy("dispute")
    send("dispute", 1, "buyer", "fund()", value=AMOUNT)
    e = send("dispute", 2, "seller", "raiseDispute()")
    checks.append(("dispute: raiseDispute emitted DisputeRaised", "DisputeRaised" in e["events"]))
    e = send("dispute", 3, "arbiter", "resolve(bool)", "false")
    checks.append(("dispute: resolve emitted DisputeResolved + Credited", {"DisputeResolved", "Credited"} <= set(e["events"])))
    send("dispute", 4, "buyer", "withdraw()")
    checks.append(("dispute: final state ResolvedToBuyer", state("dispute") == "ResolvedToBuyer"))

    # ---------------------------------------------------------------- mutual cancellation
    deploy("cancel")
    send("cancel", 1, "buyer", "approveCancel()")
    checks.append(("cancel: one approval keeps state Created", state("cancel") == "Created"))
    e = send("cancel", 2, "seller", "approveCancel()")
    checks.append(("cancel: second approval -> Cancelled", state("cancel") == "Cancelled" and "StateChanged" in e["events"]))

    # ---------------------------------------------------------------- EIP-712 signed release
    a = deploy("signed")
    send("signed", 1, "buyer", "fund()", value=AMOUNT)
    # raw JSON-RPC: its format is fixed by the Ethereum spec, unlike `cast block --json`, which varies by Foundry version
    latest = json.loads(cast("rpc", "eth_getBlockByNumber", "latest", "false"))
    deadline = q(latest["timestamp"]) + 3600
    typed = {"types": {"EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                                        {"name": "chainId", "type": "uint256"}, {"name": "verifyingContract", "type": "address"}],
                       "Release": [{"name": "nonce", "type": "uint256"}, {"name": "deadline", "type": "uint256"}]},
             "primaryType": "Release", "domain": {"name": "Escrow", "version": "1", "chainId": 31337, "verifyingContract": a},
             "message": {"nonce": 0, "deadline": deadline}}
    sig = cast("wallet", "sign", "--private-key", KEYS["buyer"], "--data", json.dumps(typed))
    e = send("signed", 2, "deployer", "releaseWithSig(uint256,bytes)", str(deadline), sig)
    checks.append(("signed: relayer (deployer account) released with the buyer's signature", "Released" in e["events"]))
    send("signed", 3, "seller", "withdraw()")
    checks.append(("signed: final state Released", state("signed") == "Released"))

    # ---------------------------------------------------------------- final balances and bytecode
    end_bal = {n: int(cast("balance", x)) for n, x in addr.items()}
    gas_cost = cost
    # buyer paid 3 deposits and got 1 refund back; seller received 2 payments; arbiter is never paid
    checks.append(("buyer balance = start − 3 deposits + 1 refund − gas",
                   end_bal["buyer"] == start_bal["buyer"] - 3 * AMOUNT + AMOUNT - cost["buyer"]))
    checks.append(("seller balance = start + 2 payments − gas", end_bal["seller"] == start_bal["seller"] + 2 * AMOUNT - cost["seller"]))
    checks.append(("arbiter balance = start − gas only (never paid by the escrow)", end_bal["arbiter"] == start_bal["arbiter"] - cost["arbiter"]))
    for label, x in escrows.items():
        checks.append((f"{label}: contract balance 0 and liabilities 0 at the end",
                       int(cast("balance", x)) == 0 and int(cast("call", x, "liabilities()(uint256)").split()[0]) == 0))
    art = json.load(open(os.path.join(ROOT, "out", "Escrow.sol", "Escrow.json")))
    compiled_len = (len(art["deployedBytecode"]["object"]) - 2) // 2
    code_info = {}
    for label, x in escrows.items():
        code = cast("code", x)
        code_info[label] = ((len(code) - 2) // 2, cast("keccak", code))
        checks.append((f"{label}: bytecode deployed at {x} ({code_info[label][0]:,} bytes = compiled artifact size)",
                       code_info[label][0] == compiled_len > 0))
    ok = all(v for _, v in checks)
    lines = [f"# Assignment 7 — Local Anvil run", "",
             f"Generated by `python3 script/run_local.py` against Anvil (chain id {chain}, hardfork osaka). "
             f"Keys are Anvil's public development keys.", "",
             "## Accounts", "", "| Role | Address |", "|---|---|"] + [f"| {n} | `{a}` |" for n, a in addr.items()]
    lines += ["", "## Deployed contracts", "", "| Escrow | Address |", "|---|---|"] + [f"| {l} | `{a}` |" for l, a in escrows.items()]
    lines += ["", "## Deployed bytecode", "", "| Escrow | Code size (bytes) | keccak256(code) |", "|---|---:|---|"]
    lines += [f"| {l} | {n:,} | `{h}` |" for l, (n, h) in code_info.items()]
    lines += ["", f"Compiled runtime size: {compiled_len:,} bytes. Hashes differ between deployments because the "
                  "immutables (EIP-712 cached domain separator and contract address) are written into the code at deployment."]
    lines += ["", "## Transactions and receipts", "",
              "| Escrow | Call | From | Tx hash | Gas used | Status | Events |", "|---|---|---|---|---:|:---:|---|"]
    lines += [f"| {l} | `{s}` | {w} | `{h[:18]}…` | {g:,} | {'✅' if st == 1 else '❌'} | {ev} |" for l, s, w, h, g, st, ev in rows]
    lines += ["", "Raw receipts: `deployments/anvil/receipts/`.", "", "## Final balances (wei)", "",
              "| Account | Start | End | Change | Gas paid |", "|---|---:|---:|---:|---:|"]
    lines += [f"| {n} | {start_bal[n]:,} | {end_bal[n]:,} | {end_bal[n] - start_bal[n]:+,} | {gas_cost[n]:,} |" for n in addr]
    lines += ["", "## Checks", ""] + [f"- {'✅' if v else '❌'} {k}" for k, v in checks]
    lines += [""]
    with open(os.path.join(OUT, "summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    for k, v in checks:
        print(f"  [{'PASS' if v else 'FAIL'}] {k}")
    print(f"\nwrote {os.path.relpath(OUT, ROOT)}/summary.md and receipts/  ({len(rows)} transactions)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
