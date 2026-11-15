// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {Escrow} from "../src/Escrow.sol";

/// Random actors call random functions; the fuzzer explores sequences of actions.
contract Handler is Test {
    Escrow public escrow;
    address[4] public actors;
    uint256 public paidOut;
    uint256 public deposited;
    uint256 public stateChanges;
    Escrow.State public lastTerminal;
    bool public sawTerminal;

    constructor(Escrow e, address[4] memory a) {
        escrow = e;
        actors = a;
        for (uint256 i; i < 4; i++) vm.deal(a[i], 1000 ether);
    }

    function _actor(uint256 seed) internal view returns (address) {
        return actors[seed % 4];
    }

    function _track() internal {
        if (escrow.isTerminal()) {
            if (sawTerminal) require(escrow.state() == lastTerminal, "terminal state changed");
            sawTerminal = true;
            lastTerminal = escrow.state();
        }
    }

    function fund(uint256 who, uint256 value) external {
        address a = _actor(who);
        value = bound(value, 0, 3 ether);
        vm.prank(a);
        try escrow.fund{value: value}() {
            deposited += value;
        } catch {}
        _track();
    }

    function approveCancel(uint256 who) external {
        vm.prank(_actor(who));
        try escrow.approveCancel() {} catch {}
        _track();
    }

    function release(uint256 who) external {
        vm.prank(_actor(who));
        try escrow.release() {} catch {}
        _track();
    }

    function raiseDispute(uint256 who) external {
        vm.prank(_actor(who));
        try escrow.raiseDispute() {} catch {}
        _track();
    }

    function resolve(uint256 who, bool toSeller) external {
        vm.prank(_actor(who));
        try escrow.resolve(toSeller) {} catch {}
        _track();
    }

    function timeout(uint256 who, uint256 jump) external {
        vm.warp(block.timestamp + bound(jump, 0, 30 days));
        vm.prank(_actor(who));
        try escrow.resolveAfterTimeout() {} catch {}
        _track();
    }

    function withdraw(uint256 who) external {
        address a = _actor(who);
        uint256 before = a.balance;
        vm.prank(a);
        try escrow.withdraw() {
            paidOut += a.balance - before;
        } catch {}
        _track();
    }

    function sendDirect(uint256 who, uint256 value) external {
        vm.prank(_actor(who));
        (bool ok,) = address(escrow).call{value: bound(value, 1, 1 ether)}("");
        require(!ok, "direct ETH accepted");
    }
}

contract EscrowInvariantTest is StdInvariant, Test {
    Escrow internal escrow;
    Handler internal handler;
    address internal buyer = makeAddr("buyer");
    address internal seller = makeAddr("seller");
    address internal arbiter = makeAddr("arbiter");
    address internal stranger = makeAddr("stranger");

    function setUp() public {
        escrow = new Escrow(buyer, seller, arbiter, 1 ether, 7 days);
        handler = new Handler(escrow, [buyer, seller, arbiter, stranger]);
        targetContract(address(handler));
    }

    /// The contract's balance and its recorded liabilities agree after every action.
    function invariant_BalanceEqualsLiabilities() public view {
        assertEq(address(escrow).balance, escrow.liabilities());
    }

    /// Money is conserved: everything deposited is either still held or has been paid out.
    function invariant_Conservation() public view {
        assertEq(handler.deposited(), address(escrow).balance + handler.paidOut());
    }

    /// At most one deposit ever, and nothing is paid out beyond it.
    function invariant_NeverMoreThanOneDeposit() public view {
        assertLe(handler.deposited(), 1 ether);
        assertLe(handler.paidOut(), 1 ether);
    }

    /// Only the buyer or seller can ever hold a credit; arbiter and strangers never can.
    function invariant_UnauthorizedNeverCredited() public view {
        assertEq(escrow.credits(arbiter), 0);
        assertEq(escrow.credits(stranger), 0);
        assertEq(escrow.credits(buyer) + escrow.credits(seller), escrow.totalCredits());
    }
}
