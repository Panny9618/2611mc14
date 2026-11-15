// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base} from "./Base.t.sol";
import {Escrow} from "../src/Escrow.sol";

/// Fuzz tests over deposited amounts and caller roles.
contract EscrowFuzzTest is Base {
    function testFuzz_FundExactAmountOnly(uint96 amount_, uint96 sent) public {
        uint256 amt = bound(uint256(amount_), 1, type(uint96).max);
        Escrow e = new Escrow(buyer, seller, arbiter, amt, TIMEOUT);
        vm.deal(buyer, uint256(sent) + amt);
        vm.prank(buyer);
        if (sent != amt) {
            vm.expectRevert(abi.encodeWithSelector(Escrow.WrongAmount.selector, uint256(sent), amt));
            e.fund{value: sent}();
            assertEq(address(e).balance, 0);
        } else {
            e.fund{value: sent}();
            assertEq(address(e).balance, amt);
        }
        assertEq(address(e).balance, e.liabilities());
    }

    /// Any amount, any path: the payee ends with exactly `amount`, the contract with 0.
    function testFuzz_LifecyclePaysExactlyOnce(uint96 amount_, uint8 path) public {
        uint256 amt = bound(uint256(amount_), 1, 1_000_000 ether);
        Escrow e = new Escrow(buyer, seller, arbiter, amt, TIMEOUT);
        vm.deal(buyer, amt);
        uint256 buyerStart = buyer.balance;
        uint256 sellerStart = seller.balance;
        vm.prank(buyer);
        e.fund{value: amt}();
        assertEq(address(e).balance, e.liabilities());

        address payee;
        uint8 p = path % 4;
        if (p == 0) {
            vm.prank(buyer);
            e.release();
            payee = seller;
        } else {
            vm.prank(p == 1 ? buyer : seller);
            e.raiseDispute();
            assertEq(address(e).balance, e.liabilities());
            if (p == 3) {
                vm.warp(e.disputeDeadline());
                vm.prank(seller);
                e.resolveAfterTimeout();
                payee = buyer;
            } else {
                vm.prank(arbiter);
                e.resolve(p == 1);
                payee = p == 1 ? seller : buyer;
            }
        }
        assertEq(address(e).balance, e.liabilities());
        vm.prank(payee);
        e.withdraw();
        assertEq(address(e).balance, 0);
        assertEq(e.liabilities(), 0);
        if (payee == seller) {
            assertEq(seller.balance, sellerStart + amt);
            assertEq(buyer.balance, buyerStart - amt);
        } else {
            assertEq(buyer.balance, buyerStart);
            assertEq(seller.balance, sellerStart);
        }
        vm.prank(payee);
        vm.expectRevert(Escrow.NothingToWithdraw.selector);
        e.withdraw();
    }

    /// Any caller that does not hold the required role is rejected, in the right state.
    function testFuzz_UnauthorizedCallersRejected(address caller) public {
        vm.assume(caller != buyer && caller != seller && caller != arbiter);
        vm.deal(caller, AMOUNT);

        vm.prank(caller);
        vm.expectRevert(_unauth(caller));
        escrow.fund{value: AMOUNT}();
        vm.prank(caller);
        vm.expectRevert(_unauth(caller));
        escrow.approveCancel();

        _fund();
        vm.prank(caller);
        vm.expectRevert(_unauth(caller));
        escrow.release();
        vm.prank(caller);
        vm.expectRevert(_unauth(caller));
        escrow.raiseDispute();

        vm.prank(seller);
        escrow.raiseDispute();
        vm.prank(caller);
        vm.expectRevert(_unauth(caller));
        escrow.resolve(true);
        vm.warp(escrow.disputeDeadline());
        vm.prank(caller);
        vm.expectRevert(_unauth(caller));
        escrow.resolveAfterTimeout();
        vm.prank(caller);
        vm.expectRevert(Escrow.NothingToWithdraw.selector);
        escrow.withdraw();
        assertEq(uint8(escrow.state()), uint8(Escrow.State.Disputed));
        assertBalanced();
    }

    /// Fuzzed role assignment: deployment succeeds iff the three roles are distinct and non-zero.
    function testFuzz_ConstructorRoleRules(address b, address s, address a, uint256 amt) public {
        bool zero = b == address(0) || s == address(0) || a == address(0);
        bool overlap = b == s || a == b || a == s;
        if (zero) {
            vm.expectRevert(Escrow.ZeroAddress.selector);
        } else if (overlap) {
            vm.expectRevert(Escrow.RoleOverlap.selector);
        } else if (amt == 0) {
            vm.expectRevert(Escrow.ZeroAmount.selector);
        }
        new Escrow(b, s, a, amt, TIMEOUT);
    }
}
