// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base} from "./Base.t.sol";
import {Escrow} from "../src/Escrow.sol";

/// Unit tests: every permitted transition and every rejected one.
contract EscrowTest is Base {
    // ================================================================ constructor
    function test_Constructor_SetsParties() public view {
        assertEq(escrow.buyer(), buyer);
        assertEq(escrow.seller(), seller);
        assertEq(escrow.arbiter(), arbiter);
        assertEq(escrow.amount(), AMOUNT);
        assertEq(escrow.disputeTimeout(), TIMEOUT);
        assertEq(uint8(escrow.state()), uint8(Escrow.State.Created));
        assertBalanced();
    }

    function test_Constructor_RejectsZeroAddresses() public {
        vm.expectRevert(Escrow.ZeroAddress.selector);
        new Escrow(address(0), seller, arbiter, AMOUNT, TIMEOUT);
        vm.expectRevert(Escrow.ZeroAddress.selector);
        new Escrow(buyer, address(0), arbiter, AMOUNT, TIMEOUT);
        vm.expectRevert(Escrow.ZeroAddress.selector);
        new Escrow(buyer, seller, address(0), AMOUNT, TIMEOUT);
    }

    function test_Constructor_RejectsRoleOverlap() public {
        vm.expectRevert(Escrow.RoleOverlap.selector);
        new Escrow(buyer, buyer, arbiter, AMOUNT, TIMEOUT);
        vm.expectRevert(Escrow.RoleOverlap.selector);
        new Escrow(buyer, seller, buyer, AMOUNT, TIMEOUT);
        vm.expectRevert(Escrow.RoleOverlap.selector);
        new Escrow(buyer, seller, seller, AMOUNT, TIMEOUT);
    }

    function test_Constructor_RejectsZeroAmountAndTimeout() public {
        vm.expectRevert(Escrow.ZeroAmount.selector);
        new Escrow(buyer, seller, arbiter, 0, TIMEOUT);
        vm.expectRevert(Escrow.ZeroTimeout.selector);
        new Escrow(buyer, seller, arbiter, AMOUNT, 0);
    }

    // ================================================================ Created -> Funded
    function test_Fund() public {
        vm.expectEmit(address(escrow));
        emit Escrow.StateChanged(Escrow.State.Created, Escrow.State.Funded);
        vm.expectEmit(address(escrow));
        emit Escrow.Funded(buyer, AMOUNT);
        _fund();
        assertEq(uint8(escrow.state()), uint8(Escrow.State.Funded));
        assertEq(address(escrow).balance, AMOUNT);
        assertEq(escrow.liabilities(), AMOUNT);
        assertBalanced();
    }

    function test_Fund_RevertsWrongAmount() public {
        vm.prank(buyer);
        vm.expectRevert(abi.encodeWithSelector(Escrow.WrongAmount.selector, AMOUNT - 1, AMOUNT));
        escrow.fund{value: AMOUNT - 1}();
        vm.prank(buyer);
        vm.expectRevert(abi.encodeWithSelector(Escrow.WrongAmount.selector, AMOUNT + 1, AMOUNT));
        escrow.fund{value: AMOUNT + 1}();
        assertBalanced();
    }

    function test_Fund_RevertsNotBuyer() public {
        address[3] memory who = [seller, arbiter, stranger];
        for (uint256 i; i < who.length; i++) {
            vm.deal(who[i], AMOUNT);
            vm.prank(who[i]);
            vm.expectRevert(_unauth(who[i]));
            escrow.fund{value: AMOUNT}();
        }
    }

    function test_Fund_RevertsRepeatedFunding() public {
        _fund();
        vm.prank(buyer);
        vm.expectRevert(_invalid(Escrow.State.Funded));
        escrow.fund{value: AMOUNT}();
        assertEq(address(escrow).balance, AMOUNT);
        assertBalanced();
    }

    // ================================================================ Created -> Cancelled
    function test_Cancel_NeedsBothParties() public {
        vm.prank(buyer);
        escrow.approveCancel();
        assertEq(uint8(escrow.state()), uint8(Escrow.State.Created), "one approval is not enough");
        vm.expectEmit(address(escrow));
        emit Escrow.CancelApproved(seller);
        vm.expectEmit(address(escrow));
        emit Escrow.StateChanged(Escrow.State.Created, Escrow.State.Cancelled);
        vm.prank(seller);
        escrow.approveCancel();
        assertEq(uint8(escrow.state()), uint8(Escrow.State.Cancelled));
        assertTrue(escrow.isTerminal());
        assertBalanced();
    }

    function test_Cancel_SellerFirstAlsoWorks() public {
        vm.prank(seller);
        escrow.approveCancel();
        vm.prank(buyer);
        escrow.approveCancel();
        assertEq(uint8(escrow.state()), uint8(Escrow.State.Cancelled));
    }

    function test_Cancel_RevertsDoubleApproval() public {
        vm.prank(buyer);
        escrow.approveCancel();
        vm.prank(buyer);
        vm.expectRevert(abi.encodeWithSelector(Escrow.AlreadyApproved.selector, buyer));
        escrow.approveCancel();
        vm.prank(seller);
        escrow.approveCancel();
    }

    function test_Cancel_RevertsUnauthorized() public {
        vm.prank(arbiter);
        vm.expectRevert(_unauth(arbiter));
        escrow.approveCancel();
        vm.prank(stranger);
        vm.expectRevert(_unauth(stranger));
        escrow.approveCancel();
    }

    function test_Cancel_RevertsAfterFunding() public {
        _fund();
        vm.prank(buyer);
        vm.expectRevert(_invalid(Escrow.State.Funded));
        escrow.approveCancel();
    }

    function test_Cancelled_CannotBeFunded() public {
        vm.prank(buyer);
        escrow.approveCancel();
        vm.prank(seller);
        escrow.approveCancel();
        vm.prank(buyer);
        vm.expectRevert(_invalid(Escrow.State.Cancelled));
        escrow.fund{value: AMOUNT}();
    }

    // ================================================================ Funded -> Released
    function test_Release_CreditsSeller() public {
        _fund();
        vm.expectEmit(address(escrow));
        emit Escrow.StateChanged(Escrow.State.Funded, Escrow.State.Released);
        vm.expectEmit(address(escrow));
        emit Escrow.Released(buyer);
        vm.expectEmit(address(escrow));
        emit Escrow.Credited(seller, AMOUNT);
        vm.prank(buyer);
        escrow.release();
        assertEq(uint8(escrow.state()), uint8(Escrow.State.Released));
        assertEq(escrow.credits(seller), AMOUNT);
        assertEq(seller.balance, 1 ether, "pull payment: nothing pushed yet");
        assertBalanced();
    }

    function test_Release_RevertsNotBuyer() public {
        _fund();
        address[3] memory who = [seller, arbiter, stranger];
        for (uint256 i; i < who.length; i++) {
            vm.prank(who[i]);
            vm.expectRevert(_unauth(who[i]));
            escrow.release();
        }
    }

    function test_Release_RevertsInCreatedAndDisputed() public {
        vm.prank(buyer);
        vm.expectRevert(_invalid(Escrow.State.Created));
        escrow.release();
        _dispute(seller);
        vm.prank(buyer);
        vm.expectRevert(_invalid(Escrow.State.Disputed));
        escrow.release();
    }

    // ================================================================ Funded -> Disputed
    function test_Dispute_ByBuyerOrSeller() public {
        _dispute(buyer);
        assertEq(uint8(escrow.state()), uint8(Escrow.State.Disputed));
        assertEq(escrow.disputedAt(), block.timestamp);
        assertEq(escrow.disputeDeadline(), block.timestamp + TIMEOUT);
        assertBalanced();

        setUp();
        vm.prank(buyer);
        escrow.fund{value: AMOUNT}();
        vm.expectEmit(address(escrow));
        emit Escrow.DisputeRaised(seller);
        vm.prank(seller);
        escrow.raiseDispute();
    }

    function test_Dispute_RevertsUnauthorizedOrWrongState() public {
        vm.prank(buyer);
        vm.expectRevert(_invalid(Escrow.State.Created));
        escrow.raiseDispute();
        _fund();
        vm.prank(arbiter);
        vm.expectRevert(_unauth(arbiter));
        escrow.raiseDispute();
        vm.prank(stranger);
        vm.expectRevert(_unauth(stranger));
        escrow.raiseDispute();
        vm.prank(seller);
        escrow.raiseDispute();
        vm.prank(buyer);
        vm.expectRevert(_invalid(Escrow.State.Disputed));
        escrow.raiseDispute();
    }

    // ================================================================ Disputed -> Resolved
    function test_Resolve_ToSeller() public {
        _dispute(buyer);
        vm.expectEmit(address(escrow));
        emit Escrow.DisputeResolved(arbiter, true);
        vm.prank(arbiter);
        escrow.resolve(true);
        assertEq(uint8(escrow.state()), uint8(Escrow.State.ResolvedToSeller));
        assertEq(escrow.credits(seller), AMOUNT);
        assertEq(escrow.credits(buyer), 0);
        assertBalanced();
    }

    function test_Resolve_ToBuyer() public {
        _dispute(seller);
        vm.prank(arbiter);
        escrow.resolve(false);
        assertEq(uint8(escrow.state()), uint8(Escrow.State.ResolvedToBuyer));
        assertEq(escrow.credits(buyer), AMOUNT);
        assertBalanced();
    }

    function test_Resolve_RevertsNotArbiterOrNotDisputed() public {
        _fund();
        vm.prank(arbiter);
        vm.expectRevert(_invalid(Escrow.State.Funded));
        escrow.resolve(true);
        vm.prank(buyer);
        escrow.raiseDispute();
        address[3] memory who = [buyer, seller, stranger];
        for (uint256 i; i < who.length; i++) {
            vm.prank(who[i]);
            vm.expectRevert(_unauth(who[i]));
            escrow.resolve(true);
        }
    }

    function test_Resolve_OnlyOnce() public {
        _dispute(buyer);
        vm.prank(arbiter);
        escrow.resolve(true);
        vm.prank(arbiter);
        vm.expectRevert(_invalid(Escrow.State.ResolvedToSeller));
        escrow.resolve(false);
    }

    // ================================================================ dispute timeout (no locked funds)
    function test_Timeout_RevertsBeforeDeadline() public {
        _dispute(seller);
        uint256 deadline = escrow.disputeDeadline();
        vm.warp(deadline - 1);
        vm.prank(buyer);
        vm.expectRevert(abi.encodeWithSelector(Escrow.DisputeNotExpired.selector, deadline));
        escrow.resolveAfterTimeout();
    }

    function test_Timeout_WorksAtAndAfterDeadline() public {
        _dispute(seller);
        vm.warp(escrow.disputeDeadline()); // exactly at the deadline (>=, not ==)
        vm.prank(seller);
        escrow.resolveAfterTimeout();
        assertEq(uint8(escrow.state()), uint8(Escrow.State.ResolvedToBuyer));
        assertEq(escrow.credits(buyer), AMOUNT);
        assertBalanced();
    }

    function test_Timeout_RevertsForArbiterOrStranger() public {
        _dispute(seller);
        vm.warp(escrow.disputeDeadline() + 1);
        vm.prank(arbiter);
        vm.expectRevert(_unauth(arbiter));
        escrow.resolveAfterTimeout();
        vm.prank(stranger);
        vm.expectRevert(_unauth(stranger));
        escrow.resolveAfterTimeout();
    }

    function test_Timeout_ArbiterCannotResolveAfterwards() public {
        _dispute(seller);
        vm.warp(escrow.disputeDeadline() + 1 days);
        vm.prank(buyer);
        escrow.resolveAfterTimeout();
        vm.prank(arbiter);
        vm.expectRevert(_invalid(Escrow.State.ResolvedToBuyer));
        escrow.resolve(true);
    }

    // ================================================================ withdrawals (pull payments)
    function test_Withdraw_PaysPayeeOnce() public {
        _fund();
        vm.prank(buyer);
        escrow.release();
        vm.expectEmit(address(escrow));
        emit Escrow.Withdrawn(seller, seller, AMOUNT);
        vm.prank(seller);
        escrow.withdraw();
        assertEq(seller.balance, 2 ether);
        assertEq(address(escrow).balance, 0);
        assertEq(escrow.liabilities(), 0);
        vm.prank(seller);
        vm.expectRevert(Escrow.NothingToWithdraw.selector);
        escrow.withdraw(); // terminal state cannot pay twice
        assertBalanced();
    }

    function test_Withdraw_RevertsForNonPayees() public {
        _fund();
        vm.prank(buyer);
        escrow.release();
        address[3] memory who = [buyer, arbiter, stranger];
        for (uint256 i; i < who.length; i++) {
            vm.prank(who[i]);
            vm.expectRevert(Escrow.NothingToWithdraw.selector);
            escrow.withdraw();
        }
        assertEq(escrow.credits(seller), AMOUNT);
    }

    function test_WithdrawTo_OtherAddress() public {
        _dispute(buyer);
        vm.prank(arbiter);
        escrow.resolve(false);
        address payable wallet = payable(makeAddr("buyerColdWallet"));
        vm.prank(buyer);
        escrow.withdrawTo(wallet);
        assertEq(wallet.balance, AMOUNT);
        assertBalanced();
    }

    function test_WithdrawTo_RevertsZero() public {
        vm.prank(buyer);
        vm.expectRevert(Escrow.ZeroAddress.selector);
        escrow.withdrawTo(payable(address(0)));
    }

    function test_StrangerCannotRedirectFunds() public {
        _fund();
        vm.prank(buyer);
        escrow.release();
        vm.prank(stranger);
        vm.expectRevert(Escrow.NothingToWithdraw.selector);
        escrow.withdrawTo(payable(stranger));
        assertEq(escrow.credits(seller), AMOUNT);
    }

    // ================================================================ terminal states are final
    function _assertFrozen() internal {
        Escrow.State s = escrow.state();
        assertTrue(escrow.isTerminal());
        vm.startPrank(buyer);
        vm.expectRevert(_invalid(s));
        escrow.fund{value: AMOUNT}();
        vm.expectRevert(_invalid(s));
        escrow.approveCancel();
        vm.expectRevert(_invalid(s));
        escrow.release();
        vm.expectRevert(_invalid(s));
        escrow.raiseDispute();
        vm.expectRevert(_invalid(s));
        escrow.resolveAfterTimeout();
        vm.expectRevert(_invalid(s));
        escrow.releaseWithSig(block.timestamp, "");
        vm.stopPrank();
        vm.prank(arbiter);
        vm.expectRevert(_invalid(s));
        escrow.resolve(true);
        assertEq(uint8(escrow.state()), uint8(s));
    }

    function test_Terminal_Released() public {
        _fund();
        vm.prank(buyer);
        escrow.release();
        _assertFrozen();
    }

    function test_Terminal_ResolvedToSeller() public {
        _dispute(buyer);
        vm.prank(arbiter);
        escrow.resolve(true);
        _assertFrozen();
    }

    function test_Terminal_ResolvedToBuyer() public {
        _dispute(buyer);
        vm.prank(arbiter);
        escrow.resolve(false);
        _assertFrozen();
    }

    function test_Terminal_Cancelled() public {
        vm.prank(buyer);
        escrow.approveCancel();
        vm.prank(seller);
        escrow.approveCancel();
        _assertFrozen();
    }

    // ================================================================ stray ETH
    function test_DirectEthRejected() public {
        vm.prank(stranger);
        (bool ok, bytes memory ret) = address(escrow).call{value: 1 ether}("");
        assertFalse(ok);
        assertEq(bytes4(ret), Escrow.DirectPaymentRejected.selector);
        vm.prank(stranger);
        (ok,) = address(escrow).call{value: 1 ether}(hex"deadbeef");
        assertFalse(ok);
        assertBalanced();
    }
}
