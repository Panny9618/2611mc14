// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Base} from "./Base.t.sol";
import {Escrow} from "../src/Escrow.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// A payee contract that tries to re-enter withdraw() when it receives ETH.
contract ReentrantPayee {
    Escrow public escrow;
    uint256 public reentryAttempts;
    bool public reentrySucceeded;
    bool public swallow; // if true, swallow the failed re-entry so the outer withdraw can succeed

    function setEscrow(Escrow e, bool swallow_) external {
        escrow = e;
        swallow = swallow_;
    }

    function pull() external {
        escrow.withdraw();
    }

    receive() external payable {
        reentryAttempts++;
        if (reentryAttempts > 3) return;
        if (swallow) {
            try escrow.withdraw() {
                reentrySucceeded = true;
            } catch {}
        } else {
            escrow.withdraw(); // reverts -> whole outer withdraw reverts
        }
    }
}

/// A payee that refuses ETH entirely.
contract RejectingPayee {
    function withdrawFrom(Escrow e) external {
        e.withdraw();
    }

    function withdrawToFrom(Escrow e, address payable to) external {
        e.withdrawTo(to);
    }

    receive() external payable {
        revert("no ETH please");
    }
}

contract EscrowSecurityTest is Base {
    // ================================================================ reentrancy
    function _escrowPaying(address payee) internal returns (Escrow e) {
        e = new Escrow(buyer, payee, arbiter, AMOUNT, TIMEOUT);
        vm.prank(buyer);
        e.fund{value: AMOUNT}();
        vm.prank(buyer);
        e.release();
    }

    function test_Reentrancy_SwallowedReentryGetsNothingExtra() public {
        ReentrantPayee attacker = new ReentrantPayee();
        Escrow e = _escrowPaying(address(attacker));
        // a second, independent escrow also holds ETH that must stay safe
        Escrow other = _escrowPaying(seller);
        attacker.setEscrow(e, true);
        attacker.pull();
        assertEq(address(attacker).balance, AMOUNT, "paid exactly once");
        assertFalse(attacker.reentrySucceeded());
        assertEq(attacker.reentryAttempts(), 1);
        assertEq(address(e).balance, 0);
        assertEq(e.liabilities(), 0);
        assertEq(address(other).balance, AMOUNT);
    }

    function test_Reentrancy_RevertingReentryRestoresCredit() public {
        ReentrantPayee attacker = new ReentrantPayee();
        Escrow e = _escrowPaying(address(attacker));
        attacker.setEscrow(e, false);
        vm.expectRevert(Escrow.TransferFailed.selector);
        attacker.pull();
        assertEq(e.credits(address(attacker)), AMOUNT, "credit restored, nothing lost");
        assertEq(address(e).balance, AMOUNT);
        assertEq(e.liabilities(), AMOUNT);
    }

    function test_RejectingPayee_CanUseWithdrawTo() public {
        RejectingPayee payee = new RejectingPayee();
        Escrow e = _escrowPaying(address(payee));
        vm.expectRevert(Escrow.TransferFailed.selector);
        payee.withdrawFrom(e);
        assertEq(e.credits(address(payee)), AMOUNT); // not lost
        address payable wallet = payable(makeAddr("wallet"));
        payee.withdrawToFrom(e, wallet);
        assertEq(wallet.balance, AMOUNT);
        assertEq(address(e).balance, 0);
    }

    // ================================================================ EIP-712 signed release
    function _sig(uint256 key, Escrow e, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        bytes32 structHash = keccak256(abi.encode(e.RELEASE_TYPEHASH(), nonce, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", e.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_SignedRelease_RelayerPaysGas() public {
        _fund();
        bytes memory sig = _sig(buyerKey, escrow, 0, block.timestamp + 1 hours);
        vm.expectEmit(address(escrow));
        emit Escrow.Released(stranger);
        vm.prank(stranger); // the relayer, not the buyer
        escrow.releaseWithSig(block.timestamp + 1 hours, sig);
        assertEq(uint8(escrow.state()), uint8(Escrow.State.Released));
        assertEq(escrow.credits(seller), AMOUNT);
        assertEq(escrow.credits(stranger), 0, "relayer cannot redirect funds");
        assertEq(escrow.releaseNonce(), 1);
        assertBalanced();
    }

    function test_SignedRelease_RejectsWrongSigner() public {
        _fund();
        (, uint256 sellerKey) = makeAddrAndKey("seller");
        bytes memory sig = _sig(sellerKey, escrow, 0, block.timestamp + 1 hours);
        vm.expectRevert(Escrow.InvalidSignature.selector);
        escrow.releaseWithSig(block.timestamp + 1 hours, sig);
    }

    function test_SignedRelease_RejectsExpired() public {
        _fund();
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sig(buyerKey, escrow, 0, deadline);
        vm.warp(deadline + 1);
        vm.expectRevert(abi.encodeWithSelector(Escrow.SignatureExpired.selector, deadline));
        escrow.releaseWithSig(deadline, sig);
    }

    function test_SignedRelease_RejectsChangedDeadline() public {
        _fund();
        bytes memory sig = _sig(buyerKey, escrow, 0, block.timestamp + 1 hours);
        vm.expectRevert(Escrow.InvalidSignature.selector);
        escrow.releaseWithSig(block.timestamp + 2 hours, sig);
    }

    function test_SignedRelease_NoReplayOnAnotherEscrow() public {
        _fund();
        Escrow twin = new Escrow(buyer, seller, arbiter, AMOUNT, TIMEOUT);
        vm.prank(buyer);
        twin.fund{value: AMOUNT}();
        bytes memory sig = _sig(buyerKey, escrow, 0, block.timestamp + 1 hours);
        escrow.releaseWithSig(block.timestamp + 1 hours, sig);
        vm.expectRevert(Escrow.InvalidSignature.selector); // different verifyingContract in the domain
        twin.releaseWithSig(block.timestamp + 1 hours, sig);
        vm.expectRevert(abi.encodeWithSelector(Escrow.InvalidState.selector, Escrow.State.Released));
        escrow.releaseWithSig(block.timestamp + 1 hours, sig); // same escrow: already released
    }

    function test_SignedRelease_RejectsOtherChain() public {
        _fund();
        bytes memory sig = _sig(buyerKey, escrow, 0, block.timestamp + 1 hours);
        vm.chainId(999);
        vm.expectRevert(Escrow.InvalidSignature.selector);
        escrow.releaseWithSig(block.timestamp + 1 hours, sig);
    }

    function test_SignedRelease_RejectsMalleableHighS() public {
        _fund();
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", escrow.domainSeparator(),
            keccak256(abi.encode(escrow.RELEASE_TYPEHASH(), uint256(0), deadline))));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(buyerKey, digest);
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 highS = bytes32(n - uint256(s)); // the mathematically valid "twin" signature
        bytes memory twin = abi.encodePacked(r, highS, v == 27 ? uint8(28) : uint8(27));
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureS.selector, highS));
        escrow.releaseWithSig(deadline, twin);
        escrow.releaseWithSig(deadline, abi.encodePacked(r, s, v)); // the canonical one still works
        assertEq(uint8(escrow.state()), uint8(Escrow.State.Released));
    }

    function test_SignedRelease_RejectsGarbage() public {
        _fund();
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, 3));
        escrow.releaseWithSig(block.timestamp, hex"010203");
    }
}
