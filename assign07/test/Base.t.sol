// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Escrow} from "../src/Escrow.sol";

abstract contract Base is Test {
    Escrow internal escrow;
    address internal buyer;
    uint256 internal buyerKey;
    address internal seller = makeAddr("seller");
    address internal arbiter = makeAddr("arbiter");
    address internal stranger = makeAddr("stranger");
    uint256 internal constant AMOUNT = 1 ether;
    uint256 internal constant TIMEOUT = 7 days;

    function setUp() public virtual {
        (buyer, buyerKey) = makeAddrAndKey("buyer");
        escrow = new Escrow(buyer, seller, arbiter, AMOUNT, TIMEOUT);
        vm.deal(buyer, 100 ether);
        vm.deal(seller, 1 ether);
        vm.deal(stranger, 100 ether);
    }

    /// The contract's ETH must always equal what it owes.
    function assertBalanced() internal view {
        assertEq(address(escrow).balance, escrow.liabilities(), "balance != liabilities");
    }

    function _fund() internal {
        vm.prank(buyer);
        escrow.fund{value: AMOUNT}();
    }

    function _dispute(address by) internal {
        _fund();
        vm.prank(by);
        escrow.raiseDispute();
    }

    function _invalid(Escrow.State s) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(Escrow.InvalidState.selector, s);
    }

    function _unauth(address who) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(Escrow.Unauthorized.selector, who);
    }
}
