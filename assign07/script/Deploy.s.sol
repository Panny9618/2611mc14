// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {Escrow} from "../src/Escrow.sol";

/// Deploy one Escrow.
///   forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast --private-key $DEPLOYER_PK
/// Env: BUYER, SELLER, ARBITER (addresses), AMOUNT_WEI, TIMEOUT_SECONDS, LABEL (output file name).
/// Refuses to run on any chain other than a local Anvil (31337) unless ALLOW_NON_LOCAL=true.
contract Deploy is Script {
    function run() external returns (Escrow escrow) {
        if (block.chainid != 31337 && !vm.envOr("ALLOW_NON_LOCAL", false)) {
            revert("refusing to deploy outside local Anvil (chain id 31337)");
        }
        address buyer = vm.envAddress("BUYER");
        address seller = vm.envAddress("SELLER");
        address arbiter = vm.envAddress("ARBITER");
        uint256 amount = vm.envOr("AMOUNT_WEI", uint256(1 ether));
        uint256 timeout = vm.envOr("TIMEOUT_SECONDS", uint256(7 days));
        string memory label = vm.envOr("LABEL", string("escrow"));

        vm.startBroadcast();
        escrow = new Escrow(buyer, seller, arbiter, amount, timeout);
        vm.stopBroadcast();

        console.log("Escrow deployed at", address(escrow));
        string memory json = vm.serializeAddress(label, "address", address(escrow));
        json = vm.serializeAddress(label, "buyer", buyer);
        json = vm.serializeAddress(label, "seller", seller);
        json = vm.serializeAddress(label, "arbiter", arbiter);
        json = vm.serializeUint(label, "amount", amount);
        json = vm.serializeUint(label, "chainId", block.chainid);
        vm.writeJson(json, string.concat("deployments/", label, ".json"));
    }
}
