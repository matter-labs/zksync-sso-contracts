// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { TransparentUpgradeableProxy } from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import { UpgradeableBeacon } from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import { Script } from "forge-std/Script.sol";

import { MSAFactory } from "src/MSAFactory.sol";
import { EOAKeyValidator } from "src/modules/EOAKeyValidator.sol";
import { SessionKeyValidator } from "src/modules/SessionKeyValidator.sol";
import { WebAuthnValidator } from "src/modules/WebAuthnValidator.sol";
import { ModularSmartAccount } from "src/ModularSmartAccount.sol";

import { console } from "forge-std/console.sol";

contract Deploy is Script {
    function run() public {
        address owner = msg.sender;
        address[] memory defaultModules = new address[](3);

        vm.startBroadcast();

        defaultModules[0] = address(new TransparentUpgradeableProxy(address(new EOAKeyValidator()), owner, ""));
        defaultModules[1] = address(new TransparentUpgradeableProxy(address(new SessionKeyValidator()), owner, ""));
        defaultModules[2] = address(new TransparentUpgradeableProxy(address(new WebAuthnValidator()), owner, ""));

        address accountImpl = address(new ModularSmartAccount());
        address beacon = address(new UpgradeableBeacon(accountImpl, owner));
        address factory = address(new TransparentUpgradeableProxy(address(new MSAFactory(beacon)), owner, ""));

        vm.stopBroadcast();

        console.log("EOAKeyValidator:", defaultModules[0]);
        console.log("SessionKeyValidator:", defaultModules[1]);
        console.log("WebAuthnValidator:", defaultModules[2]);
        console.log("ModularSmartAccount implementation:", accountImpl);
        console.log("UpgradeableBeacon:", beacon);
        console.log("MSAFactory:", factory);
    }
}
