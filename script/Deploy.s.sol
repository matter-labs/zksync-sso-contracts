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

contract Deploy is Script {
    function run() public {
        // TODO: use correct owner address.
        address owner = address(0x1234);
        // TODO: use correct EOA account owner address.
        address[] memory eoaOwners = new address[](1);
        eoaOwners[0] = address(0x1234);

        address[] memory defaultModules = new address[](3);
        defaultModules[0] = address(new TransparentUpgradeableProxy(address(new EOAKeyValidator()), owner, ""));
        defaultModules[1] = address(new TransparentUpgradeableProxy(address(new SessionKeyValidator()), owner, ""));
        defaultModules[2] = address(new TransparentUpgradeableProxy(address(new WebAuthnValidator()), owner, ""));

        bytes[] memory initData = new bytes[](3);
        initData[0] = abi.encode(eoaOwners);

        address accountImpl = address(new ModularSmartAccount());
        address beacon = address(new UpgradeableBeacon(accountImpl, owner));
        MSAFactory factory = MSAFactory(address(new TransparentUpgradeableProxy(address(new MSAFactory(beacon)), owner, "")));

        // TODO: use correct owner address.
        // factory.transferOwnership(address(0x1234));
    }
}
