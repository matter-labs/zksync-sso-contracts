// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { TransparentUpgradeableProxy } from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import { UpgradeableBeacon } from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import { Script } from "forge-std/Script.sol";
import { console } from "forge-std/console.sol";

import { MSAFactory } from "src/MSAFactory.sol";
import { EOAKeyValidator } from "src/modules/EOAKeyValidator.sol";
import { SessionKeyValidator } from "src/modules/SessionKeyValidator.sol";
import { WebAuthnValidator } from "src/modules/WebAuthnValidator.sol";
import { GuardianExecutor } from "src/modules/GuardianExecutor.sol";
import { ModularSmartAccount } from "src/ModularSmartAccount.sol";

contract Deploy is Script {
    function makeProxy(address impl) internal returns (address) {
        return address(new TransparentUpgradeableProxy(impl, msg.sender, ""));
    }

    function deployFactory() internal returns (address factory, address[] memory defaultModules) {
        vm.startBroadcast();

        defaultModules = new address[](4);
        defaultModules[0] = makeProxy(address(new EOAKeyValidator()));
        defaultModules[1] = makeProxy(address(new SessionKeyValidator()));
        defaultModules[2] = makeProxy(address(new WebAuthnValidator()));
        defaultModules[3] = address(
            new TransparentUpgradeableProxy(
                address(new GuardianExecutor()), 
                msg.sender,
                abi.encodeWithSelector(GuardianExecutor.initialize.selector, defaultModules[2], defaultModules[0])
            )
        );

        address accountImpl = address(new ModularSmartAccount());
        address beacon = address(new UpgradeableBeacon(accountImpl, msg.sender));
        factory = makeProxy(address(new MSAFactory(beacon)));

        vm.stopBroadcast();

        console.log("EOAKeyValidator:", defaultModules[0]);
        console.log("SessionKeyValidator:", defaultModules[1]);
        console.log("WebAuthnValidator:", defaultModules[2]);
        console.log("GuardianExecutor:", defaultModules[3]);
        console.log("ModularSmartAccount implementation:", accountImpl);
        console.log("UpgradeableBeacon:", beacon);
        console.log("MSAFactory:", factory);
    }

    function run() public {
        deployFactory();
    }

    /// @dev This function is used for tests only
    function deployAccount(address factory, address[] memory modules) public {
        bytes[] memory initData = new bytes[](4);
        address[] memory accountOwners = new address[](1);
        accountOwners[0] = msg.sender;
        initData[0] = abi.encode(accountOwners);
        bytes memory data = abi.encodeCall(ModularSmartAccount.initializeAccount, (modules, initData));

        vm.startBroadcast();

        address account = MSAFactory(factory).deployAccount(keccak256("my-account-id"), data);
        payable(account).transfer(1 ether);

        vm.stopBroadcast();

        console.log("Initialized account:", account);
    }

    function deployAll() public {
        (address factoryAddr, address[] memory modules) = deployFactory();
        deployAccount(factoryAddr, modules);
    }
}
