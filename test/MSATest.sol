// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import { EntryPoint } from "account-abstraction/core/EntryPoint.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { UpgradeableBeacon } from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import { Test } from "forge-std/Test.sol";
import { LibERC7579 } from "solady/accounts/LibERC7579.sol";

import { ModularSmartAccount } from "src/ModularSmartAccount.sol";
import { MSAFactory } from "src/MSAFactory.sol";
import { EOAKeyValidator } from "src/modules/EOAKeyValidator.sol";
import { IMSA } from "src/interfaces/IMSA.sol";
import { Execution } from "src/interfaces/IERC7579Account.sol";

contract MSATest is Test {
    EntryPoint public entryPoint;
    ModularSmartAccount public account;
    MSAFactory public factory;
    EOAKeyValidator public eoaValidator;
    Account public owner;
    address payable bundler;

    bytes32 public constant SIMPLE_SINGLE_MODE = bytes32(0);

    function setUp() public virtual {
        bundler = payable(makeAddr("bundler"));
        owner = makeAccount("owner");

        ModularSmartAccount accountImplementation = new ModularSmartAccount();

        address entryPointAddress = accountImplementation.ENTRY_POINT();
        vm.etch(entryPointAddress, address(new EntryPoint()).code);
        entryPoint = EntryPoint(payable(entryPointAddress));

        eoaValidator = new EOAKeyValidator();
        address[] memory modules = new address[](1);
        modules[0] = address(eoaValidator);

        address[] memory owners = new address[](1);
        owners[0] = owner.addr;

        bytes[] memory initData = new bytes[](1);
        initData[0] = abi.encode(owners);

        UpgradeableBeacon beacon = new UpgradeableBeacon(address(accountImplementation), address(this));
        factory = new MSAFactory(address(beacon));

        bytes memory data = abi.encodeCall(IMSA.initializeAccount, (modules, initData));
        account = ModularSmartAccount(payable(factory.deployAccount(keccak256("my-account-id"), data)));
        vm.deal(address(account), 2 ether);
    }

    function makeUserOp(bytes memory callData) public view returns (PackedUserOperation[] memory userOps) {
        userOps = new PackedUserOperation[](1);
        userOps[0] = PackedUserOperation({
            sender: address(account),
            nonce: entryPoint.getNonce(address(account), 0),
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            preVerificationGas: 2e6,
            gasFees: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            paymasterAndData: "",
            signature: ""
        });
    }

    function makeSignedUserOp(bytes memory callData, uint256 key, address validator)
        public
        view
        returns (PackedUserOperation[] memory userOps)
    {
        userOps = makeUserOp(callData);
        signUserOp(userOps[0], key, validator);
    }

    function signUserOp(PackedUserOperation memory userOp, uint256 key, address validator) public view {
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, userOpHash);
        userOp.signature = abi.encodePacked(validator, r, s, v);
    }

    function encodeCall(address target, uint256 value, bytes memory data) public pure returns (bytes memory) {
        return abi.encodeCall(ModularSmartAccount.execute, (SIMPLE_SINGLE_MODE, abi.encodePacked(target, value, data)));
    }
}
