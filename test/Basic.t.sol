// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Test } from "forge-std/Test.sol";
import { EntryPoint } from "account-abstraction/core/EntryPoint.sol";
import { ModularSmartAccount } from "../src/ModularSmartAccount.sol";
import { MSAProxy } from "../src/utils/MSAProxy.sol";
import { EOAKeyValidator } from "../src/modules/EOAKeyValidator.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { IMSA } from "../src/interfaces/IMSA.sol";
import { ExecutionLib } from "../src/libraries/ExecutionLib.sol";
import { ModeLib } from "../src/libraries/ModeLib.sol";

contract Basic is Test {
    EntryPoint public entryPoint;
    ModularSmartAccount public account;
    IMSA public accountProxy;
    EOAKeyValidator public eoaValidator;
    Account public owner;

    function setUp() public {
        owner = makeAccount("owner");
        address[] memory owners = new address[](1);
        owners[0] = owner.addr;

        entryPoint = new EntryPoint();
        account = new ModularSmartAccount();
        eoaValidator = new EOAKeyValidator();
        accountProxy = IMSA(
            address(
                new MSAProxy(
                    address(account),
                    abi.encodeCall(
                        ModularSmartAccount.initializeAccount,
                        (address(entryPoint), address(eoaValidator), abi.encode(owners))
                    )
                )
            )
        );
    }

    function makeUserOp(
        address target,
        uint256 value,
        bytes memory data
    )
        public
        view
        returns (PackedUserOperation memory userOp)
    {
        bytes memory callData = ExecutionLib.encodeSingle(target, value, data);

        userOp = PackedUserOperation({
            sender: address(accountProxy),
            nonce: 0,
            initCode: "",
            callData: abi.encodeCall(ModularSmartAccount.execute, (ModeLib.encodeSimpleSingle(), callData)),
            accountGasLimits: bytes32(uint256((100_000 << 128) | 100_000)),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.key, userOpHash);
        userOp.signature = abi.encode(address(eoaValidator), abi.encodePacked(r, s, v), "");
    }

    function test_Transfer() public {
        vm.deal(address(accountProxy), 10 ether);

        address recipient = makeAddr("recipient");
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeUserOp(recipient, 1 ether, "");

        address bundler = makeAddr("bundler");
        entryPoint.handleOps(userOps, payable(bundler));
        vm.assertEq(recipient.balance, 1 ether);
    }
}
