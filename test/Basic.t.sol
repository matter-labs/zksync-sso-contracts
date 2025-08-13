// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.24;

// NOTE: this contract has to be licensed under the GPL-3.0
// since it uses EntryPoint.sol which is licensed under the same license.
import { EntryPoint } from "account-abstraction/core/EntryPoint.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { Test } from "forge-std/Test.sol";

import { ModularSmartAccount } from "src/ModularSmartAccount.sol";
import { MSAProxy } from "src/utils/MSAProxy.sol";
import { EOAKeyValidator } from "src/modules/EOAKeyValidator.sol";
import { IMSA } from "src/interfaces/IMSA.sol";
import { ExecutionLib } from "../src/libraries/ExecutionLib.sol";
import { Execution } from "src/interfaces/IERC7579Account.sol";
import "src/libraries/ModeLib.sol";
import { MockTarget } from "./mocks/MockTarget.sol";
import { MockDelegateTarget } from "./mocks/MockDelegateTarget.sol";
import { IERC7579Account } from "src/interfaces/IERC7579Account.sol";

contract BasicTest is Test {
    EntryPoint public entryPoint;
    ModularSmartAccount public account;
    IMSA public accountProxy;
    EOAKeyValidator public eoaValidator;
    Account public owner;

    MockTarget public target;
    MockDelegateTarget public delegateTarget;
    address payable bundler;

    function setUp() public {
        bundler = payable(makeAddr("bundler"));
        owner = makeAccount("owner");
        address[] memory owners = new address[](1);
        owners[0] = owner.addr;

        account = new ModularSmartAccount();
        eoaValidator = new EOAKeyValidator();
        target = new MockTarget();
        delegateTarget = new MockDelegateTarget();

        vm.etch(account.ENTRY_POINT(), address(new EntryPoint()).code);
        entryPoint = EntryPoint(payable(account.ENTRY_POINT()));
        accountProxy = IMSA(
            address(
                new MSAProxy(
                    address(account),
                    abi.encodeCall(IMSA.initializeAccount, (address(eoaValidator), abi.encode(owners)))
                )
            )
        );
        vm.deal(address(accountProxy), 2 ether);
    }

    function makeUserOp(
        bytes memory callData
    )
        public
        view
        returns (PackedUserOperation memory userOp)
    {
        userOp = PackedUserOperation({
            sender: address(accountProxy),
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            preVerificationGas: 2e6,
            gasFees: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.key, userOpHash);
        userOp.signature = abi.encode(address(eoaValidator), abi.encodePacked(r, s, v), "");
    }

    function test_transfer() public {
        address recipient = makeAddr("recipient");
        bytes memory execution = ExecutionLib.encodeSingle(recipient, 1 ether, "");
        bytes memory callData = abi.encodeCall(IERC7579Account.execute, (ModeLib.encodeSimpleSingle(), execution));
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeUserOp(callData);

        entryPoint.handleOps(userOps, bundler);
        vm.assertEq(recipient.balance, 1 ether);
    }

    function test_execSingle() public {
        bytes memory execution = ExecutionLib.encodeSingle(address(target), 0, abi.encodeCall(MockTarget.setValue, 1337));
        bytes memory callData = abi.encodeCall(IERC7579Account.execute, (ModeLib.encodeSimpleSingle(), execution));
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeUserOp(callData);

        entryPoint.handleOps(userOps, bundler);
        vm.assertEq(target.value(), 1337);
    }

    function test_execBatch() public {
        bytes memory setValueOnTarget = abi.encodeCall(MockTarget.setValue, 1337);
        address target2 = makeAddr("target2");
        uint256 target2Amount = 1 wei;

        // Create the executions
        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({ target: address(target), value: 0, callData: setValueOnTarget });
        executions[1] = Execution({ target: target2, value: target2Amount, callData: "" });

        // Encode the call into the calldata for the userOp
        bytes memory callData = abi.encodeCall(
            IERC7579Account.execute,
            (ModeLib.encodeSimpleBatch(), ExecutionLib.encodeBatch(executions))
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeUserOp(callData);

        entryPoint.handleOps(userOps, bundler);
        vm.assertEq(target.value(), 1337);
        vm.assertEq(target2.balance, target2Amount);
    }

    function test_delegateCall() public {
        // Create calldata for the account to execute
        address valueTarget = makeAddr("valueTarget");
        uint256 value = 1 ether;
        bytes memory sendValue =
            abi.encodeWithSelector(MockDelegateTarget.sendValue.selector, valueTarget, value);

        // Encode the call into the calldata for the userOp
        bytes memory callData = abi.encodeCall(
            IERC7579Account.execute,
            (
                ModeLib.encode(
                    CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, MODE_DEFAULT, ModePayload.wrap(0x00)
                ),
                abi.encodePacked(address(delegateTarget), sendValue)
            )
        );

        // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeUserOp(callData);

        entryPoint.handleOps(userOps, bundler);
        vm.assertEq(valueTarget.balance, value);
    }
}
