// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { LibString } from "solady/utils/LibString.sol";

import { IERC7579Account } from "src/interfaces/IERC7579Account.sol";
import { ExecutionLib } from "src/libraries/ExecutionLib.sol";
import { Execution } from "src/interfaces/IERC7579Account.sol";
import "src/libraries/ModeLib.sol";

import { MockTarget } from "./mocks/MockTarget.sol";
import { MockDelegateTarget } from "./mocks/MockDelegateTarget.sol";
import { MockERC1271Caller, MockMessage } from "./mocks/MockERC1271Caller.sol";
import { MockPaymaster } from "./mocks/MockPaymaster.sol";
import { MSATest } from "./MSATest.sol";

contract BasicTest is MSATest {
    MockTarget public target;
    MockDelegateTarget public delegateTarget;
    MockERC1271Caller public erc1271Caller;
    MockPaymaster public paymaster;

    function setUp() public override {
        super.setUp();

        target = new MockTarget();
        delegateTarget = new MockDelegateTarget();
        erc1271Caller = new MockERC1271Caller();
        paymaster = new MockPaymaster();
    }

    function test_transfer() public {
        address recipient = makeAddr("recipient");
        bytes memory execution = ExecutionLib.encodeSingle(recipient, 1 ether, "");
        bytes memory callData = abi.encodeCall(IERC7579Account.execute, (ModeLib.encodeSimpleSingle(), execution));
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeSignedUserOp(callData, owner.key, address(eoaValidator));

        entryPoint.handleOps(userOps, bundler);
        vm.assertEq(recipient.balance, 1 ether, "Value not transferred via simple call");
    }

    function test_execSingle() public {
        bytes memory execution =
            ExecutionLib.encodeSingle(address(target), 0, abi.encodeCall(MockTarget.setValue, 1337));
        bytes memory callData = abi.encodeCall(IERC7579Account.execute, (ModeLib.encodeSimpleSingle(), execution));
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeSignedUserOp(callData, owner.key, address(eoaValidator));

        entryPoint.handleOps(userOps, bundler);
        vm.assertEq(target.value(), 1337, "State not changed via simple call");
    }

    function test_execBatch() public {
        bytes memory setValueOnTarget = abi.encodeCall(MockTarget.setValue, 1337);
        address target2 = makeAddr("target2");
        uint256 target2Amount = 1 wei;

        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({ target: address(target), value: 0, callData: setValueOnTarget });
        executions[1] = Execution({ target: target2, value: target2Amount, callData: "" });

        bytes memory callData =
            abi.encodeCall(IERC7579Account.execute, (ModeLib.encodeSimpleBatch(), ExecutionLib.encodeBatch(executions)));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeSignedUserOp(callData, owner.key, address(eoaValidator));

        entryPoint.handleOps(userOps, bundler);
        vm.assertEq(target.value(), 1337, "State not changed via batch call");
        vm.assertEq(target2.balance, target2Amount, "Value not transferred via batch call");
    }

    function test_delegateCall() public {
        address valueTarget = makeAddr("valueTarget");
        uint256 value = 1 ether;
        bytes memory sendValue = abi.encodeWithSelector(MockDelegateTarget.sendValue.selector, valueTarget, value);

        bytes memory callData = abi.encodeCall(
            IERC7579Account.execute,
            (
                ModeLib.encode(CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, MODE_DEFAULT, ModePayload.wrap(0x00)),
                abi.encodePacked(address(delegateTarget), sendValue)
            )
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeSignedUserOp(callData, owner.key, address(eoaValidator));

        entryPoint.handleOps(userOps, bundler);
        vm.assertEq(valueTarget.balance, value, "Value not transferred via delegatecall");
    }

    function test_signatureTypedData() public view {
        MockMessage memory mockMessage = MockMessage({ message: "Hello, world!", value: 42 });
        bytes memory contentsDescription = "MockMessage(string message,uint256 value)";

        bytes32 structHash = keccak256(
            abi.encode(keccak256(contentsDescription), keccak256(bytes(mockMessage.message)), mockMessage.value)
        );

        (, string memory name, string memory version, uint256 chainId, address verifyingContract, bytes32 salt,) =
            account.eip712Domain();

        bytes32 typedDataSignTypehash = keccak256(
            abi.encodePacked(
                "TypedDataSign(",
                "MockMessage contents,",
                "string name,",
                "string version,",
                "uint256 chainId,",
                "address verifyingContract,",
                "bytes32 salt)",
                contentsDescription
            )
        );

        bytes32 wrapperStructHash = keccak256(
            abi.encode(
                typedDataSignTypehash,
                structHash,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                uint256(chainId),
                uint256(uint160(verifyingContract)),
                bytes32(salt)
            )
        );

        bytes32 finalHash = keccak256(abi.encodePacked(hex"1901", erc1271Caller.domainSeparator(), wrapperStructHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.key, finalHash);
        bytes memory originalSignature = abi.encodePacked(r, s, v);

        bytes memory signature = abi.encodePacked(
            address(eoaValidator),
            originalSignature,
            erc1271Caller.domainSeparator(),
            structHash,
            contentsDescription,
            uint16(contentsDescription.length)
        );

        bool success = erc1271Caller.validateStruct(mockMessage, address(account), signature);
        vm.assertTrue(success, "Signature validation failed");
    }

    function test_signaturePersonalSign() public view {
        bytes memory message = "Hello, world!";
        bytes32 messageHash =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", LibString.toString(message.length), message));

        bytes32 finalHash = keccak256(
            abi.encodePacked(
                hex"1901",
                account.domainSeparator(),
                keccak256(abi.encode(keccak256("PersonalSign(bytes prefixed)"), messageHash))
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.key, finalHash);
        bytes memory originalSignature = abi.encodePacked(r, s, v);
        bytes memory signature = abi.encodePacked(address(eoaValidator), originalSignature);

        bytes4 magic = account.isValidSignature(messageHash, signature);
        vm.assertEq(magic, account.isValidSignature.selector, "Signature verification failed");
    }

    function test_signatureTypedDataUnnested() public {
        // This test is skipped because solady's implementation of ERC1271
        // does some weird checks with gas limit for RPC calls
        vm.skip(true);

        MockMessage memory mockMessage = MockMessage({ message: "Hello, world!", value: 42 });

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("MockMessage(string message,uint256 value)"),
                keccak256(bytes(mockMessage.message)),
                mockMessage.value
            )
        );

        bytes32 finalHash = keccak256(abi.encodePacked(hex"1901", erc1271Caller.domainSeparator(), structHash));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.key, finalHash);
        bytes memory originalSignature = abi.encodePacked(r, s, v);

        bytes memory signature = abi.encodePacked(address(eoaValidator), originalSignature);

        bool success = erc1271Caller.validateStruct(mockMessage, address(account), signature);
        vm.assertTrue(success, "Signature validation failed");
    }

    function test_paymaster() public {
        vm.deal(address(account), 0);

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        bytes memory callData = ExecutionLib.encodeSingle(address(target), 0, abi.encodeCall(MockTarget.setValue, 1337));
        userOps[0] = makeUserOp(abi.encodeCall(IERC7579Account.execute, (ModeLib.encodeSimpleSingle(), callData)));
        userOps[0].paymasterAndData = abi.encodePacked(address(paymaster), uint128(2e6), uint128(2e6));
        signUserOp(userOps[0], owner.key, address(eoaValidator));

        paymaster.deposit{ value: 0.5 ether }();

        entryPoint.handleOps(userOps, bundler);
        vm.assertEq(target.value(), 1337, "State not changed via simple call");
    }
}
