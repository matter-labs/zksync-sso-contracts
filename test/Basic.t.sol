// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { LibString } from "solady/utils/LibString.sol";
import { LibERC7579 } from "solady/accounts/LibERC7579.sol";

import { IERC7579Account } from "src/interfaces/IERC7579Account.sol";
import { Execution } from "src/interfaces/IERC7579Account.sol";
import { ExecutionHelper } from "src/core/ExecutionHelper.sol";
import { AccountBase } from "src/core/AccountBase.sol";
import { ModuleManager } from "src/core/ModuleManager.sol";
import { IMSA } from "src/interfaces/IMSA.sol";
import "src/interfaces/IERC7579Module.sol" as ERC7579;

import { MockTarget } from "./mocks/MockTarget.sol";
import { MockDelegateTarget } from "./mocks/MockDelegateTarget.sol";
import { MockERC1271Caller, MockMessage } from "./mocks/MockERC1271Caller.sol";
import { MockPaymaster } from "./mocks/MockPaymaster.sol";
import { MSATest } from "./MSATest.sol";
import { MockHook } from "./mocks/MockHook.sol";

contract BasicTest is MSATest {
    MockTarget public target;
    MockDelegateTarget public delegateTarget;
    MockERC1271Caller public erc1271Caller;
    MockPaymaster public paymaster;
    MockHook public hookModule;

    function setUp() public override {
        super.setUp();

        target = new MockTarget();
        delegateTarget = new MockDelegateTarget();
        erc1271Caller = new MockERC1271Caller();
        paymaster = new MockPaymaster();
        hookModule = new MockHook();
    }

    function test_transfer() public {
        address recipient = makeAddr("recipient");
        bytes memory call = encodeCall(recipient, 1 ether, "");
        PackedUserOperation[] memory userOps = makeSignedUserOp(call);

        entryPoint.handleOps(userOps, bundler);
        vm.assertEq(recipient.balance, 1 ether, "Value not transferred via simple call");
    }

    function test_execSingle() public {
        bytes memory call = encodeCall(address(target), 0, abi.encodeCall(MockTarget.setValue, 1337));
        PackedUserOperation[] memory userOps = makeSignedUserOp(call);

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

        bytes memory call = abi.encodeCall(
            IERC7579Account.execute, (LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, 0, 0, 0), abi.encode(executions))
        );

        PackedUserOperation[] memory userOps = makeSignedUserOp(call);

        entryPoint.handleOps(userOps, bundler);
        vm.assertEq(target.value(), 1337, "State not changed via batch call");
        vm.assertEq(target2.balance, target2Amount, "Value not transferred via batch call");
    }

    function test_delegateCall() public {
        address valueTarget = makeAddr("valueTarget");
        uint256 value = 1 ether;
        bytes memory sendValue = abi.encodeWithSelector(MockDelegateTarget.sendValue.selector, valueTarget, value);

        bytes memory call = abi.encodeCall(
            IERC7579Account.execute,
            (
                LibERC7579.encodeMode(LibERC7579.CALLTYPE_DELEGATECALL, 0, 0, 0),
                abi.encodePacked(address(delegateTarget), sendValue)
            )
        );

        PackedUserOperation[] memory userOps = makeSignedUserOp(call);

        entryPoint.handleOps(userOps, bundler);
        vm.assertEq(valueTarget.balance, value, "Value not transferred via delegatecall");
    }

    function test_tryBatch() public {
        bytes memory setValueOnTarget = abi.encodeCall(MockTarget.setValue, 1337);
        bytes memory justRevert = abi.encodeCall(MockTarget.justRevert, ());
        Execution[] memory executions = new Execution[](2);
        executions[0] = Execution({ target: address(target), value: 0, callData: setValueOnTarget });
        executions[1] = Execution({ target: address(target), value: 0, callData: justRevert });

        bytes memory call = abi.encodeCall(
            IERC7579Account.execute,
            (LibERC7579.encodeMode(LibERC7579.CALLTYPE_BATCH, LibERC7579.EXECTYPE_TRY, 0, 0), abi.encode(executions))
        );

        PackedUserOperation[] memory userOps = makeSignedUserOp(call);

        vm.expectEmit(true, true, true, true);
        emit ExecutionHelper.TryExecuteUnsuccessful(1, abi.encodeWithSignature("Error(string)", "MockTarget: reverted"));
        entryPoint.handleOps(userOps, bundler);

        vm.assertEq(target.value(), 1337, "State not changed via batch call");
    }

    function test_tryDelegateCall() public {
        uint256 value = 0.1 ether;
        bytes memory sendValue = abi.encodeWithSelector(MockDelegateTarget.sendValue.selector, address(target), value);
        bytes memory call = abi.encodeCall(
            IERC7579Account.execute,
            (
                LibERC7579.encodeMode(LibERC7579.CALLTYPE_DELEGATECALL, LibERC7579.EXECTYPE_TRY, 0, 0),
                abi.encodePacked(address(delegateTarget), sendValue)
            )
        );
        PackedUserOperation[] memory userOps = makeSignedUserOp(call);

        vm.expectEmit(true, false, false, false);
        emit ExecutionHelper.TryExecuteUnsuccessful(0, "");
        entryPoint.handleOps(userOps, bundler);

        vm.assertEq(address(target).balance, 0, "Value should not have been transferred");
    }

    function testRevert_executeUserOp_callFailure() public {
        bytes memory call = encodeCall(address(target), 0, abi.encodeCall(MockTarget.justRevert, ()));
        PackedUserOperation[] memory userOps = makeSignedUserOp(call);

        vm.startPrank(address(entryPoint));
        vm.expectRevert(ExecutionHelper.ExecutionFailed.selector);
        account.executeUserOp(userOps[0], bytes32(0));
        vm.stopPrank();
    }

    function testRevert_execute_unsupportedCallType() public {
        bytes32 mode = LibERC7579.encodeMode(bytes1(0x42), LibERC7579.EXECTYPE_DEFAULT, 0, 0);
        bytes memory callData = abi.encodePacked(address(target), uint256(0), abi.encodeCall(MockTarget.setValue, (1)));

        vm.expectRevert(abi.encodeWithSelector(ExecutionHelper.UnsupportedCallType.selector, bytes1(0x42)));
        vm.prank(address(entryPoint));
        account.execute(mode, callData);
    }

    function testRevert_execute_unsupportedExecType() public {
        bytes32 mode = LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, bytes1(0x42), 0, 0);
        bytes memory callData = abi.encodePacked(address(target), uint256(0), abi.encodeCall(MockTarget.setValue, (1)));

        vm.expectRevert(abi.encodeWithSelector(ExecutionHelper.UnsupportedExecType.selector, bytes1(0x42)));
        vm.prank(address(entryPoint));
        account.execute(mode, callData);
    }

    function testRevert_execute_unauthorizedSender() public {
        bytes memory callData = abi.encodePacked(address(target), uint256(0), abi.encodeCall(MockTarget.setValue, (1)));
        bytes32 mode = LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, 0, 0);

        vm.expectRevert(AccountBase.AccountAccessUnauthorized.selector);
        account.execute(mode, callData);
    }

    function testRevert_executeFromExecutor_invalidModule() public {
        bytes32 mode = LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, 0, 0);
        address notExecutor = makeAddr("notExecutor");

        vm.expectRevert(abi.encodeWithSelector(ModuleManager.InvalidModule.selector, notExecutor));
        vm.prank(notExecutor);
        account.executeFromExecutor(mode, "");
    }

    function testRevert_installModuleUnsupportedType() public {
        vm.expectRevert(abi.encodeWithSelector(IMSA.UnsupportedModuleType.selector, ERC7579.MODULE_TYPE_HOOK));
        vm.prank(address(entryPoint));
        account.installModule(ERC7579.MODULE_TYPE_HOOK, address(hookModule), bytes(""));
    }

    function testRevert_uninstallLastValidator() public {
        vm.expectRevert(ModuleManager.CannotRemoveLastValidator.selector);
        vm.prank(address(entryPoint));
        account.uninstallModule(ERC7579.MODULE_TYPE_VALIDATOR, address(eoaValidator), bytes(""));
    }

    function testRevert_executeUserOp_unauthorizedCaller() public {
        bytes memory call = encodeCall(address(target), 0, abi.encodeCall(MockTarget.setValue, 1));
        PackedUserOperation[] memory userOps = makeSignedUserOp(call);

        vm.expectRevert(AccountBase.AccountAccessUnauthorized.selector);
        account.executeUserOp(userOps[0], bytes32(0));
    }

    function test_supportedStuff() public view {
        bytes1[3] memory callTypes =
            [LibERC7579.CALLTYPE_SINGLE, LibERC7579.CALLTYPE_DELEGATECALL, LibERC7579.CALLTYPE_BATCH];
        bytes1[2] memory execTypes = [LibERC7579.EXECTYPE_TRY, LibERC7579.EXECTYPE_DEFAULT];

        for (uint256 i; i < callTypes.length; i++) {
            for (uint256 j; j < execTypes.length; j++) {
                bytes32 mode = LibERC7579.encodeMode(callTypes[i], execTypes[j], 0, 0);
                vm.assertTrue(account.supportsExecutionMode(mode), "Mode should be supported");
            }
        }
        vm.assertFalse(
            account.supportsExecutionMode(LibERC7579.encodeMode(0x42, 0x18, 0, 0)), "Mode should not be supported"
        );

        uint256[3] memory moduleTypes =
            [ERC7579.MODULE_TYPE_EXECUTOR, ERC7579.MODULE_TYPE_VALIDATOR, ERC7579.MODULE_TYPE_FALLBACK];
        for (uint256 i; i < moduleTypes.length; i++) {
            vm.assertTrue(account.supportsModule(moduleTypes[i]), "Module type should be supported");
        }
        vm.assertFalse(account.supportsModule(ERC7579.MODULE_TYPE_HOOK), "Module type should not be supported");
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

        bytes memory call = encodeCall(address(target), 0, abi.encodeCall(MockTarget.setValue, 1337));
        PackedUserOperation[] memory userOps = makeUserOp(call);
        userOps[0].paymasterAndData = abi.encodePacked(address(paymaster), uint128(2e6), uint128(2e6));
        signUserOp(userOps[0], owner.key, address(eoaValidator));

        paymaster.deposit{ value: 0.5 ether }();

        entryPoint.handleOps(userOps, bundler);
        vm.assertEq(target.value(), 1337, "State not changed via simple call");
    }
}
