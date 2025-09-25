// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";

import { ModularSmartAccount } from "src/ModularSmartAccount.sol";
import { MSAFactory } from "src/MSAFactory.sol";
import { EOAKeyValidator } from "src/modules/EOAKeyValidator.sol";
import { SessionKeyValidator } from "src/modules/SessionKeyValidator.sol";
import { IMSA } from "src/interfaces/IMSA.sol";
import { ExecutionLib } from "src/libraries/ExecutionLib.sol";
import { ModeLib } from "src/libraries/ModeLib.sol";
import { MODULE_TYPE_VALIDATOR } from "src/interfaces/IERC7579Module.sol";
import { IERC7579Account } from "src/interfaces/IERC7579Account.sol";
import { SessionLib } from "src/libraries/SessionLib.sol";

import { MSATest } from "./MSATest.sol";
import { MockERC20 } from "./mocks/MockERC20.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract SessionsTest is MSATest {
    SessionKeyValidator public sessionKeyValidator;
    Account public sessionOwner;
    address recipient;
    MockERC20 erc20;

    SessionLib.SessionSpec public spec;

    function setUp() public override {
        super.setUp();

        recipient = makeAddr("sessionRecipient");
        sessionOwner = makeAccount("sessionOwner");
        sessionKeyValidator = new SessionKeyValidator();
        erc20 = new MockERC20(address(account));
    }

    function test_installValidator() public {
        bytes memory data =
            abi.encodeCall(ModularSmartAccount.installModule, (MODULE_TYPE_VALIDATOR, address(sessionKeyValidator), ""));
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeSignedUserOp(data, owner.key, address(eoaValidator));

        vm.expectEmit(true, true, true, true);
        emit IERC7579Account.ModuleInstalled(MODULE_TYPE_VALIDATOR, address(sessionKeyValidator));
        entryPoint.handleOps(userOps, bundler);
    }

    function test_createSession() public {
        test_installValidator();

        SessionLib.TransferSpec[] memory transferPolicies = new SessionLib.TransferSpec[](1);
        transferPolicies[0] = SessionLib.TransferSpec({
            target: recipient,
            maxValuePerUse: 0.1 ether,
            valueLimit: SessionLib.UsageLimit({ limitType: SessionLib.LimitType.Unlimited, limit: 0, period: 0 })
        });

        spec = SessionLib.SessionSpec({
            signer: sessionOwner.addr,
            expiresAt: uint48(block.timestamp + 1000),
            transferPolicies: transferPolicies,
            callPolicies: new SessionLib.CallSpec[](0),
            feeLimit: SessionLib.UsageLimit({ limitType: SessionLib.LimitType.Lifetime, limit: 0.15 ether, period: 0 })
        });

        bytes memory call = ExecutionLib.encodeSingle(
            address(sessionKeyValidator), 0, abi.encodeCall(SessionKeyValidator.createSession, (spec))
        );
        bytes memory callData = abi.encodeCall(IERC7579Account.execute, (ModeLib.encodeSimpleSingle(), call));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeSignedUserOp(callData, owner.key, address(eoaValidator));

        bytes32 sessionHash = keccak256(abi.encode(spec));
        vm.expectEmit(true, true, true, true);
        emit SessionKeyValidator.SessionCreated(address(account), sessionHash, spec);
        entryPoint.handleOps(userOps, bundler);

        SessionLib.Status status = sessionKeyValidator.sessionStatus(address(account), sessionHash);
        vm.assertTrue(status == SessionLib.Status.Active, "Session not active after creating");
    }

    function test_useSession() public {
        test_createSession();

        bytes memory call = ExecutionLib.encodeSingle(recipient, 0.05 ether, "");
        bytes memory callData = abi.encodeCall(IERC7579Account.execute, (ModeLib.encodeSimpleSingle(), call));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeUserOp(callData);
        userOps[0].nonce = uint256(uint160(sessionOwner.addr)) << 64;
        _signSessionUserOp(userOps[0]);

        entryPoint.handleOps(userOps, bundler);
        vm.assertEq(recipient.balance, 0.05 ether, "Value not transferred using session");
    }

    function testRevert_useSession() public {
        test_createSession();

        bytes memory call = ExecutionLib.encodeSingle(recipient, 0.11 ether, ""); // more than maxValuePerUse
        bytes memory callData = abi.encodeCall(IERC7579Account.execute, (ModeLib.encodeSimpleSingle(), call));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeUserOp(callData);
        userOps[0].nonce = uint256(uint160(sessionOwner.addr)) << 64;
        _signSessionUserOp(userOps[0]);

        vm.expectRevert();
        entryPoint.handleOps(userOps, bundler);
    }

    function test_uninstallModule() public {
        test_createSession();

        bytes32 sessionHash = keccak256(abi.encode(spec));
        vm.assertEq(
            sessionKeyValidator.sessionSigner(sessionOwner.addr), sessionHash, "stored session hash mismatch"
        );
        bytes32[] memory sessionHashes = new bytes32[](1);
        sessionHashes[0] = sessionHash;

        SessionLib.Status statusBefore = sessionKeyValidator.sessionStatus(address(account), sessionHash);
        vm.assertEq(uint256(statusBefore), uint256(SessionLib.Status.Active), "Session inactive before uninstall");

        bytes memory data = abi.encodeCall(
            ModularSmartAccount.uninstallModule,
            (MODULE_TYPE_VALIDATOR, address(sessionKeyValidator), abi.encode(sessionHashes))
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeSignedUserOp(data, owner.key, address(eoaValidator));

        entryPoint.handleOps(userOps, bundler);

        SessionLib.Status status = sessionKeyValidator.sessionStatus(address(account), sessionHash);
        vm.assertFalse(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(sessionKeyValidator), ""),
            "Validator still installed"
        );
        vm.assertEq(uint256(status), uint256(SessionLib.Status.Closed), "Session not revoked on uninstall");
    }

    function test_sessionTransferERC20() public {
        test_createSessionERC20();

        _sendSessionTransfer(recipient, 0.15 ether, false);
        vm.assertEq(erc20.balanceOf(recipient), 0.15 ether, "First transfer did not succeed");

        _sendSessionTransfer(recipient, 0.10 ether, false);
        vm.assertEq(erc20.balanceOf(recipient), 0.25 ether, "Second transfer cumulative balance mismatch");
    }

    function testRevert_sessionTransferERC20_invalidRecipient() public {
        test_createSessionERC20();

        address wrongRecipient = makeAddr("wrongRecipient");
        _sendSessionTransfer(wrongRecipient, 0.01 ether, true);
    }

    function testRevert_sessionTransferERC20_exceedsLimit() public {
        test_createSessionERC20();

        _sendSessionTransfer(recipient, 0.25 ether, false);
        vm.assertEq(erc20.balanceOf(recipient), 0.25 ether, "Initial transfer should consume full limit");

        _sendSessionTransfer(recipient, 0.01 ether, true);
        vm.assertEq(
            erc20.balanceOf(recipient), 0.25 ether, "Balance should remain capped after exceeding attempt"
        );
    }

    function test_createSessionERC20() public {
        test_installValidator();

        SessionLib.CallSpec[] memory callPolicies = new SessionLib.CallSpec[](1);
        SessionLib.Constraint[] memory constraints = new SessionLib.Constraint[](2);
        constraints[0] = SessionLib.Constraint({
            condition: SessionLib.Condition.Equal,
            index: 0,
            refValue: bytes32(uint256(uint160(recipient))),
            limit: SessionLib.UsageLimit({
                limitType: SessionLib.LimitType.Unlimited,
                limit: 0,
                period: 0
            })
        });
        constraints[1] = SessionLib.Constraint({
            condition: SessionLib.Condition.LessOrEqual,
            index: 1,
            refValue: bytes32(uint256(0.25 ether)),
            limit: SessionLib.UsageLimit({
                limitType: SessionLib.LimitType.Lifetime,
                limit: 0.25 ether,
                period: 0
            })
        });
        callPolicies[0] = SessionLib.CallSpec({
            target: address(erc20),
            selector: IERC20.transfer.selector,
            maxValuePerUse: 0,
            valueLimit: SessionLib.UsageLimit({
                limitType: SessionLib.LimitType.Unlimited,
                limit: 0,
                period: 0
            }),
            constraints: constraints
        });

        spec = SessionLib.SessionSpec({
            signer: sessionOwner.addr,
            expiresAt: uint48(block.timestamp + 1000),
            transferPolicies: new SessionLib.TransferSpec[](0),
            callPolicies: callPolicies,
            feeLimit: SessionLib.UsageLimit({
                limitType: SessionLib.LimitType.Lifetime,
                limit: 0.15 ether,
                period: 0
            })
        });

        bytes32 sessionHash = keccak256(abi.encode(spec));

        bytes memory createSessionCall = ExecutionLib.encodeSingle(
            address(sessionKeyValidator), 0, abi.encodeCall(SessionKeyValidator.createSession, (spec))
        );
        bytes memory createSessionCallData =
            abi.encodeCall(IERC7579Account.execute, (ModeLib.encodeSimpleSingle(), createSessionCall));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeSignedUserOp(createSessionCallData, owner.key, address(eoaValidator));

        vm.expectEmit(true, true, true, true);
        emit SessionKeyValidator.SessionCreated(address(account), sessionHash, spec);

        entryPoint.handleOps(userOps, bundler);

        vm.assertEq(
            sessionKeyValidator.sessionSigner(sessionOwner.addr), sessionHash, "Session hash not stored for signer"
        );
        SessionLib.Status status = sessionKeyValidator.sessionStatus(address(account), sessionHash);
        vm.assertEq(uint256(status), uint256(SessionLib.Status.Active), "ERC20 session not active after creation");
        vm.assertEq(spec.callPolicies.length, 1, "Unexpected call policies configured");
        vm.assertEq(spec.callPolicies[0].constraints.length, 2, "Constraints not set");
    }

    function _sendSessionTransfer(
        address to,
        uint256 amount,
        bool expectRevert
    )
        internal
    {
        bytes memory transferCall = ExecutionLib.encodeSingle(
            address(erc20), 0, abi.encodeCall(IERC20.transfer, (to, amount))
        );
        bytes memory transferCallData =
            abi.encodeCall(IERC7579Account.execute, (ModeLib.encodeSimpleSingle(), transferCall));

        PackedUserOperation[] memory sessionOps = new PackedUserOperation[](1);
        sessionOps[0] = makeUserOp(transferCallData);
        sessionOps[0].nonce = entryPoint.getNonce(address(account), uint192(uint160(sessionOwner.addr)));
        _signSessionUserOp(sessionOps[0]);

        if (expectRevert) {
            vm.expectRevert();
        }

        entryPoint.handleOps(sessionOps, bundler);
    }

    function _signSessionUserOp(PackedUserOperation memory userOp) internal view {
        uint256 constraints = 0;
        for (uint256 i = 0; i < spec.callPolicies.length; i++) {
            constraints += spec.callPolicies[i].constraints.length;
        }

        uint48[] memory periodIds = new uint48[](2 + constraints);
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionOwner.key, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        userOp.signature = abi.encodePacked(sessionKeyValidator, abi.encode(signature, spec, periodIds));
    }
}
