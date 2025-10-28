// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";

import { ModularSmartAccount } from "src/ModularSmartAccount.sol";
import { SessionKeyValidator } from "src/modules/SessionKeyValidator.sol";
import { AllowedSessionsValidator } from "src/modules/contrib/AllowedSessionsValidator.sol";
import { IMSA } from "src/interfaces/IMSA.sol";
import { MODULE_TYPE_VALIDATOR } from "src/interfaces/IERC7579Module.sol";
import { IERC7579Account } from "src/interfaces/IERC7579Account.sol";
import { SessionLib } from "src/libraries/SessionLib.sol";

import { MSATest } from "./MSATest.sol";
import { MockERC20 } from "./mocks/MockERC20.sol";

contract SessionsTest is MSATest {
    SessionKeyValidator public sessionKeyValidator;
    AllowedSessionsValidator public allowedValidator;
    Account public sessionOwner;
    address recipient;
    MockERC20 erc20;

    SessionLib.SessionSpec public spec;

    function setUp() public virtual override {
        super.setUp();

        recipient = makeAddr("sessionRecipient");
        sessionOwner = makeAccount("sessionOwner");
        sessionKeyValidator = new SessionKeyValidator();
        allowedValidator = new AllowedSessionsValidator();
        erc20 = new MockERC20(address(account));
    }

    function test_installValidator() public {
        bytes memory data = abi.encodeCall(
            ModularSmartAccount.installModule, (MODULE_TYPE_VALIDATOR, address(sessionKeyValidator), "")
        );
        PackedUserOperation[] memory userOps = makeSignedUserOp(data);

        vm.expectEmit(true, true, true, true);
        emit IERC7579Account.ModuleInstalled(MODULE_TYPE_VALIDATOR, address(sessionKeyValidator));
        entryPoint.handleOps(userOps, bundler);
    }

    function test_createSession() public {
        test_installValidator();

        spec = _baseSessionSpec();
        bytes memory call =
            encodeCall(address(sessionKeyValidator), 0, abi.encodeCall(SessionKeyValidator.createSession, (spec)));
        PackedUserOperation[] memory userOps = makeSignedUserOp(call);

        bytes32 sessionHash = keccak256(abi.encode(spec));
        vm.expectEmit(true, true, true, true);
        emit SessionKeyValidator.SessionCreated(address(account), sessionHash, spec);
        entryPoint.handleOps(userOps, bundler);

        SessionLib.Status status = sessionKeyValidator.sessionStatus(address(account), sessionHash);
        vm.assertTrue(status == SessionLib.Status.Active, "Session not active after creating");
    }

    function testRevert_createSession_zeroSigner() public {
        test_installValidator();

        SessionLib.SessionSpec memory invalidSpec = _baseSessionSpec();
        invalidSpec.signer = address(0);

        vm.expectRevert(SessionLib.ZeroSigner.selector);
        vm.prank(address(account));
        sessionKeyValidator.createSession(invalidSpec);
    }

    function testRevert_createSession_unlimitedFees() public {
        test_installValidator();

        SessionLib.SessionSpec memory invalidSpec = _baseSessionSpec();
        invalidSpec.feeLimit.limitType = SessionLib.LimitType.Unlimited;

        vm.expectRevert(SessionLib.UnlimitedFees.selector);
        vm.prank(address(account));
        sessionKeyValidator.createSession(invalidSpec);
    }

    function testRevert_createSession_signerAlreadyUsed() public {
        test_createSession();

        SessionLib.SessionSpec memory duplicateSpec = spec;
        duplicateSpec.expiresAt = uint48(block.timestamp + 2000);

        vm.expectRevert(abi.encodeWithSelector(SessionLib.SignerAlreadyUsed.selector, sessionOwner.addr));
        vm.prank(address(account));
        sessionKeyValidator.createSession(duplicateSpec);
    }

    function testRevert_createSession_sessionExpiresTooSoon() public {
        test_installValidator();

        SessionLib.SessionSpec memory invalidSpec = _baseSessionSpec();
        invalidSpec.expiresAt = uint48(block.timestamp + 30);

        vm.expectRevert(abi.encodeWithSelector(SessionLib.SessionExpiresTooSoon.selector, invalidSpec.expiresAt));
        vm.prank(address(account));
        sessionKeyValidator.createSession(invalidSpec);
    }

    function testRevert_createSession_callPolicyBanned() public {
        test_installValidator();

        SessionLib.CallSpec[] memory callPolicies = new SessionLib.CallSpec[](1);
        callPolicies[0] = SessionLib.CallSpec({
            target: address(sessionKeyValidator),
            selector: bytes4(0),
            maxValuePerUse: 0,
            valueLimit: SessionLib.UsageLimit({ limitType: SessionLib.LimitType.Unlimited, limit: 0, period: 0 }),
            constraints: new SessionLib.Constraint[](0)
        });

        SessionLib.SessionSpec memory invalidSpec = SessionLib.SessionSpec({
            signer: sessionOwner.addr,
            expiresAt: uint48(block.timestamp + 1000),
            transferPolicies: new SessionLib.TransferSpec[](0),
            callPolicies: callPolicies,
            feeLimit: SessionLib.UsageLimit({ limitType: SessionLib.LimitType.Lifetime, limit: 0.15 ether, period: 0 })
        });

        vm.expectRevert(
            abi.encodeWithSelector(SessionLib.CallPolicyBanned.selector, address(sessionKeyValidator), bytes4(0))
        );
        vm.prank(address(account));
        sessionKeyValidator.createSession(invalidSpec);
    }

    function test_useSession() public {
        test_createSession();

        bytes memory call = encodeCall(recipient, 0.05 ether, "");
        PackedUserOperation[] memory userOps = makeUserOp(call);
        userOps[0].nonce = uint256(uint160(sessionOwner.addr)) << 64;
        _signSessionUserOp(userOps[0]);

        entryPoint.handleOps(userOps, bundler);
        vm.assertEq(recipient.balance, 0.05 ether, "Value not transferred using session");
    }

    function testRevert_useSession() public {
        test_createSession();

        bytes memory call = encodeCall(recipient, 0.11 ether, ""); // more than maxValuePerUse
        PackedUserOperation[] memory userOps = makeUserOp(call);
        userOps[0].nonce = uint256(uint160(sessionOwner.addr)) << 64;
        _signSessionUserOp(userOps[0]);

        vm.expectRevert();
        entryPoint.handleOps(userOps, bundler);
    }

    function testRevert_useSession_invalidNonceKey() public {
        test_createSession();

        bytes memory call = encodeCall(recipient, 0.05 ether, "");
        PackedUserOperation[] memory userOps = makeUserOp(call);
        userOps[0].nonce = entryPoint.getNonce(address(account), 0);
        _signSessionUserOp(userOps[0]);

        bytes32 userOpHash = entryPoint.getUserOpHash(userOps[0]);
        vm.expectRevert(
            abi.encodeWithSelector(
                SessionLib.InvalidNonceKey.selector,
                uint192(userOps[0].nonce >> 64),
                uint192(uint160(sessionOwner.addr))
            )
        );
        vm.prank(address(entryPoint));
        sessionKeyValidator.validateUserOp(userOps[0], userOpHash);
    }

    function test_closeSession() public {
        test_createSession();
        bytes32 sessionHash = keccak256(abi.encode(spec));
        vm.assertEq(sessionKeyValidator.sessionSigner(sessionOwner.addr), sessionHash, "stored session hash mismatch");

        SessionLib.Status statusBefore = sessionKeyValidator.sessionStatus(address(account), sessionHash);
        vm.assertEq(uint256(statusBefore), uint256(SessionLib.Status.Active), "Session inactive before close");

        bytes memory call =
            encodeCall(address(sessionKeyValidator), 0, abi.encodeCall(SessionKeyValidator.revokeKey, (sessionHash)));
        PackedUserOperation[] memory userOps = makeSignedUserOp(call);

        vm.expectEmit(true, true, true, true);
        emit SessionKeyValidator.SessionRevoked(address(account), sessionHash);
        entryPoint.handleOps(userOps, bundler);

        SessionLib.Status status = sessionKeyValidator.sessionStatus(address(account), sessionHash);
        vm.assertEq(uint256(status), uint256(SessionLib.Status.Closed), "Session not closed");
    }

    function testRevert_revokeKey_notActive() public {
        test_closeSession();
        bytes32 sessionHash = keccak256(abi.encode(spec));

        vm.expectRevert(SessionLib.SessionNotActive.selector);
        vm.prank(address(account));
        sessionKeyValidator.revokeKey(sessionHash);
    }

    function test_uninstallModule() public {
        test_createSession();

        bytes32 sessionHash = keccak256(abi.encode(spec));
        vm.assertEq(sessionKeyValidator.sessionSigner(sessionOwner.addr), sessionHash, "stored session hash mismatch");
        bytes32[] memory sessionHashes = new bytes32[](1);
        sessionHashes[0] = sessionHash;

        SessionLib.Status statusBefore = sessionKeyValidator.sessionStatus(address(account), sessionHash);
        vm.assertEq(uint256(statusBefore), uint256(SessionLib.Status.Active), "Session inactive before uninstall");

        bytes memory data = abi.encodeCall(
            ModularSmartAccount.uninstallModule,
            (MODULE_TYPE_VALIDATOR, address(sessionKeyValidator), abi.encode(sessionHashes))
        );

        PackedUserOperation[] memory userOps = makeSignedUserOp(data);

        entryPoint.handleOps(userOps, bundler);

        SessionLib.Status status = sessionKeyValidator.sessionStatus(address(account), sessionHash);
        vm.assertFalse(
            account.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(sessionKeyValidator), ""),
            "Validator still installed"
        );
        vm.assertEq(uint256(status), uint256(SessionLib.Status.Closed), "Session not revoked on uninstall");
    }

    function test_revokeKeys() public {
        test_installValidator();

        SessionLib.SessionSpec memory firstSpec = _baseSessionSpec();
        bytes memory createFirst =
            encodeCall(address(sessionKeyValidator), 0, abi.encodeCall(SessionKeyValidator.createSession, (firstSpec)));
        entryPoint.handleOps(makeSignedUserOp(createFirst), bundler);
        bytes32 sessionHashOne = keccak256(abi.encode(firstSpec));

        Account memory secondOwner = makeAccount("secondSessionOwner");
        SessionLib.SessionSpec memory secondSpec = firstSpec;
        secondSpec.signer = secondOwner.addr;
        secondSpec.expiresAt = uint48(block.timestamp + 2000);

        bytes memory createSecond = encodeCall(
            address(sessionKeyValidator), 0, abi.encodeCall(SessionKeyValidator.createSession, (secondSpec))
        );
        PackedUserOperation[] memory secondUserOps = makeSignedUserOp(createSecond);
        entryPoint.handleOps(secondUserOps, bundler);
        bytes32 sessionHashTwo = keccak256(abi.encode(secondSpec));

        bytes32[] memory hashes = new bytes32[](2);
        hashes[0] = sessionHashOne;
        hashes[1] = sessionHashTwo;

        bytes memory revokeCall =
            encodeCall(address(sessionKeyValidator), 0, abi.encodeCall(SessionKeyValidator.revokeKeys, (hashes)));
        PackedUserOperation[] memory userOps = makeSignedUserOp(revokeCall);

        entryPoint.handleOps(userOps, bundler);

        vm.assertEq(
            uint256(sessionKeyValidator.sessionStatus(address(account), sessionHashOne)),
            uint256(SessionLib.Status.Closed),
            "First session not closed"
        );
        vm.assertEq(
            uint256(sessionKeyValidator.sessionStatus(address(account), sessionHashTwo)),
            uint256(SessionLib.Status.Closed),
            "Second session not closed"
        );
    }

    function test_sessionState() public {
        test_createSessionERC20();
        _sendSessionTransfer(recipient, 0.15 ether, false);

        SessionLib.SessionState memory state = sessionKeyValidator.sessionState(address(account), spec);
        vm.assertEq(uint256(state.status), uint256(SessionLib.Status.Active));
        vm.assertTrue(state.feesRemaining < 0.15 ether);
        vm.assertEq(state.callParams[0].remaining, 0.1 ether);
    }

    function test_sessionTransferERC20() public {
        test_createSessionERC20();

        _sendSessionTransfer(recipient, 0.15 ether, false);
        vm.assertEq(erc20.balanceOf(recipient), 0.15 ether, "First transfer did not succeed");

        _sendSessionTransfer(recipient, 0.1 ether, false);
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
        vm.assertEq(erc20.balanceOf(recipient), 0.25 ether, "Balance should remain capped after exceeding attempt");
    }

    function test_createSessionERC20() public {
        test_installValidator();

        SessionLib.CallSpec[] memory callPolicies = new SessionLib.CallSpec[](1);
        SessionLib.Constraint[] memory constraints = new SessionLib.Constraint[](2);
        constraints[0] = SessionLib.Constraint({
            condition: SessionLib.Condition.Equal,
            index: 0,
            refValue: bytes32(uint256(uint160(recipient))),
            limit: SessionLib.UsageLimit({ limitType: SessionLib.LimitType.Unlimited, limit: 0, period: 0 })
        });
        constraints[1] = SessionLib.Constraint({
            condition: SessionLib.Condition.LessOrEqual,
            index: 1,
            refValue: bytes32(uint256(0.25 ether)),
            limit: SessionLib.UsageLimit({ limitType: SessionLib.LimitType.Lifetime, limit: 0.25 ether, period: 0 })
        });
        callPolicies[0] = SessionLib.CallSpec({
            target: address(erc20),
            selector: IERC20.transfer.selector,
            maxValuePerUse: 0,
            valueLimit: SessionLib.UsageLimit({ limitType: SessionLib.LimitType.Unlimited, limit: 0, period: 0 }),
            constraints: constraints
        });

        spec = SessionLib.SessionSpec({
            signer: sessionOwner.addr,
            expiresAt: uint48(block.timestamp + 1000),
            transferPolicies: new SessionLib.TransferSpec[](0),
            callPolicies: callPolicies,
            feeLimit: SessionLib.UsageLimit({ limitType: SessionLib.LimitType.Lifetime, limit: 0.15 ether, period: 0 })
        });

        bytes32 sessionHash = keccak256(abi.encode(spec));

        bytes memory call =
            encodeCall(address(sessionKeyValidator), 0, abi.encodeCall(SessionKeyValidator.createSession, (spec)));
        PackedUserOperation[] memory userOps = makeSignedUserOp(call);

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

    function test_deployAccountWithSession() public {
        address[] memory modules = new address[](1);
        modules[0] = address(sessionKeyValidator);

        spec = SessionLib.SessionSpec({
            signer: sessionOwner.addr,
            expiresAt: uint48(block.timestamp + 1000),
            transferPolicies: new SessionLib.TransferSpec[](0),
            callPolicies: new SessionLib.CallSpec[](0),
            feeLimit: SessionLib.UsageLimit({ limitType: SessionLib.LimitType.Lifetime, limit: 0.1 ether, period: 0 })
        });

        bytes[] memory initData = new bytes[](1);
        initData[0] = abi.encode(spec);

        bytes memory data = abi.encodeCall(IMSA.initializeAccount, (modules, initData));
        factory.deployAccount(keccak256("my-other-account-id"), data);
    }

    function testRevert_createSession_actionsNotAllowed() public {
        test_installAllowedValidator();
        SessionLib.SessionSpec memory localSpec = _baseSessionSpec();
        bytes32 actionsHash = allowedValidator.getSessionActionsHash(localSpec);

        vm.expectRevert(abi.encodeWithSelector(SessionLib.ActionsNotAllowed.selector, actionsHash));
        vm.prank(address(account));
        allowedValidator.createSession(localSpec);
    }

    function test_createSession_allowed() public {
        test_installAllowedValidator();
        SessionLib.SessionSpec memory localSpec = _baseSessionSpec();
        bytes32 actionsHash = allowedValidator.getSessionActionsHash(localSpec);

        vm.expectEmit(true, true, true, true);
        emit AllowedSessionsValidator.SessionActionsAllowed(actionsHash, true);
        allowedValidator.setSessionActionsAllowed(actionsHash, true);

        bytes32 sessionHash = keccak256(abi.encode(localSpec));
        bytes memory call =
            encodeCall(address(allowedValidator), 0, abi.encodeCall(SessionKeyValidator.createSession, (localSpec)));
        PackedUserOperation[] memory userOps = makeSignedUserOp(call);

        vm.expectEmit(true, true, true, true);
        emit SessionKeyValidator.SessionCreated(address(account), sessionHash, localSpec);
        entryPoint.handleOps(userOps, bundler);

        vm.assertTrue(allowedValidator.areSessionActionsAllowed(actionsHash), "Session actions unexpectedly disallowed");
        vm.assertEq(allowedValidator.sessionSigner(localSpec.signer), sessionHash, "Session hash not stored for signer");
    }

    function testRevert_setSessionActionsAllowed_unauthorized() public {
        bytes32 role = allowedValidator.SESSION_REGISTRY_MANAGER_ROLE();
        address intruder = makeAddr("intruder");

        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, intruder, role)
        );
        vm.prank(intruder);
        allowedValidator.setSessionActionsAllowed(bytes32("hash"), true);
    }

    function testRevert_useSession_actionsNotAllowed() public {
        test_installAllowedValidator();
        spec = _baseSessionSpec();
        bytes32 actionsHash = allowedValidator.getSessionActionsHash(spec);

        allowedValidator.setSessionActionsAllowed(actionsHash, true);

        bytes memory call =
            encodeCall(address(allowedValidator), 0, abi.encodeCall(SessionKeyValidator.createSession, (spec)));
        PackedUserOperation[] memory userOps = makeSignedUserOp(call);
        entryPoint.handleOps(userOps, bundler);

        bytes memory transferCall = encodeCall(recipient, 0.1 ether, "");
        PackedUserOperation[] memory sessionOps = makeUserOp(transferCall);
        sessionOps[0].nonce = entryPoint.getNonce(address(account), uint192(uint160(sessionOwner.addr)));
        _signAllowedSessionUserOp(sessionOps[0]);
        entryPoint.handleOps(sessionOps, bundler);
        vm.assertEq(address(recipient).balance, 0.1 ether, "Balance not changed after transfer");

        allowedValidator.setSessionActionsAllowed(actionsHash, false);

        sessionOps[0].nonce++;
        _signAllowedSessionUserOp(sessionOps[0]);
        vm.expectRevert(
            abi.encodeWithSelector(
                IEntryPoint.FailedOpWithRevert.selector,
                0,
                "AA23 reverted",
                abi.encodeWithSelector(SessionLib.ActionsNotAllowed.selector, actionsHash)
            )
        );
        entryPoint.handleOps(sessionOps, bundler);
        vm.assertEq(address(recipient).balance, 0.1 ether, "Balance should not change after failed transfer");
    }

    function test_installAllowedValidator() public {
        bytes memory data =
            abi.encodeCall(ModularSmartAccount.installModule, (MODULE_TYPE_VALIDATOR, address(allowedValidator), ""));
        PackedUserOperation[] memory userOps = makeSignedUserOp(data);

        vm.expectEmit(true, true, true, true);
        emit IERC7579Account.ModuleInstalled(MODULE_TYPE_VALIDATOR, address(allowedValidator));
        entryPoint.handleOps(userOps, bundler);
    }

    function _baseSessionSpec() internal view returns (SessionLib.SessionSpec memory base) {
        SessionLib.TransferSpec[] memory transferPolicies = new SessionLib.TransferSpec[](1);
        transferPolicies[0] = SessionLib.TransferSpec({
            target: recipient,
            maxValuePerUse: 0.1 ether,
            valueLimit: SessionLib.UsageLimit({ limitType: SessionLib.LimitType.Unlimited, limit: 0, period: 0 })
        });

        base = SessionLib.SessionSpec({
            signer: sessionOwner.addr,
            expiresAt: uint48(block.timestamp + 1000),
            transferPolicies: transferPolicies,
            callPolicies: new SessionLib.CallSpec[](0),
            feeLimit: SessionLib.UsageLimit({ limitType: SessionLib.LimitType.Lifetime, limit: 0.15 ether, period: 0 })
        });
    }

    function _sendSessionTransfer(address to, uint256 amount, bool expectRevert) internal {
        uint256 balanceBefore = erc20.balanceOf(to);
        bytes memory transferCall = encodeCall(address(erc20), 0, abi.encodeCall(IERC20.transfer, (to, amount)));

        PackedUserOperation[] memory sessionOps = makeUserOp(transferCall);
        sessionOps[0].nonce = entryPoint.getNonce(address(account), uint192(uint160(sessionOwner.addr)));
        _signSessionUserOp(sessionOps[0]);

        if (expectRevert) {
            vm.expectRevert();
        }

        entryPoint.handleOps(sessionOps, bundler);

        vm.assertEq(
            erc20.balanceOf(to) - balanceBefore, expectRevert ? 0 : amount, "Value not transferred using session"
        );
    }

    function _signUserOpNoPrefix(PackedUserOperation memory userOp) internal view {
        uint256 constraints = 0;
        for (uint256 i = 0; i < spec.callPolicies.length; ++i) {
            constraints += spec.callPolicies[i].constraints.length;
        }

        uint48[] memory periodIds = new uint48[](2 + constraints);
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionOwner.key, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        userOp.signature = abi.encode(signature, spec, periodIds);
    }

    function _signSessionUserOp(PackedUserOperation memory userOp) internal view {
        _signUserOpNoPrefix(userOp);
        userOp.signature = abi.encodePacked(sessionKeyValidator, userOp.signature);
    }

    function _signAllowedSessionUserOp(PackedUserOperation memory userOp) internal view {
        _signUserOpNoPrefix(userOp);
        userOp.signature = abi.encodePacked(allowedValidator, userOp.signature);
    }
}
