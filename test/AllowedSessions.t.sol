// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import { LibBytes } from "solady/utils/LibBytes.sol";

import { SessionLib } from "src/libraries/SessionLib.sol";
import { ModularSmartAccount } from "src/ModularSmartAccount.sol";
import { AllowedSessionsValidator } from "src/modules/contrib/AllowedSessionsValidator.sol";
import { SessionKeyValidator } from "src/modules/SessionKeyValidator.sol";
import { MODULE_TYPE_VALIDATOR } from "src/interfaces/IERC7579Module.sol";
import { IERC7579Account } from "src/interfaces/IERC7579Account.sol";

import { SessionsTest } from "./Sessions.t.sol";

contract AllowedSessionsTest is SessionsTest {
    AllowedSessionsValidator public allowedValidator;

    function setUp() public override {
        super.setUp();

        allowedValidator = new AllowedSessionsValidator();
    }

    function testRevert_createSession_actionsNotAllowed() public {
        test_installAllowedValidator();
        SessionLib.SessionSpec memory localSpec = _baseSessionSpec();
        bytes32 actionsHash = allowedValidator.getSessionActionsHash(localSpec);

        vm.expectRevert(abi.encodeWithSelector(SessionLib.ActionsNotAllowed.selector, actionsHash));
        vm.prank(address(account));
        allowedValidator.createSession(localSpec);
    }

    function test_createSessionWhenAllowed() public {
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

    function testRevert_validateUserOpDisallowed() public {
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
        _signSessionUserOp(sessionOps[0]);
        sessionOps[0].signature = abi.encodePacked(allowedValidator, LibBytes.slice(sessionOps[0].signature, 20));
        entryPoint.handleOps(sessionOps, bundler);
        vm.assertEq(address(recipient).balance, 0.1 ether, "Balance not changed after transfer");

        allowedValidator.setSessionActionsAllowed(actionsHash, false);

        sessionOps[0].nonce++;
        _signSessionUserOp(sessionOps[0]);
        sessionOps[0].signature = abi.encodePacked(allowedValidator, LibBytes.slice(sessionOps[0].signature, 20));
        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOpWithRevert.selector, 0, "AA23 reverted", abi.encodeWithSelector(SessionLib.ActionsNotAllowed.selector, actionsHash)));
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
}
