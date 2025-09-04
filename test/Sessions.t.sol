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

contract SessionsTest is MSATest {
    SessionKeyValidator public sessionKeyValidator;
    Account public sessionOwner;
    address recipient;

    SessionLib.SessionSpec public spec;

    function setUp() public override {
        super.setUp();

        recipient = makeAddr("sessionRecipient");
        sessionOwner = makeAccount("sessionOwner");
        sessionKeyValidator = new SessionKeyValidator();
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
        signUserOp(userOps[0], sessionOwner.key, address(sessionKeyValidator), abi.encode(spec, new uint48[](2)));

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
        signUserOp(userOps[0], sessionOwner.key, address(sessionKeyValidator), abi.encode(spec, new uint48[](2)));

        vm.expectRevert();
        entryPoint.handleOps(userOps, bundler);
    }
}
