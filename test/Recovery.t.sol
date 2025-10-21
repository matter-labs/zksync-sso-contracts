// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";

import { ModularSmartAccount } from "src/ModularSmartAccount.sol";
import { MSAFactory } from "src/MSAFactory.sol";
import { EOAKeyValidator } from "src/modules/EOAKeyValidator.sol";
import { SessionKeyValidator } from "src/modules/SessionKeyValidator.sol";
import { IMSA } from "src/interfaces/IMSA.sol";
import { MODULE_TYPE_EXECUTOR } from "src/interfaces/IERC7579Module.sol";
import { IERC7579Account } from "src/interfaces/IERC7579Account.sol";
import { GuardianBasedRecoveryExecutor } from "src/modules/contrib/GuardianBasedRecoveryExecutor.sol";
import { GuardianExecutor } from "src/modules/GuardianExecutor.sol";

import { MSATest } from "./MSATest.sol";

contract RecoveryTest is MSATest {
    GuardianBasedRecoveryExecutor public recoveryExecutor;
    Account public newOwner;
    Account public admin;
    Account public submitter;
    Account public finalizer;

    function setUp() public override {
        super.setUp();
        newOwner = makeAccount("newOwner");
        admin = makeAccount("admin");
        submitter = makeAccount("submitter");
        finalizer = makeAccount("finalizer");

        recoveryExecutor = new GuardianBasedRecoveryExecutor(address(0), address(eoaValidator));
        // recoveryExecutor.initialize(admin.addr, finalizer.addr, submitter.addr);
        recoveryExecutor.grantRole(recoveryExecutor.DEFAULT_ADMIN_ROLE(), admin.addr);
        recoveryExecutor.grantRole(recoveryExecutor.FINALIZER_ROLE(), finalizer.addr);
        recoveryExecutor.grantRole(recoveryExecutor.SUBMITTER_ROLE(), submitter.addr);
    }

    function test_installExecutor() public {
        bytes memory data =
            abi.encodeCall(ModularSmartAccount.installModule, (MODULE_TYPE_EXECUTOR, address(recoveryExecutor), ""));
        PackedUserOperation[] memory userOps = makeSignedUserOp(data);

        vm.expectEmit(true, true, true, true);
        emit IERC7579Account.ModuleInstalled(MODULE_TYPE_EXECUTOR, address(recoveryExecutor));
        entryPoint.handleOps(userOps, bundler);

        vm.assertTrue(recoveryExecutor.isInitialized(address(account)), "Executor not initialized");
        vm.assertTrue(recoveryExecutor.isModuleType(MODULE_TYPE_EXECUTOR), "Wrong module type");
    }

    function test_uninstallExecutor() public {
        test_installExecutor();
        bytes memory data =
            abi.encodeCall(ModularSmartAccount.uninstallModule, (MODULE_TYPE_EXECUTOR, address(recoveryExecutor), ""));
        PackedUserOperation[] memory userOps = makeSignedUserOp(data);
        vm.expectEmit(true, true, true, true);
        emit IERC7579Account.ModuleUninstalled(MODULE_TYPE_EXECUTOR, address(recoveryExecutor));
        entryPoint.handleOps(userOps, bundler);
        vm.assertTrue(!recoveryExecutor.isInitialized(address(account)), "Executor not uninitialized");
    }

    function test_initialization() public {
        vm.assertTrue(recoveryExecutor.hasRole(recoveryExecutor.DEFAULT_ADMIN_ROLE(), admin.addr), "Admin role not set");
        vm.assertTrue(
            recoveryExecutor.hasRole(recoveryExecutor.SUBMITTER_ROLE(), submitter.addr), "Submitter role not set"
        );
        vm.assertTrue(
            recoveryExecutor.hasRole(recoveryExecutor.FINALIZER_ROLE(), finalizer.addr), "Finalizer role not set"
        );
    }

    function test_initRecovery() public {
        test_installExecutor();

        vm.prank(submitter.addr);
        vm.expectEmit(true, true, true, false); // don't check data
        emit GuardianExecutor.RecoveryInitiated(
            address(account),
            submitter.addr,
            GuardianExecutor.RecoveryRequest(
                GuardianExecutor.RecoveryType.EOA, abi.encode(newOwner.addr), uint48(block.timestamp)
            )
        );
        recoveryExecutor.initializeRecovery(
            address(account), GuardianExecutor.RecoveryType.EOA, abi.encode(newOwner.addr)
        );

        (GuardianExecutor.RecoveryType recoveryType, bytes memory data, uint256 timestamp) =
            recoveryExecutor.pendingRecovery(address(account));
        vm.assertEq(uint256(recoveryType), uint256(GuardianExecutor.RecoveryType.EOA), "Invalid recovery type");
        vm.assertEq(abi.decode(data, (address)), newOwner.addr, "Invalid recovery data");
        vm.assertTrue(timestamp != 0, "Recovery timestamp is empty");
    }

    function test_finishRecovery() public {
        test_initRecovery();

        vm.warp(2 days);

        vm.prank(finalizer.addr);
        vm.expectEmit(true, true, true, true);
        emit GuardianExecutor.RecoveryFinished(address(account));
        recoveryExecutor.finalizeRecovery(address(account));

        vm.assertTrue(eoaValidator.isOwnerOf(address(account), newOwner.addr), "New owner was not added");

        assertPendingRecoveryCleared();
    }

    function test_discardRecovery() public {
        test_initRecovery();

        vm.prank(address(account));
        vm.expectEmit(true, true, true, true);
        emit GuardianExecutor.RecoveryDiscarded(address(account));
        recoveryExecutor.discardRecovery();
        assertPendingRecoveryCleared();
    }

    function test_discardRecoveryFor() public {
        test_initRecovery();

        vm.prank(submitter.addr);
        vm.expectEmit(true, true, true, true);
        emit GuardianExecutor.RecoveryDiscarded(address(account));
        recoveryExecutor.discardRecoveryFor(address(account));
        assertPendingRecoveryCleared();
    }

    function testRevert_initRecoveryUnauthorized() public {
        test_installExecutor();

        vm.prank(makeAddr("unauthorized"));
        vm.expectRevert();
        recoveryExecutor.initializeRecovery(
            address(account), GuardianExecutor.RecoveryType.EOA, abi.encode(newOwner.addr)
        );
    }

    function testRevert_finalizeRecoveryUnauthorized() public {
        test_initRecovery();
        vm.warp(2 days);

        vm.prank(makeAddr("unauthorized"));
        vm.expectRevert();
        recoveryExecutor.finalizeRecovery(address(account));
    }

    function testRevert_discardRecoveryForUnauthorized() public {
        test_initRecovery();

        vm.prank(makeAddr("unauthorized"));
        vm.expectRevert();
        recoveryExecutor.discardRecoveryFor(address(account));
    }

    function testRevert_earlyRecovery() public {
        test_initRecovery();
        vm.prank(finalizer.addr);
        vm.expectPartialRevert(GuardianExecutor.RecoveryTimestampInvalid.selector);
        recoveryExecutor.finalizeRecovery(address(account));
    }

    function testRevert_expiredRecovery() public {
        test_initRecovery();
        vm.warp(8 days); // Beyond REQUEST_VALIDITY_TIME

        vm.prank(finalizer.addr);
        vm.expectPartialRevert(GuardianExecutor.RecoveryTimestampInvalid.selector);
        recoveryExecutor.finalizeRecovery(address(account));
    }

    function testRevert_recoveryInProgress() public {
        test_initRecovery();

        vm.prank(submitter.addr);
        vm.expectPartialRevert(GuardianExecutor.RecoveryInProgress.selector);
        recoveryExecutor.initializeRecovery(
            address(account), GuardianExecutor.RecoveryType.EOA, abi.encode(makeAddr("anotherOwner"))
        );
    }

    function testRevert_discardNonExistentRecovery() public {
        test_installExecutor();

        vm.prank(submitter.addr);
        vm.expectPartialRevert(GuardianBasedRecoveryExecutor.CannotDiscardRecoveryFor.selector);
        recoveryExecutor.discardRecoveryFor(address(account));
    }

    function testRevert_proposeGuardianDisabled() public {
        test_installExecutor();

        bytes memory data = abi.encodeCall(GuardianBasedRecoveryExecutor.proposeGuardian, (makeAddr("guardian")));
        bytes memory call = encodeCall(address(recoveryExecutor), 0, data);
        PackedUserOperation[] memory userOps = makeSignedUserOp(call);

        expectUserOpRevert(
            userOps[0], abi.encodeWithSelector(GuardianBasedRecoveryExecutor.GuardianModificationDisabled.selector)
        );
    }

    function testRevert_acceptGuardianDisabled() public {
        vm.expectPartialRevert(GuardianBasedRecoveryExecutor.GuardianModificationDisabled.selector);
        recoveryExecutor.acceptGuardian(address(account));
    }

    function testRevert_removeGuardianDisabled() public {
        test_installExecutor();

        bytes memory data = abi.encodeCall(GuardianBasedRecoveryExecutor.removeGuardian, (makeAddr("guardian")));
        bytes memory call = encodeCall(address(recoveryExecutor), 0, data);
        PackedUserOperation[] memory userOps = makeSignedUserOp(call);

        expectUserOpRevert(
            userOps[0], abi.encodeWithSelector(GuardianBasedRecoveryExecutor.GuardianModificationDisabled.selector)
        );
    }

    function test_supportsInterface() public {
        vm.assertTrue(
            recoveryExecutor.supportsInterface(type(IAccessControl).interfaceId), "Should support IAccessControl"
        );
    }

    function test_replaceExpiredRecovery() public {
        test_installExecutor();

        // Start first recovery
        vm.prank(submitter.addr);
        recoveryExecutor.initializeRecovery(
            address(account), GuardianExecutor.RecoveryType.EOA, abi.encode(newOwner.addr)
        );

        // Fast forward past expiry
        vm.warp(8 days);

        Account memory anotherOwner = makeAccount("anotherOwner");

        // Start new recovery (should replace expired one)
        vm.prank(submitter.addr);
        vm.expectEmit(true, true, true, false);
        emit GuardianExecutor.RecoveryInitiated(
            address(account),
            submitter.addr,
            GuardianExecutor.RecoveryRequest(
                GuardianExecutor.RecoveryType.EOA, abi.encode(anotherOwner.addr), uint48(block.timestamp)
            )
        );
        recoveryExecutor.initializeRecovery(
            address(account), GuardianExecutor.RecoveryType.EOA, abi.encode(anotherOwner.addr)
        );

        (GuardianExecutor.RecoveryType recoveryType, bytes memory data, uint256 timestamp) =
            recoveryExecutor.pendingRecovery(address(account));
        vm.assertEq(abi.decode(data, (address)), anotherOwner.addr, "Should have new recovery data");
    }

    function assertPendingRecoveryCleared() internal view {
        (GuardianExecutor.RecoveryType recoveryType, bytes memory data, uint256 timestamp) =
            recoveryExecutor.pendingRecovery(address(account));
        vm.assertEq(uint256(recoveryType), uint256(GuardianExecutor.RecoveryType.None), "Recovery type not cleared");
        vm.assertEq(data.length, 0, "Recovery data not cleared");
        vm.assertEq(timestamp, 0, "Recovery timestamp not cleared");
    }
}
