// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";

import { ModularSmartAccount } from "src/ModularSmartAccount.sol";
import { MODULE_TYPE_EXECUTOR } from "src/interfaces/IERC7579Module.sol";
import { IERC7579Account } from "src/interfaces/IERC7579Account.sol";
import { GuardianExecutor } from "src/modules/GuardianExecutor.sol";

import { MSATest } from "./MSATest.sol";

contract GuardianTest is MSATest {
    GuardianExecutor public guardiansExecutor;
    Account public guardian;
    Account public newOwner;

    function setUp() public override {
        super.setUp();

        guardian = makeAccount("guardian");
        newOwner = makeAccount("newOwner");
        guardiansExecutor = new GuardianExecutor(address(0), address(eoaValidator));
    }

    function test_installExecutor() public {
        bytes memory data =
            abi.encodeCall(ModularSmartAccount.installModule, (MODULE_TYPE_EXECUTOR, address(guardiansExecutor), ""));
        PackedUserOperation[] memory userOps = makeSignedUserOp(data);

        vm.expectEmit(true, true, true, true);
        emit IERC7579Account.ModuleInstalled(MODULE_TYPE_EXECUTOR, address(guardiansExecutor));
        entryPoint.handleOps(userOps, bundler);

        vm.assertTrue(guardiansExecutor.isInitialized(address(account)), "Executor not initialized");
        vm.assertTrue(guardiansExecutor.isModuleType(MODULE_TYPE_EXECUTOR), "Wrong module type");
    }

    function test_uninstallExecutor() public {
        test_installExecutor();
        bytes memory data =
            abi.encodeCall(ModularSmartAccount.uninstallModule, (MODULE_TYPE_EXECUTOR, address(guardiansExecutor), ""));
        PackedUserOperation[] memory userOps = makeSignedUserOp(data);
        vm.expectEmit(true, true, true, true);
        emit IERC7579Account.ModuleUninstalled(MODULE_TYPE_EXECUTOR, address(guardiansExecutor));
        entryPoint.handleOps(userOps, bundler);
        vm.assertTrue(!guardiansExecutor.isInitialized(address(account)), "Executor not uninitialized");
    }

    function test_proposeGuardian() public {
        test_installExecutor();

        bytes memory data = abi.encodeCall(GuardianExecutor.proposeGuardian, (guardian.addr));
        bytes memory call = encodeCall(address(guardiansExecutor), 0, data);
        PackedUserOperation[] memory userOps = makeSignedUserOp(call);

        vm.expectEmit(true, true, true, true);
        emit GuardianExecutor.GuardianProposed(address(account), guardian.addr);
        entryPoint.handleOps(userOps, bundler);

        address[] memory guardians = guardiansExecutor.guardiansFor(address(account));
        vm.assertEq(guardians.length, 1, "Invalid guardians array");
        vm.assertEq(guardians[0], guardian.addr, "Guardian not found for account");

        (bool isPresent, bool isActive, uint48 timestamp) =
            guardiansExecutor.guardianStatusFor(address(account), guardian.addr);
        vm.assertTrue(isPresent, "Guardian not present after proposing");
        vm.assertTrue(!isActive, "Proposed guardian should not be active");
        vm.assertTrue(timestamp != 0, "Proposed guardian timestamp is empty");
    }

    function test_acceptGuardian() public {
        test_proposeGuardian();

        vm.prank(guardian.addr);
        vm.expectEmit(true, true, true, true);
        emit GuardianExecutor.GuardianAdded(address(account), guardian.addr);
        guardiansExecutor.acceptGuardian(address(account));

        (, bool isActive,) = guardiansExecutor.guardianStatusFor(address(account), guardian.addr);
        vm.assertTrue(isActive, "Guardian not active after accepting");
    }

    function test_initRecovery() public {
        test_acceptGuardian();

        GuardianExecutor.RecoveryRequest memory recovery;

        vm.prank(guardian.addr);
        vm.expectEmit(true, true, true, false); // don't check data
        emit GuardianExecutor.RecoveryInitiated(address(account), guardian.addr, recovery);
        guardiansExecutor.initializeRecovery(
            address(account), GuardianExecutor.RecoveryType.EOA, abi.encode(newOwner.addr)
        );

        (GuardianExecutor.RecoveryType recoveryType, bytes memory data, uint256 timestamp) =
            guardiansExecutor.pendingRecovery(address(account));
        vm.assertEq(uint256(recoveryType), uint256(GuardianExecutor.RecoveryType.EOA), "Invalid recovery type");
        vm.assertEq(abi.decode(data, (address)), newOwner.addr, "Invalid recovery data");
        vm.assertTrue(timestamp != 0, "Recovery timestamp is empty");
    }

    function test_finishRecovery() public {
        test_initRecovery();

        vm.warp(2 days);

        vm.prank(guardian.addr);
        vm.expectEmit(true, true, true, true);
        emit GuardianExecutor.RecoveryFinished(address(account));
        guardiansExecutor.finalizeRecovery(address(account));

        vm.assertTrue(eoaValidator.isOwnerOf(address(account), newOwner.addr), "New owner was not added");

        assertPendingRecoveryCleared();
    }

    function test_cancelRecovery() public {
        test_initRecovery();

        vm.prank(address(account));
        vm.expectEmit(true, true, true, true);
        emit GuardianExecutor.RecoveryDiscarded(address(account));
        guardiansExecutor.discardRecovery();
        assertPendingRecoveryCleared();
    }

    function testRevert_earlyRecovery() public {
        test_initRecovery();
        vm.prank(guardian.addr);
        vm.expectPartialRevert(GuardianExecutor.RecoveryTimestampInvalid.selector);
        guardiansExecutor.finalizeRecovery(address(account));
    }

    function assertPendingRecoveryCleared() internal view {
        (GuardianExecutor.RecoveryType recoveryType, bytes memory data, uint256 timestamp) =
            guardiansExecutor.pendingRecovery(address(account));
        vm.assertEq(uint256(recoveryType), uint256(GuardianExecutor.RecoveryType.None), "Recovery type not cleared");
        vm.assertEq(data.length, 0, "Recovery data not cleared");
        vm.assertEq(timestamp, 0, "Recovery timestamp not cleared");
    }
}
