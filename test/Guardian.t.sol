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
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeSignedUserOp(data, owner.key, address(eoaValidator));

        vm.expectEmit(true, false, false, false);
        emit IERC7579Account.ModuleInstalled(MODULE_TYPE_EXECUTOR, address(guardiansExecutor));
        entryPoint.handleOps(userOps, bundler);
    }

    function test_proposeGuardian() public {
        test_installExecutor();

        bytes memory data = abi.encodeCall(GuardianExecutor.proposeGuardian, (guardian.addr));
        bytes memory call = ExecutionLib.encodeSingle(address(guardiansExecutor), 0, data);
        bytes memory callData = abi.encodeCall(IERC7579Account.execute, (ModeLib.encodeSimpleSingle(), call));
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeSignedUserOp(callData, owner.key, address(eoaValidator));

        vm.expectEmit(true, true, true, true);
        emit GuardianExecutor.GuardianProposed(address(account), guardian.addr);
        entryPoint.handleOps(userOps, bundler);

        address[] memory guardians = guardiansExecutor.guardiansFor(address(account));
        vm.assertEq(guardians[0], guardian.addr);
        vm.assertEq(guardians.length, 1);

        (bool isPresent, bool isActive, uint48 timestamp) =
            guardiansExecutor.guardianStatusFor(address(account), guardian.addr);
        vm.assertTrue(isPresent);
        vm.assertTrue(!isActive);
        vm.assertTrue(timestamp != 0);
    }

    function test_acceptGuardian() public {
        test_proposeGuardian();

        vm.prank(guardian.addr);
        vm.expectEmit(true, true, true, true);
        emit GuardianExecutor.GuardianAdded(address(account), guardian.addr);
        guardiansExecutor.acceptGuardian(address(account));

        (, bool isActive,) = guardiansExecutor.guardianStatusFor(address(account), guardian.addr);
        vm.assertTrue(isActive);
    }

    function test_recovery() public {
        test_acceptGuardian();

        GuardianExecutor.RecoveryRequest memory recovery;

        vm.prank(guardian.addr);
        vm.expectEmit(true, true, true, false);
        emit GuardianExecutor.RecoveryInitiated(address(account), guardian.addr, recovery);
        guardiansExecutor.initializeRecovery(
            address(account), GuardianExecutor.RecoveryType.EOA, abi.encode(newOwner.addr)
        );

        vm.warp(2 days);

        vm.prank(guardian.addr);
        vm.expectEmit(true, true, true, true);
        emit GuardianExecutor.RecoveryFinished(address(account));
        guardiansExecutor.finalizeRecovery(address(account));

        address[] memory owners = eoaValidator.getOwners(address(account));
        vm.assertEq(owners.length, 2);
        vm.assertTrue(owners[0] == newOwner.addr || owners[1] == newOwner.addr);
    }
}
