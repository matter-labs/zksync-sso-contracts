// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { LibERC7579 } from "solady/accounts/LibERC7579.sol";
import { IERC721Receiver } from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import { IERC1155Receiver } from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

import { IERC7579Account } from "src/interfaces/IERC7579Account.sol";
import { MODULE_TYPE_FALLBACK } from "src/interfaces/IERC7579Module.sol";
import { ModularSmartAccount } from "src/ModularSmartAccount.sol";
import { ModuleManager } from "src/core/ModuleManager.sol";
import { IERC7484Registry } from "src/interfaces/IERC7484Registry.sol";
import { RegistryAdapter } from "src/core/RegistryAdapter.sol";

import { MockFallback } from "./mocks/MockFallback.sol";
import { MockRegistry } from "./mocks/MockRegistry.sol";
import { MSATest } from "./MSATest.sol";

contract FallbackTest is MSATest {
    MockFallback public mockFallback;
    MockRegistry public mockRegistry;

    address public attester = makeAddr("attester");

    function setUp() public override {
        super.setUp();

        mockFallback = new MockFallback();
        mockRegistry = new MockRegistry();
    }

    function test_setRegistry() public {
        address[] memory attesters = new address[](1);
        attesters[0] = attester;

        bytes memory data = abi.encodeCall(RegistryAdapter.setRegistry, (IERC7484Registry(mockRegistry), attesters, 1));

        PackedUserOperation[] memory userOps = makeSignedUserOp(data);

        vm.expectEmit(true, true, true, true);
        emit RegistryAdapter.ERC7484RegistryConfigured(address(mockRegistry));
        entryPoint.handleOps(userOps, bundler);

        vm.assertEq(mockRegistry._threshold(address(account)), 1, "Registry not set correctly");
    }

    function testRevert_installNonAttestedModule() public {
        test_setRegistry();

        bytes memory initData = abi.encodePacked(MockFallback.fallbackMethod.selector, LibERC7579.CALLTYPE_SINGLE);
        bytes memory data =
            abi.encodeCall(IERC7579Account.installModule, (MODULE_TYPE_FALLBACK, address(mockFallback), initData));

        bytes memory reason = abi.encodeWithSignature("Error(string)", "Threshold not met");
        expectUserOpRevert(makeSignedUserOp(data)[0], reason);
    }

    function test_installAttestedModule() public {
        test_setRegistry();

        vm.prank(attester);
        mockRegistry.attest(address(mockFallback), MODULE_TYPE_FALLBACK, 1 days);

        test_installFallback();
    }

    function test_installFallback() public {
        bytes memory initData = abi.encodePacked(MockFallback.fallbackMethod.selector, LibERC7579.CALLTYPE_SINGLE);
        bytes memory data =
            abi.encodeCall(IERC7579Account.installModule, (MODULE_TYPE_FALLBACK, address(mockFallback), initData));
        PackedUserOperation[] memory userOps = makeSignedUserOp(data);

        vm.expectEmit(true, true, true, true);
        emit IERC7579Account.ModuleInstalled(MODULE_TYPE_FALLBACK, address(mockFallback));
        entryPoint.handleOps(userOps, bundler);

        vm.assertTrue(mockFallback.isInitialized(address(account)), "Fallback not initialized");
        vm.assertEq(
            account.getActiveFallbackHandler(MockFallback.fallbackMethod.selector).handler,
            address(mockFallback),
            "Fallback not set correctly"
        );
    }

    function testRevert_installFallback_duplicateSelector() public {
        test_installFallback();

        bytes memory initData = abi.encodePacked(MockFallback.fallbackMethod.selector, LibERC7579.CALLTYPE_SINGLE);
        bytes memory data =
            abi.encodeCall(IERC7579Account.installModule, (MODULE_TYPE_FALLBACK, address(mockFallback), initData));

        bytes memory reason =
            abi.encodeWithSelector(ModuleManager.SelectorAlreadyUsed.selector, MockFallback.fallbackMethod.selector);
        expectUserOpRevert(makeSignedUserOp(data)[0], reason);

        vm.assertEq(
            account.getActiveFallbackHandler(MockFallback.fallbackMethod.selector).handler,
            address(mockFallback),
            "Fallback handler unexpectedly removed"
        );
    }

    function test_callFallback() public {
        test_installFallback();

        MockFallback(address(account)).fallbackMethod(42);
        vm.assertEq(mockFallback.value(), 42, "Fallback method not called correctly");
    }

    function test_uninstallFallback() public {
        test_installFallback();

        bytes memory initData = abi.encodePacked(MockFallback.fallbackMethod.selector);
        bytes memory data =
            abi.encodeCall(IERC7579Account.uninstallModule, (MODULE_TYPE_FALLBACK, address(mockFallback), initData));
        PackedUserOperation[] memory userOps = makeSignedUserOp(data);

        vm.expectEmit(true, true, true, true);
        emit IERC7579Account.ModuleUninstalled(MODULE_TYPE_FALLBACK, address(mockFallback));
        entryPoint.handleOps(userOps, bundler);

        vm.assertTrue(!mockFallback.isInitialized(address(account)), "Fallback not uninitialized");
        vm.assertEq(
            account.getActiveFallbackHandler(MockFallback.fallbackMethod.selector).handler,
            address(0),
            "Fallback not removed correctly"
        );
    }

    function testRevert_uninstallFallback_onUninstall() public {
        test_installFallback();

        bytes memory deinitData = abi.encodePacked(MockFallback.fallbackMethod.selector, "some data");
        bytes memory data =
            abi.encodeCall(IERC7579Account.uninstallModule, (MODULE_TYPE_FALLBACK, address(mockFallback), deinitData));

        bytes memory reason = abi.encodeWithSignature("Error(string)", "MockFallback: uninstall failed");
        expectUserOpRevert(makeSignedUserOp(data)[0], reason);

        vm.assertTrue(mockFallback.isInitialized(address(account)), "Fallback still initialized but should not be");
        vm.assertEq(
            account.getActiveFallbackHandler(MockFallback.fallbackMethod.selector).handler,
            address(mockFallback),
            "Fallback removed but should not have been"
        );
    }

    function testRevert_uninstallFallback_notInstalled() public {
        bytes memory data = abi.encodeCall(
            IERC7579Account.uninstallModule,
            (MODULE_TYPE_FALLBACK, address(mockFallback), abi.encodePacked(MockFallback.fallbackMethod.selector))
        );

        bytes memory reason =
            abi.encodeWithSelector(ModuleManager.NoFallbackHandler.selector, MockFallback.fallbackMethod.selector);
        expectUserOpRevert(makeSignedUserOp(data)[0], reason);
    }

    function test_unlinkFallback() public {
        test_installFallback();

        // This deinit data will cause `onUninstall` to revert
        bytes memory initData = abi.encodePacked(MockFallback.fallbackMethod.selector, "some data");
        bytes memory data =
            abi.encodeCall(ModularSmartAccount.unlinkModule, (MODULE_TYPE_FALLBACK, address(mockFallback), initData));
        PackedUserOperation[] memory userOps = makeSignedUserOp(data);

        vm.expectEmit(true, true, true, true);
        bytes memory reason = abi.encodeWithSignature("Error(string)", "MockFallback: uninstall failed");
        emit ModuleManager.ModuleUnlinked(MODULE_TYPE_FALLBACK, address(mockFallback), reason);
        entryPoint.handleOps(userOps, bundler);

        vm.assertTrue(!mockFallback.isInitialized(address(account)), "Fallback not uninitialized");
        vm.assertEq(
            account.getActiveFallbackHandler(MockFallback.fallbackMethod.selector).handler,
            address(0),
            "Fallback not removed correctly"
        );
    }

    function test_tokenFallbacks() public {
        bytes4 result721 = IERC721Receiver(address(account)).onERC721Received(address(this), address(this), 1, "");
        vm.assertEq(result721, IERC721Receiver.onERC721Received.selector, "ERC721 fallback failed");

        bytes4 result1155 = IERC1155Receiver(address(account)).onERC1155Received(address(this), address(this), 1, 1, "");
        vm.assertEq(result1155, IERC1155Receiver.onERC1155Received.selector, "ERC1155 fallback failed");
    }
}
