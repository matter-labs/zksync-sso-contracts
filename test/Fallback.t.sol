// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { LibERC7579 } from "solady/accounts/LibERC7579.sol";

import { IERC7579Account } from "src/interfaces/IERC7579Account.sol";
import { MODULE_TYPE_FALLBACK } from "src/interfaces/IERC7579Module.sol";

import { MockFallback } from "./mocks/MockFallback.sol";
import { MSATest } from "./MSATest.sol";

contract FallbackTest is MSATest {
    MockFallback public mockFallback;

    function setUp() public override {
        super.setUp();

        mockFallback = new MockFallback();
    }

    function test_installFallback() public {
        bytes memory initData = abi.encodePacked(MockFallback.fallbackMethod.selector, LibERC7579.CALLTYPE_SINGLE);
        bytes memory data =
            abi.encodeCall(IERC7579Account.installModule, (MODULE_TYPE_FALLBACK, address(mockFallback), initData));
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeSignedUserOp(data, owner.key, address(eoaValidator));

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
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeSignedUserOp(data, owner.key, address(eoaValidator));

        vm.expectEmit(true, true, true, true);
        emit IERC7579Account.ModuleUninstalled(MODULE_TYPE_FALLBACK, address(mockFallback));
        entryPoint.handleOps(userOps, bundler);

        vm.assertTrue(!mockFallback.isInitialized(address(account)), "Fallback not initialized");
        vm.assertEq(
            account.getActiveFallbackHandler(MockFallback.fallbackMethod.selector).handler,
            address(0),
            "Fallback not removed correctly"
        );
    }
}
