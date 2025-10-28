// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

import { IFallback, MODULE_TYPE_FALLBACK } from "src/interfaces/IERC7579Module.sol";
import { IMSA } from "src/interfaces/IMSA.sol";

contract MockFallback is IFallback {
    uint256 public value;

    function onInstall(bytes calldata) external { }

    function onUninstall(bytes calldata data) external pure {
        if (data.length > 0) {
            revert("MockFallback: uninstall failed");
        }
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_FALLBACK;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return IMSA(smartAccount)
            .isModuleInstalled(MODULE_TYPE_FALLBACK, address(this), abi.encode(MockFallback.fallbackMethod.selector));
    }

    function fallbackMethod(uint256 _value) external {
        value = _value;
    }
}
