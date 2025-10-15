// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import { IModule, MODULE_TYPE_HOOK } from "src/interfaces/IERC7579Module.sol";

contract MockHook is IModule {
    function onInstall(bytes calldata) external { }
    function onUninstall(bytes calldata data) external { }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_HOOK;
    }

    function isInitialized(address) external pure returns (bool) {
        return false;
    }
}
