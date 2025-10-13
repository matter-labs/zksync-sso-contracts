// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import { IERC7579Account } from "./IERC7579Account.sol";
import { IERC4337Account } from "./IERC4337Account.sol";

interface IMSA is IERC7579Account, IERC4337Account {
    // Error thrown when an unsupported ModuleType is requested
    error UnsupportedModuleType(uint256 moduleTypeId);
    // Error thrown when account installs/unistalls module with mismatched input `moduleTypeId`
    error MismatchModuleTypeId(uint256 moduleTypeId);

    /// @dev Initializes the account. Function might be called directly, or by a Factory
    function initializeAccount(address[] calldata modules, bytes[] calldata data) external payable;
}
