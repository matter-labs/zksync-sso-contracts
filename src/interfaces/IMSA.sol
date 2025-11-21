// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC7579Account } from "./IERC7579Account.sol";
import { IERC4337Account } from "./IERC4337Account.sol";

interface IMSA is IERC7579Account, IERC4337Account {
    // Error thrown when an unsupported ModuleType is requested
    error UnsupportedModuleType(uint256 moduleTypeId);
    // Error thrown when account installs/unistalls module with mismatched input `moduleTypeId`
    error MismatchModuleTypeId(uint256 moduleTypeId);

    /// @notice Initializes the account. Function might be called directly, or by a Factory.
    /// @dev All passed in modules have to be unique, and of exactly one module type.
    /// @param modules Array of module addresses to be installed in the account
    /// @param data Array of initialization data corresponding to each module
    function initializeAccount(address[] calldata modules, bytes[] calldata data) external payable;
}
