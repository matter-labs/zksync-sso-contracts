// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import { IERC7579Account } from "./IERC7579Account.sol";
import { IERC4337Account } from "./IERC4337Account.sol";

import { CallType, ExecType, ModeCode } from "../libraries/ModeLib.sol";

interface IMSA is IERC7579Account, IERC4337Account {
    // Error thrown when an unsupported ModuleType is requested
    error UnsupportedModuleType(uint256 moduleTypeId);
    // Error thrown when an execution with an unsupported CallType was made
    error UnsupportedCallType(CallType callType);
    // Error thrown when an execution with an unsupported ExecType was made
    error UnsupportedExecType(ExecType execType);
    // Error thrown when account initialization fails
    error AccountInitializationFailed();
    // Error thrown when account installs/unistalls module with mismatched input `moduleTypeId`
    error MismatchModuleTypeId(uint256 moduleTypeId);

    /// @dev Initializes the account. Function might be called directly, or by a Factory
    function initializeAccount(address[] calldata modules, bytes[] calldata data) external payable;
}
