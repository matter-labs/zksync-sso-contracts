// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Execution } from "../../src/interfaces/IERC7579Account.sol";

/// @title IERC7579TypeExporter
/// @notice Mock contract that exports Execution struct to the ABI
/// @dev This contract exists solely to force the Solidity compiler to include
/// the Execution struct definition in the generated ABI JSON.
/// It should never be deployed or called in production.
contract IERC7579TypeExporter {
    function exportExecution(Execution calldata) external pure { }
}
