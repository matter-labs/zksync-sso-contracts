// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { SessionLib } from "../../src/libraries/SessionLib.sol";

/// @title SessionLib Type Exporter
/// @notice Mock contract that exports SessionLib types to the ABI
/// @dev This contract exists solely to force the Solidity compiler to include
/// SessionLib struct and enum definitions in the generated ABI JSON.
/// It should never be deployed or called in production.
contract SessionLibTypeExporter {
    // ============================================
    // Type Export Functions (for ABI generation)
    // ============================================

    /// @notice Exports SessionSpec type to ABI
    /// @dev Never call this function - it exists only for ABI generation
    function exportSessionSpec(SessionLib.SessionSpec calldata) external pure { }

    /// @notice Exports SessionState type to ABI
    /// @dev Never call this function - it exists only for ABI generation
    function exportSessionState(SessionLib.SessionState calldata) external pure { }

    /// @notice Exports CallSpec type to ABI
    /// @dev Never call this function - it exists only for ABI generation
    function exportCallSpec(SessionLib.CallSpec calldata) external pure { }

    /// @notice Exports TransferSpec type to ABI
    /// @dev Never call this function - it exists only for ABI generation
    function exportTransferSpec(SessionLib.TransferSpec calldata) external pure { }

    /// @notice Exports Constraint type to ABI
    /// @dev Never call this function - it exists only for ABI generation
    function exportConstraint(SessionLib.Constraint calldata) external pure { }

    /// @notice Exports UsageLimit type to ABI
    /// @dev Never call this function - it exists only for ABI generation
    function exportUsageLimit(SessionLib.UsageLimit calldata) external pure { }

    /// @notice Exports LimitState type to ABI
    /// @dev Never call this function - it exists only for ABI generation
    function exportLimitState(SessionLib.LimitState calldata) external pure { }

    /// @notice Exports enum types to ABI
    /// @dev Never call this function - it exists only for ABI generation
    function exportEnums() external pure returns (SessionLib.Status, SessionLib.LimitType, SessionLib.Condition) { }
}
