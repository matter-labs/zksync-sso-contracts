// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { LibERC7579 } from "solady/accounts/LibERC7579.sol";

/// @title Execution
/// @dev This contract executes calls in the context of this contract.
/// @author zeroknots.eth | rhinestone.wtf
/// shoutout to solady (vectorized, ross) for this code
/// https://github.com/Vectorized/solady/blob/main/src/accounts/ERC4337.sol
contract ExecutionHelper {
    using LibERC7579 for bytes32;

    error ExecutionFailed();
    error UnsupportedCallType(bytes1 callType);
    error UnsupportedExecType(bytes1 execType);

    event TryExecuteUnsuccessful(uint256 batchExecutionindex, bytes result);

    function _execute(bytes32[] calldata executions) internal returns (bytes[] memory result) {
        uint256 length = executions.length;
        result = new bytes[](length);

        for (uint256 i; i < length; ++i) {
            (address target, uint256 value, bytes calldata callData) = LibERC7579.getExecution(executions, i);
            result[i] = _execute(target, value, callData);
        }
    }

    function _tryExecute(bytes32[] calldata executions) internal returns (bytes[] memory result) {
        uint256 length = executions.length;
        result = new bytes[](length);

        for (uint256 i; i < length; ++i) {
            (address target, uint256 value, bytes calldata callData) = LibERC7579.getExecution(executions, i);
            bool success;
            (success, result[i]) = _tryExecute(target, value, callData);
            if (!success) emit TryExecuteUnsuccessful(i, result[i]);
        }
    }

    function _execute(address target, uint256 value, bytes calldata callData)
        internal
        virtual
        returns (bytes memory result)
    {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            calldatacopy(result, callData.offset, callData.length)
            if iszero(call(gas(), target, value, result, callData.length, codesize(), 0x00)) {
                // Bubble up the revert if the call reverts.
                returndatacopy(result, 0x00, returndatasize())
                revert(result, returndatasize())
            }
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }

    function _tryExecute(address target, uint256 value, bytes calldata callData)
        internal
        virtual
        returns (bool success, bytes memory result)
    {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            calldatacopy(result, callData.offset, callData.length)
            success := call(gas(), target, value, result, callData.length, codesize(), 0x00)
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }

    /// @dev Execute a delegatecall with `delegate` on this account.
    function _executeDelegatecall(address delegate, bytes calldata callData) internal returns (bytes memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            calldatacopy(result, callData.offset, callData.length)
            // Forwards the `data` to `delegate` via delegatecall.
            if iszero(delegatecall(gas(), delegate, result, callData.length, codesize(), 0x00)) {
                // Bubble up the revert if the call reverts.
                returndatacopy(result, 0x00, returndatasize())
                revert(result, returndatasize())
            }
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }

    /// @dev Execute a delegatecall with `delegate` on this account and catch reverts.
    function _tryExecuteDelegatecall(address delegate, bytes calldata callData)
        internal
        returns (bool success, bytes memory result)
    {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            calldatacopy(result, callData.offset, callData.length)
            // Forwards the `data` to `delegate` via delegatecall.
            success := delegatecall(gas(), delegate, result, callData.length, codesize(), 0x00)
            mstore(result, returndatasize()) // Store the length.
            let o := add(result, 0x20)
            returndatacopy(o, 0x00, returndatasize()) // Copy the returndata.
            mstore(0x40, add(o, returndatasize())) // Allocate the memory.
        }
    }

    function _handleExecute(bytes32 mode, bytes calldata data) internal returns (bytes[] memory returnData) {
        bytes1 callType = mode.getCallType();
        bytes1 execType = mode.getExecType();

        // check if calltype is batch, single or delegatecall
        if (callType == LibERC7579.CALLTYPE_BATCH) {
            // destructure executionCallData according to batched exec
            bytes32[] calldata executions = LibERC7579.decodeBatch(data);
            // check if execType is revert or try
            if (execType == LibERC7579.EXECTYPE_DEFAULT) returnData = _execute(executions);
            else if (execType == LibERC7579.EXECTYPE_TRY) returnData = _tryExecute(executions);
            else revert UnsupportedExecType(execType);
        } else if (callType == LibERC7579.CALLTYPE_SINGLE) {
            // destructure executionCallData according to single exec
            (address target, uint256 value, bytes calldata callData) = LibERC7579.decodeSingle(data);
            returnData = new bytes[](1);
            bool success;
            // check if execType is revert or try
            if (execType == LibERC7579.EXECTYPE_DEFAULT) {
                returnData[0] = _execute(target, value, callData);
            } else if (execType == LibERC7579.EXECTYPE_TRY) {
                (success, returnData[0]) = _tryExecute(target, value, callData);
                if (!success) emit TryExecuteUnsuccessful(0, returnData[0]);
            } else {
                revert UnsupportedExecType(execType);
            }
        } else if (callType == LibERC7579.CALLTYPE_DELEGATECALL) {
            // destructure executionCallData according to single exec
            (address delegate, bytes calldata callData) = LibERC7579.decodeDelegate(data);
            returnData = new bytes[](1);
            bool success;
            // check if execType is revert or try
            if (execType == LibERC7579.EXECTYPE_DEFAULT) {
                returnData[0] = _executeDelegatecall(delegate, callData);
            } else if (execType == LibERC7579.EXECTYPE_TRY) {
                (success, returnData[0]) = _tryExecuteDelegatecall(delegate, callData);
                if (!success) emit TryExecuteUnsuccessful(0, returnData[0]);
            } else {
                revert UnsupportedExecType(execType);
            }
        } else {
            revert UnsupportedCallType(callType);
        }
    }
}
