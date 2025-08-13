// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { ERC1271 } from "solady/accounts/ERC1271.sol";

import { ExecutionLib } from "./libraries/ExecutionLib.sol";
import { ExecutionHelper } from "./core/ExecutionHelper.sol";
import { IERC7579Account, Execution } from "./interfaces/IERC7579Account.sol";
import { IMSA } from "./interfaces/IMSA.sol";
import { ERC1271Handler } from "./core/ERC1271Handler.sol";
import { RegistryAdapter } from "./core/RegistryAdapter.sol";
import { Initializable } from "./libraries/Initializable.sol";

import {
    IModule,
    IValidator,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_FALLBACK,
    VALIDATION_FAILED,
    VALIDATION_SUCCESS,
    MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
    MODULE_TYPE_PREVALIDATION_HOOK_ERC1271
} from "./interfaces/IERC7579Module.sol";
import {
    CallType,
    ModeCode,
    ExecType,
    EXECTYPE_DEFAULT,
    EXECTYPE_TRY,
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH,
    CALLTYPE_DELEGATECALL,
    ModeLib
} from "./libraries/ModeLib.sol";

/**
 * @author zeroknots.eth | rhinestone.wtf
 * Reference implementation of a very simple ERC7579 Account.
 * This account implements CallType: SINGLE, BATCH and DELEGATECALL.
 * This account implements ExecType: DEFAULT and TRY.
 * Hook support is implemented
 */
contract ModularSmartAccount is IMSA, ExecutionHelper, ERC1271Handler, RegistryAdapter {
    using ExecutionLib for bytes;
    using ModeLib for ModeCode;

    /**
     * @inheritdoc IERC7579Account
     * @dev this function is only callable by the entry point or the account itself
     * @dev this function demonstrates how to implement
     * CallType SINGLE and BATCH and ExecType DEFAULT and TRY
     * @dev this function demonstrates how to implement hook support (modifier)
     */
    function execute(
        ModeCode mode,
        bytes calldata executionCalldata
    )
        external
        payable
        onlyEntryPointOrSelf /*withHook*/
    {
        // slither-disable-next-line unused-return
        (CallType callType, ExecType execType,,) = mode.decode();

        // check if calltype is batch or single
        if (callType == CALLTYPE_BATCH) {
            // destructure executionCallData according to batched exec
            Execution[] calldata executions = executionCalldata.decodeBatch();
            // check if execType is revert or try
            if (execType == EXECTYPE_DEFAULT) _execute(executions);
            else if (execType == EXECTYPE_TRY) _tryExecute(executions);
            else revert UnsupportedExecType(execType);
        } else if (callType == CALLTYPE_SINGLE) {
            // destructure executionCallData according to single exec
            (address target, uint256 value, bytes calldata callData) = executionCalldata.decodeSingle();
            // check if execType is revert or try
            if (execType == EXECTYPE_DEFAULT) _execute(target, value, callData);
            // TODO: implement event emission for tryExecute singleCall
            else if (execType == EXECTYPE_TRY) _tryExecute(target, value, callData);
            else revert UnsupportedExecType(execType);
        } else if (callType == CALLTYPE_DELEGATECALL) {
            // destructure executionCallData according to single exec
            address delegate = address(uint160(bytes20(executionCalldata[0:20])));
            bytes calldata callData = executionCalldata[20:];
            // check if execType is revert or try
            if (execType == EXECTYPE_DEFAULT) _executeDelegatecall(delegate, callData);
            else if (execType == EXECTYPE_TRY) _tryExecuteDelegatecall(delegate, callData);
            else revert UnsupportedExecType(execType);
        } else {
            revert UnsupportedCallType(callType);
        }
    }

    /**
     * @inheritdoc IERC7579Account
     * @dev this function is only callable by an installed executor module
     * @dev this function demonstrates how to implement
     * CallType SINGLE and BATCH and ExecType DEFAULT and TRY
     * @dev this function demonstrates how to implement hook support (modifier)
     */
    function executeFromExecutor(
        ModeCode mode,
        bytes calldata executionCalldata
    )
        external
        payable
        onlyExecutorModule
        // withHook
        withRegistry(msg.sender, MODULE_TYPE_EXECUTOR)
        returns (
            bytes[] memory returnData // TODO returnData is not used
        )
    {
        // slither-disable-next-line unused-return
        (CallType callType, ExecType execType,,) = mode.decode();

        // check if calltype is batch or single
        if (callType == CALLTYPE_BATCH) {
            // destructure executionCallData according to batched exec
            Execution[] calldata executions = executionCalldata.decodeBatch();
            // check if execType is revert or try
            if (execType == EXECTYPE_DEFAULT) returnData = _execute(executions);
            else if (execType == EXECTYPE_TRY) returnData = _tryExecute(executions);
            else revert UnsupportedExecType(execType);
        } else if (callType == CALLTYPE_SINGLE) {
            // destructure executionCallData according to single exec
            (address target, uint256 value, bytes calldata callData) = executionCalldata.decodeSingle();
            returnData = new bytes[](1);
            bool success;
            // check if execType is revert or try
            if (execType == EXECTYPE_DEFAULT) {
                returnData[0] = _execute(target, value, callData);
            }
            // TODO: implement event emission for tryExecute singleCall
            else if (execType == EXECTYPE_TRY) {
                (success, returnData[0]) = _tryExecute(target, value, callData);
                if (!success) emit TryExecuteUnsuccessful(0, returnData[0]);
            } else {
                revert UnsupportedExecType(execType);
            }
        } else if (callType == CALLTYPE_DELEGATECALL) {
            // destructure executionCallData according to single exec
            address delegate = address(uint160(bytes20(executionCalldata[0:20])));
            bytes calldata callData = executionCalldata[20:];
            // check if execType is revert or try
            if (execType == EXECTYPE_DEFAULT) _executeDelegatecall(delegate, callData);
            else if (execType == EXECTYPE_TRY) _tryExecuteDelegatecall(delegate, callData);
            else revert UnsupportedExecType(execType);
        } else {
            revert UnsupportedCallType(callType);
        }
    }

    /**
     * @dev ERC-4337 executeUserOp according to ERC-4337 v0.7
     *         This function is intended to be called by ERC-4337 EntryPoint.sol
     * @dev Ensure adequate authorization control: i.e. onlyEntryPointOrSelf
     *      The implementation of the function is OPTIONAL
     *
     * @param userOp PackedUserOperation struct (see ERC-4337 v0.7+)
     */
    function executeUserOp(
        PackedUserOperation calldata userOp,
        bytes32 // userOpHash
    )
        external
        payable
        onlyEntryPoint
    {
        bytes calldata callData = userOp.callData[4:];
        (bool success,) = address(this).delegatecall(callData);
        if (!success) revert ExecutionFailed();
    }

    /**
     * @inheritdoc IERC7579Account
     */
    function installModule(
        uint256 moduleTypeId,
        address module,
        bytes calldata initData
    )
        external
        payable
        onlyEntryPointOrSelf
        withRegistry(module, moduleTypeId)
    {
        if (!IModule(module).isModuleType(moduleTypeId)) revert MismatchModuleTypeId(moduleTypeId);

        if (moduleTypeId == MODULE_TYPE_VALIDATOR) {
            _installValidator(module, initData);
        } else if (moduleTypeId == MODULE_TYPE_EXECUTOR) {
            _installExecutor(module, initData);
        } else if (moduleTypeId == MODULE_TYPE_FALLBACK) {
            _installFallbackHandler(module, initData);
        } else {
            revert UnsupportedModuleType(moduleTypeId);
        }
        emit ModuleInstalled(moduleTypeId, module);
    }

    /**
     * @inheritdoc IERC7579Account
     */
    function uninstallModule(
        uint256 moduleTypeId,
        address module,
        bytes calldata deInitData
    )
        external
        payable
        onlyEntryPointOrSelf
    {
        if (moduleTypeId == MODULE_TYPE_VALIDATOR) {
            _uninstallValidator(module, deInitData);
        } else if (moduleTypeId == MODULE_TYPE_EXECUTOR) {
            _uninstallExecutor(module, deInitData);
        } else if (moduleTypeId == MODULE_TYPE_FALLBACK) {
            _uninstallFallbackHandler(module, deInitData);
        } else {
            revert UnsupportedModuleType(moduleTypeId);
        }
        emit ModuleUninstalled(moduleTypeId, module);
    }

    /**
     * @dev ERC-4337 validateUserOp according to ERC-4337 v0.7
     *         This function is intended to be called by ERC-4337 EntryPoint.sol
     * this validation function should decode / sload the validator module to validate the userOp
     * and call it.
     *
     * @dev MSA MUST implement this function signature.
     * @param userOp PackedUserOperation struct (see ERC-4337 v0.7+)
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    )
        external
        payable
        virtual
        onlyEntryPoint
        payPrefund(missingAccountFunds)
        returns (uint256 validSignature)
    {
        address validator = address(bytes20(userOp.signature[12:32]));

        // check if validator is enabled. If not terminate the validation phase.
        if (!_isValidatorInstalled(validator)) {
            return VALIDATION_FAILED;
        } else {
            // bubble up the return value of the validator module
            validSignature = IValidator(validator).validateUserOp(userOp, userOpHash);
        }
    }

    function isValidSignature(
        bytes32 hash,
        bytes calldata data
    )
        public
        view
        override(ERC1271, IERC7579Account)
        returns (bytes4)
    {
        return super.isValidSignature(hash, data);
    }

    /**
     * @inheritdoc IERC7579Account
     */
    function isModuleInstalled(
        uint256 moduleTypeId,
        address module,
        bytes calldata additionalContext
    )
        external
        view
        override
        returns (bool)
    {
        if (moduleTypeId == MODULE_TYPE_VALIDATOR) {
            return _isValidatorInstalled(module);
        } else if (moduleTypeId == MODULE_TYPE_EXECUTOR) {
            return _isExecutorInstalled(module);
        } else if (moduleTypeId == MODULE_TYPE_FALLBACK) {
            return _isFallbackHandlerInstalled(abi.decode(additionalContext, (bytes4)), module);
        } else {
            return false;
        }
    }

    /**
     * @inheritdoc IERC7579Account
     */
    function accountId() external view virtual override returns (string memory) {
        // vendor.flavour.SemVer
        return "ZKsyncSSO.mvp.v0.0.1";
    }

    /**
     * @inheritdoc IERC7579Account
     */
    function supportsExecutionMode(ModeCode mode) external view virtual override returns (bool isSupported) {
        // slither-disable-next-line unused-return
        (CallType callType, ExecType execType,,) = mode.decode();
        if (callType == CALLTYPE_BATCH) isSupported = true;
        else if (callType == CALLTYPE_SINGLE) isSupported = true;
        else if (callType == CALLTYPE_DELEGATECALL) isSupported = true;
        // if callType is not single, batch or delegatecall return false
        else return false;

        if (execType == EXECTYPE_DEFAULT) isSupported = true;
        else if (execType == EXECTYPE_TRY) isSupported = true;
        // if execType is not default or try, return false
        else return false;
    }

    /**
     * @inheritdoc IERC7579Account
     */
    function supportsModule(uint256 modulTypeId) external view virtual override returns (bool) {
        if (modulTypeId == MODULE_TYPE_VALIDATOR) return true;
        else if (modulTypeId == MODULE_TYPE_EXECUTOR) return true;
        else if (modulTypeId == MODULE_TYPE_FALLBACK) return true;
        else if (modulTypeId == MODULE_TYPE_HOOK) return true;
        else if (
            modulTypeId == MODULE_TYPE_PREVALIDATION_HOOK_ERC1271
                || modulTypeId == MODULE_TYPE_PREVALIDATION_HOOK_ERC4337
        ) return true;
        else return false;
    }

    /**
     * @dev Initializes the account. Function might be called directly, or by a Factory
     * @param data. encoded data that can be used during the initialization phase
     */
    function initializeAccount(address validator, bytes calldata data) public payable virtual {
        // protect this function to only be callable when used with the proxy factory or when
        // account calls itself
        if (msg.sender != address(this)) {
            Initializable.checkInitializable();
        }

        _installValidator(address(validator), data);
    }
}
