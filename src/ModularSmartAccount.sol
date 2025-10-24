// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { ERC1271 } from "solady/accounts/ERC1271.sol";
import { LibERC7579 } from "solady/accounts/LibERC7579.sol";

import { ExecutionHelper } from "./core/ExecutionHelper.sol";
import { IERC7579Account } from "./interfaces/IERC7579Account.sol";
import { IMSA } from "./interfaces/IMSA.sol";
import { ERC1271Handler } from "./core/ERC1271Handler.sol";
import { RegistryAdapter } from "./core/RegistryAdapter.sol";

import "./interfaces/IERC7579Module.sol" as ERC7579;

/// @author zeroknots.eth | rhinestone.wtf
/// Reference implementation of a very simple ERC7579 Account.
/// This account implements CallType: SINGLE, BATCH and DELEGATECALL.
/// This account implements ExecType: DEFAULT and TRY.
/// Hook support is implemented
contract ModularSmartAccount is IMSA, ExecutionHelper, ERC1271Handler, RegistryAdapter, Initializable {
    using LibERC7579 for bytes32;

    constructor() {
        _disableInitializers();
    }

    /// @inheritdoc IERC7579Account
    /// @dev this function is only callable by the entry point or the account itself
    /// @dev this function demonstrates how to implement
    /// CallType SINGLE and BATCH and ExecType DEFAULT and TRY
    /// @dev this function demonstrates how to implement hook support (modifier)
    function execute(bytes32 mode, bytes calldata executionCalldata) external payable onlyEntryPointOrSelf {
        // slither-disable-next-line unused-return
        _handleExecute(mode, executionCalldata);
    }

    /// @inheritdoc IERC7579Account
    /// @dev this function is only callable by an installed executor module
    /// @dev this function demonstrates how to implement
    /// CallType SINGLE and BATCH and ExecType DEFAULT and TRY
    /// @dev this function demonstrates how to implement hook support (modifier)
    function executeFromExecutor(bytes32 mode, bytes calldata executionCalldata)
        external
        payable
        onlyExecutorModule
        withRegistry(msg.sender, ERC7579.MODULE_TYPE_EXECUTOR)
        returns (bytes[] memory returnData)
    {
        returnData = _handleExecute(mode, executionCalldata);
    }

    /// @dev ERC-4337 executeUserOp according to ERC-4337 v0.7
    ///         This function is intended to be called by ERC-4337 EntryPoint.sol
    /// @dev Ensure adequate authorization control: i.e. onlyEntryPointOrSelf
    ///      The implementation of the function is OPTIONAL
    ///
    /// @param userOp PackedUserOperation struct (see ERC-4337 v0.7+)
    function executeUserOp(
        PackedUserOperation calldata userOp,
        bytes32 // userOpHash
    ) external payable onlyEntryPoint {
        bytes calldata callData = userOp.callData[4:];
        (bool success,) = address(this).delegatecall(callData);
        if (!success) revert ExecutionFailed();
    }

    /// @inheritdoc IERC7579Account
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData)
        external
        payable
        onlyEntryPointOrSelf
        withRegistry(module, moduleTypeId)
    {
        if (!ERC7579.IModule(module).isModuleType(moduleTypeId)) revert MismatchModuleTypeId(moduleTypeId);

        if (moduleTypeId == ERC7579.MODULE_TYPE_VALIDATOR) {
            _installValidator(module, initData);
        } else if (moduleTypeId == ERC7579.MODULE_TYPE_EXECUTOR) {
            _installExecutor(module, initData);
        } else if (moduleTypeId == ERC7579.MODULE_TYPE_FALLBACK) {
            _installFallbackHandler(module, initData);
        } else {
            revert UnsupportedModuleType(moduleTypeId);
        }
        emit ModuleInstalled(moduleTypeId, module);
    }

    /// @inheritdoc IERC7579Account
    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData)
        external
        payable
        onlyEntryPointOrSelf
    {
        if (moduleTypeId == ERC7579.MODULE_TYPE_VALIDATOR) {
            _uninstallValidator(module, deInitData, false);
        } else if (moduleTypeId == ERC7579.MODULE_TYPE_EXECUTOR) {
            _uninstallExecutor(module, deInitData, false);
        } else if (moduleTypeId == ERC7579.MODULE_TYPE_FALLBACK) {
            _uninstallFallbackHandler(module, deInitData, false);
        } else {
            revert UnsupportedModuleType(moduleTypeId);
        }
        emit ModuleUninstalled(moduleTypeId, module);
    }

    /// @notice Uninstall a module while allowing its cleanup to revert without bubbling up.
    /// @param moduleTypeId Type identifier of the module being removed.
    /// @param module Address of the module to unlink.
    /// @param deInitData ABI-encoded data forwarded to the uninstall routine when possible.
    function unlinkModule(uint256 moduleTypeId, address module, bytes calldata deInitData)
        external
        payable
        onlyEntryPointOrSelf
    {
        if (moduleTypeId == ERC7579.MODULE_TYPE_VALIDATOR) {
            _uninstallValidator(module, deInitData, true);
        } else if (moduleTypeId == ERC7579.MODULE_TYPE_EXECUTOR) {
            _uninstallExecutor(module, deInitData, true);
        } else if (moduleTypeId == ERC7579.MODULE_TYPE_FALLBACK) {
            _uninstallFallbackHandler(module, deInitData, true);
        } else {
            revert UnsupportedModuleType(moduleTypeId);
        }
        emit ModuleUninstalled(moduleTypeId, module);
    }

    /// @dev ERC-4337 validateUserOp according to ERC-4337 v0.7
    ///         This function is intended to be called by ERC-4337 EntryPoint.sol
    /// this validation function should decode / sload the validator module to validate the userOp
    /// and call it.
    /// @param userOp PackedUserOperation struct (see ERC-4337 v0.7+)
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        payable
        virtual
        onlyEntryPoint
        payPrefund(missingAccountFunds)
        returns (uint256 validSignature)
    {
        address validator = address(bytes20(userOp.signature[:20]));

        // check if validator is enabled. If not terminate the validation phase.
        if (!_isValidatorInstalled(validator)) {
            return ERC7579.VALIDATION_FAILED;
        } else {
            // bubble up the return value of the validator module
            validSignature = ERC7579.IValidator(validator).validateUserOp(userOp, userOpHash);
        }
    }

    /// @inheritdoc IERC7579Account
    function isValidSignature(bytes32 hash, bytes calldata data)
        public
        view
        override(ERC1271, IERC7579Account)
        returns (bytes4)
    {
        return super.isValidSignature(hash, data);
    }

    /// @inheritdoc IERC7579Account
    function isModuleInstalled(uint256 moduleTypeId, address module, bytes calldata additionalContext)
        external
        view
        override
        returns (bool)
    {
        if (moduleTypeId == ERC7579.MODULE_TYPE_VALIDATOR) {
            return _isValidatorInstalled(module);
        } else if (moduleTypeId == ERC7579.MODULE_TYPE_EXECUTOR) {
            return _isExecutorInstalled(module);
        } else if (moduleTypeId == ERC7579.MODULE_TYPE_FALLBACK) {
            return _isFallbackHandlerInstalled(abi.decode(additionalContext, (bytes4)), module);
        } else {
            return false;
        }
    }

    /// @inheritdoc IERC7579Account
    function accountId() external view virtual override returns (string memory) {
        // vendor.flavour.SemVer
        return "ZKsyncSSO.mvp.v0.0.1";
    }

    /// @inheritdoc IERC7579Account
    function supportsExecutionMode(bytes32 mode) external view virtual override returns (bool isSupported) {
        bytes1 callType = mode.getCallType();
        bytes1 execType = mode.getExecType();
        if (callType == LibERC7579.CALLTYPE_BATCH) isSupported = true;
        else if (callType == LibERC7579.CALLTYPE_SINGLE) isSupported = true;
        else if (callType == LibERC7579.CALLTYPE_DELEGATECALL) isSupported = true;
        // if callType is not single, batch or delegatecall return false
        else return false;

        if (execType == LibERC7579.EXECTYPE_DEFAULT) isSupported = true;
        else if (execType == LibERC7579.EXECTYPE_TRY) isSupported = true;
        // if execType is not default or try, return false
        else return false;
    }

    /// @inheritdoc IERC7579Account
    function supportsModule(uint256 moduleTypeId) external view virtual override returns (bool) {
        if (moduleTypeId == ERC7579.MODULE_TYPE_VALIDATOR) return true;
        else if (moduleTypeId == ERC7579.MODULE_TYPE_EXECUTOR) return true;
        else if (moduleTypeId == ERC7579.MODULE_TYPE_FALLBACK) return true;
        else return false;
    }

    /// @inheritdoc IMSA
    function initializeAccount(address[] calldata modules, bytes[] calldata data)
        external
        payable
        virtual
        initializer
    {
        for (uint256 i = 0; i < modules.length; i++) {
            address module = modules[i];
            if (ERC7579.IModule(module).isModuleType(ERC7579.MODULE_TYPE_VALIDATOR)) {
                _installValidator(module, data[i]);
            }
            if (ERC7579.IModule(module).isModuleType(ERC7579.MODULE_TYPE_EXECUTOR)) {
                _installExecutor(module, data[i]);
            }
            if (ERC7579.IModule(module).isModuleType(ERC7579.MODULE_TYPE_FALLBACK)) {
                _installFallbackHandler(module, data[i]);
            }
        }
    }
}
