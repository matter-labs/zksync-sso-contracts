// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { LibERC7579 } from "solady/accounts/LibERC7579.sol";

import { RegistryAdapter } from "./RegistryAdapter.sol";
import "../interfaces/IERC7579Module.sol" as ERC7579;

/// @title ModuleManager
/// @author Matter Labs
/// @custom:security-contact security@matterlabs.dev
/// @notice The implementation is inspired by https://github.com/erc7579/erc7579-implementation
/// @dev This contract manages Validator, Executor and Fallback modules for the MSA
/// NOTE: the linked list is just an example. accounts may implement this differently
abstract contract ModuleManager is RegistryAdapter {
    using EnumerableSet for EnumerableSet.AddressSet;

    error InvalidModule(address module);
    error NotEnoughData();
    error NoFallbackHandler(bytes4 selector);
    error CannotRemoveLastValidator();
    error InvalidCallType(bytes1 calltype);
    error SelectorAlreadyUsed(bytes4 selector);
    error AlreadyInstalled(address module);
    error NotInstalled(address module);

    event ModuleUnlinked(uint256 indexed moduleTypeId, address indexed module, bytes error);

    // forgefmt: disable-next-line
    // keccak256(abi.encode(uint256(keccak256("modulemanager.storage.msa")) - 1)) & ~bytes32(uint256(0xff));
    bytes32 internal constant MODULEMANAGER_STORAGE_LOCATION =
        0xe3a55571e8f241b58442871487cc151a8cb048bb4ad24e833467f724ec89a900;

    struct FallbackHandler {
        address handler;
        bytes1 calltype;
    }

    /// @custom:storage-location erc7201:modulemanager.storage.msa
    struct ModuleManagerStorage {
        EnumerableSet.AddressSet $validators;
        EnumerableSet.AddressSet $executors;
        mapping(bytes4 selector => FallbackHandler fallbackHandler) $fallbacks;
    }

    /// @dev Returns the storage pointer used to manage modules for the account.
    function $moduleManager() internal pure virtual returns (ModuleManagerStorage storage $ims) {
        bytes32 position = MODULEMANAGER_STORAGE_LOCATION;
        assembly {
            $ims.slot := position
        }
    }

    /// @dev Ensures that the caller is an installed executor module.
    modifier onlyExecutorModule() {
        if (!$moduleManager().$executors.contains(msg.sender)) revert InvalidModule(msg.sender);
        _;
    }

    /// @dev Ensures that the supplied validator module is installed.
    modifier onlyValidatorModule(address validator) {
        if (!$moduleManager().$validators.contains(validator)) revert InvalidModule(validator);
        _;
    }

    function _uninstallModule(bytes memory deinitData, address module, uint256 moduleTypeId, bool force) internal {
        bytes memory callData = abi.encodeCall(ERC7579.IModule.onUninstall, deinitData);
        uint256 gasLimit = force ? gasleft() / 2 : gasleft();
        bool success;
        assembly {
            success := call(gasLimit, module, 0, add(callData, 0x20), mload(callData), 0, 0)
        }
        if (success) {
            return;
        }
        if (force) {
            uint256 copySize;
            assembly {
                copySize := returndatasize()
            }
            // cap return data size at 256 bytes
            copySize = copySize > 256 ? 256 : copySize;
            bytes memory returnData = new bytes(copySize);
            assembly {
                returndatacopy(add(returnData, 0x20), 0, copySize)
            }
            emit ModuleUnlinked(moduleTypeId, module, returnData);
        } else {
            assembly {
                let size := returndatasize()
                returndatacopy(0, 0, size)
                revert(0, size)
            }
        }
    }

    /////////////////////////////////////////////////////
    //  Manage Validators
    ////////////////////////////////////////////////////

    /// @dev Installs a validator module and triggers its initialization hook.
    /// @param validator Address of the validator module.
    /// @param data Initialization data forwarded to the module.
    function _installValidator(address validator, bytes calldata data) internal virtual {
        require($moduleManager().$validators.add(validator), AlreadyInstalled(validator));
        ERC7579.IValidator(validator).onInstall(data);
    }

    /// @dev Uninstalls a validator module and triggers its teardown hook.
    /// @param validator Address of the validator module.
    /// @param data De-initialization data forwarded to the module.
    /// @param force Whether failures should be swallowed and logged instead of bubbled.
    function _uninstallValidator(address validator, bytes calldata data, bool force) internal {
        require($moduleManager().$validators.remove(validator), NotInstalled(validator));
        require($moduleManager().$validators.length() > 0, CannotRemoveLastValidator());
        _uninstallModule(data, validator, ERC7579.MODULE_TYPE_VALIDATOR, force);
    }

    /// @dev Checks whether a validator module is currently installed.
    /// @param validator Address of the validator module.
    /// @return True if the validator is registered.
    function _isValidatorInstalled(address validator) internal view virtual returns (bool) {
        return $moduleManager().$validators.contains(validator);
    }

    /////////////////////////////////////////////////////
    //  Manage Executors
    ////////////////////////////////////////////////////

    /// @dev Installs an executor module and triggers its initialization hook.
    /// @param executor Address of the executor module.
    /// @param data Initialization data forwarded to the module.
    function _installExecutor(address executor, bytes calldata data) internal {
        require($moduleManager().$executors.add(executor), AlreadyInstalled(executor));
        ERC7579.IExecutor(executor).onInstall(data);
    }

    /// @dev Uninstalls an executor module and triggers its teardown hook.
    /// @param executor Address of the executor module.
    /// @param data De-initialization data forwarded to the module.
    /// @param force Whether failures should be swallowed and logged instead of bubbled.
    function _uninstallExecutor(address executor, bytes calldata data, bool force) internal {
        require($moduleManager().$executors.remove(executor), NotInstalled(executor));
        _uninstallModule(data, executor, ERC7579.MODULE_TYPE_EXECUTOR, force);
    }

    /// @dev Checks whether an executor module is currently installed.
    /// @param executor Address of the executor module.
    /// @return True if the executor is registered.
    function _isExecutorInstalled(address executor) internal view virtual returns (bool) {
        return $moduleManager().$executors.contains(executor);
    }

    /////////////////////////////////////////////////////
    //  Manage Fallback
    ////////////////////////////////////////////////////

    /// @dev Installs a fallback handler linked to a function selector.
    /// @param handler Address of the fallback handler module.
    /// @param params Encoded selector, call type and initialization data.
    function _installFallbackHandler(address handler, bytes calldata params) internal virtual {
        bytes4 selector = bytes4(params[0:4]);
        bytes1 calltype = params[4];
        require(calltype == LibERC7579.CALLTYPE_SINGLE || calltype == LibERC7579.CALLTYPE_STATICCALL, InvalidCallType(calltype));
        bytes calldata initData = params[5:];
        require(!_isFallbackHandlerInstalled(selector), SelectorAlreadyUsed(selector));
        $moduleManager().$fallbacks[selector] = FallbackHandler(handler, calltype);
        ERC7579.IFallback(handler).onInstall(initData);
    }

    /// @dev Uninstalls a fallback handler linked to a function selector.
    /// @param handler Address of the fallback handler module.
    /// @param deInitData Encoded selector and de-initialization data.
    /// @param force Whether failures should be swallowed and logged instead of bubbled.
    function _uninstallFallbackHandler(address handler, bytes calldata deInitData, bool force) internal virtual {
        bytes4 selector = bytes4(deInitData[0:4]);
        bytes calldata _deInitData = deInitData[4:];
        require(_isFallbackHandlerInstalled(selector), NoFallbackHandler(selector));
        FallbackHandler memory activeFallback = $moduleManager().$fallbacks[selector];
        require(activeFallback.handler == handler, NotInstalled(handler));
        $moduleManager().$fallbacks[selector] = FallbackHandler(address(0), 0);
        _uninstallModule(_deInitData, handler, ERC7579.MODULE_TYPE_FALLBACK, force);
    }

    /// @dev Checks whether any fallback handler is set for a selector.
    /// @param functionSig Selector to check.
    /// @return True if a handler is registered.
    function _isFallbackHandlerInstalled(bytes4 functionSig) internal view virtual returns (bool) {
        FallbackHandler storage $fallback = $moduleManager().$fallbacks[functionSig];
        return $fallback.handler != address(0);
    }

    /// @dev Checks whether the registered fallback handler for a selector matches an address.
    /// @param functionSig Selector to check.
    /// @param _handler Expected handler address.
    /// @return True if the handler matches the selector registration.
    function _isFallbackHandlerInstalled(bytes4 functionSig, address _handler) internal view virtual returns (bool) {
        FallbackHandler storage $fallback = $moduleManager().$fallbacks[functionSig];
        return $fallback.handler == _handler;
    }

    /// @notice Retrieve the fallback handler registered for a given selector.
    /// @param functionSig Selector to query.
    /// @return Struct containing handler address and call type metadata.
    function getActiveFallbackHandler(bytes4 functionSig) external view virtual returns (FallbackHandler memory) {
        return $moduleManager().$fallbacks[functionSig];
    }

    /// @dev For receiving ETH.
    receive() external payable { }

    /// @dev Delegates calls to the registered fallback handler or handles ERC token callbacks.
    fallback() external payable {
        if (msg.data.length > 0 && msg.data.length < 4) {
            revert NotEnoughData();
        }

        FallbackHandler storage $fallbackHandler = $moduleManager().$fallbacks[msg.sig];
        address handler = $fallbackHandler.handler;
        bytes1 calltype = $fallbackHandler.calltype;

        if (handler == address(0)) {
            // 0x150b7a02: `onERC721Received(address,address,uint256,bytes)`.
            // 0xf23a6e61: `onERC1155Received(address,address,uint256,uint256,bytes)`.
            // 0xbc197c81: `onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)`.
            if (msg.sig == 0x150b7a02 || msg.sig == 0xf23a6e61 || msg.sig == 0xbc197c81) {
                // These are the ERC721 and ERC1155 safe transfer callbacks.
                // We return the selector as a response to the callback.
                assembly {
                    let s := shr(224, calldataload(0))
                    mstore(0x20, s) // Store `msg.sig`.
                    return(0x3c, 0x20) // Return `msg.sig`.
                }
            } else {
                revert NoFallbackHandler(msg.sig);
            }
        }

        // Verify that the handler is attested in the registry.
        checkWithRegistry(handler, ERC7579.MODULE_TYPE_FALLBACK);

        assembly {
            function allocate(length) -> pos {
                pos := mload(0x40)
                mstore(0x40, add(pos, length))
            }

            let calldataPtr := allocate(calldatasize())
            calldatacopy(calldataPtr, 0, calldatasize())

            // The msg.sender address is shifted to the left by 12 bytes to remove the padding
            // Then the address without padding is stored right after the calldata
            let senderPtr := allocate(20)
            mstore(senderPtr, shl(96, caller()))

            let success := 0
            switch calltype
            case 0xFE {
                // CALLTYPE_STATIC
                // Add 20 bytes for the address appended at the end
                success := staticcall(gas(), handler, calldataPtr, add(calldatasize(), 20), 0, 0)
            }
            case 0x00 {
                // CALLTYPE_SINGLE
                // Add 20 bytes for the address appended at the end
                success := call(gas(), handler, 0, calldataPtr, add(calldatasize(), 20), 0, 0)
            }
            default { return(0, 0) } // Unsupported calltype

            let returnDataPtr := allocate(returndatasize())
            returndatacopy(returnDataPtr, 0, returndatasize())
            if iszero(success) { revert(returnDataPtr, returndatasize()) }
            return(returnDataPtr, returndatasize())
        }
    }
}
