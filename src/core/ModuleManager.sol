// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "../interfaces/IERC7579Module.sol";

/// @title ModuleManager
/// @author zeroknots.eth | rhinestone.wtf
/// @dev This contract manages Validator, Executor and Fallback modules for the MSA
/// NOTE: the linked list is just an example. accounts may implement this differently
abstract contract ModuleManager {
    using EnumerableSet for EnumerableSet.AddressSet;

    error InvalidModule(address module);
    error NoFallbackHandler(bytes4 selector);
    error CannotRemoveLastValidator();
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

    function $moduleManager() internal pure virtual returns (ModuleManagerStorage storage $ims) {
        bytes32 position = MODULEMANAGER_STORAGE_LOCATION;
        assembly {
            $ims.slot := position
        }
    }

    modifier onlyExecutorModule() {
        if (!$moduleManager().$executors.contains(msg.sender)) revert InvalidModule(msg.sender);
        _;
    }

    modifier onlyValidatorModule(address validator) {
        if (!$moduleManager().$validators.contains(validator)) revert InvalidModule(validator);
        _;
    }

    function _onUninstallFail(bytes memory reason, bool force, uint256 moduleTypeId, address module) internal {
        if (!force) {
            assembly {
                // forward revert data
                revert(add(reason, 32), mload(reason))
            }
        } else {
            emit ModuleUnlinked(moduleTypeId, module, reason);
        }
    }

    /////////////////////////////////////////////////////
    //  Manage Validators
    ////////////////////////////////////////////////////

    function _installValidator(address validator, bytes calldata data) internal virtual {
        require($moduleManager().$validators.add(validator), AlreadyInstalled(validator));
        IValidator(validator).onInstall(data);
    }

    function _uninstallValidator(address validator, bytes calldata data, bool force) internal {
        require($moduleManager().$validators.remove(validator), NotInstalled(validator));
        require($moduleManager().$validators.length() > 0, CannotRemoveLastValidator());
        try IValidator(validator).onUninstall(data) { }
        catch (bytes memory reason) {
            _onUninstallFail(reason, force, MODULE_TYPE_VALIDATOR, validator);
        }
    }

    function _isValidatorInstalled(address validator) internal view virtual returns (bool) {
        return $moduleManager().$validators.contains(validator);
    }

    /////////////////////////////////////////////////////
    //  Manage Executors
    ////////////////////////////////////////////////////

    function _installExecutor(address executor, bytes calldata data) internal {
        require($moduleManager().$executors.add(executor), AlreadyInstalled(executor));
        IExecutor(executor).onInstall(data);
    }

    function _uninstallExecutor(address executor, bytes calldata data, bool force) internal {
        require($moduleManager().$executors.remove(executor), NotInstalled(executor));
        try IExecutor(executor).onUninstall(data) { }
        catch (bytes memory reason) {
            _onUninstallFail(reason, force, MODULE_TYPE_EXECUTOR, executor);
        }
    }

    function _isExecutorInstalled(address executor) internal view virtual returns (bool) {
        return $moduleManager().$executors.contains(executor);
    }

    /////////////////////////////////////////////////////
    //  Manage Fallback
    ////////////////////////////////////////////////////

    function _installFallbackHandler(address handler, bytes calldata params) internal virtual {
        bytes4 selector = bytes4(params[0:4]);
        bytes1 calltype = params[4];
        bytes calldata initData = params[5:];
        require(!_isFallbackHandlerInstalled(selector), SelectorAlreadyUsed(selector));
        $moduleManager().$fallbacks[selector] = FallbackHandler(handler, calltype);
        IFallback(handler).onInstall(initData);
    }

    function _uninstallFallbackHandler(address handler, bytes calldata deInitData, bool force) internal virtual {
        bytes4 selector = bytes4(deInitData[0:4]);
        bytes calldata _deInitData = deInitData[4:];
        require(_isFallbackHandlerInstalled(selector), NoFallbackHandler(selector));
        FallbackHandler memory activeFallback = $moduleManager().$fallbacks[selector];
        require(activeFallback.handler == handler, NotInstalled(handler));
        $moduleManager().$fallbacks[selector] = FallbackHandler(address(0), 0);
        try IFallback(handler).onUninstall(_deInitData) { }
        catch (bytes memory reason) {
            _onUninstallFail(reason, force, MODULE_TYPE_FALLBACK, handler);
        }
    }

    function _isFallbackHandlerInstalled(bytes4 functionSig) internal view virtual returns (bool) {
        FallbackHandler storage $fallback = $moduleManager().$fallbacks[functionSig];
        return $fallback.handler != address(0);
    }

    function _isFallbackHandlerInstalled(bytes4 functionSig, address _handler) internal view virtual returns (bool) {
        FallbackHandler storage $fallback = $moduleManager().$fallbacks[functionSig];
        return $fallback.handler == _handler;
    }

    function getActiveFallbackHandler(bytes4 functionSig) external view virtual returns (FallbackHandler memory) {
        return $moduleManager().$fallbacks[functionSig];
    }

    /// @dev For receiving ETH.
    receive() external payable { }

    // FALLBACK
    fallback() external payable {
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
