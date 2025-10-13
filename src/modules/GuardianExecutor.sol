// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { EnumerableMap } from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import { LibERC7579 } from "solady/accounts/LibERC7579.sol";

import { IExecutor, MODULE_TYPE_EXECUTOR, MODULE_TYPE_VALIDATOR } from "../interfaces/IERC7579Module.sol";
import { IMSA } from "../interfaces/IMSA.sol";
import { WebAuthnValidator } from "./WebAuthnValidator.sol";
import { EOAKeyValidator } from "./EOAKeyValidator.sol";
import { IERC7579Account } from "../interfaces/IERC7579Account.sol";

/// @title GuardianExecutor
/// @author Matter Labs
/// @custom:security-contact security@matterlabs.dev
/// @dev This contract allows account recovery using trusted guardians.
contract GuardianExecutor is IExecutor {
    using EnumerableMap for EnumerableMap.AddressToUintMap;

    enum RecoveryType {
        None,
        EOA,
        Passkey
    }

    struct RecoveryRequest {
        RecoveryType recoveryType;
        bytes data;
        uint48 timestamp;
    }

    event RecoveryInitiated(address indexed account, address indexed guardian, RecoveryRequest request);
    event RecoveryFinished(address indexed account);
    event RecoveryDiscarded(address indexed account);

    event GuardianProposed(address indexed account, address indexed guardian);
    event GuardianAdded(address indexed account, address indexed guardian);
    event GuardianRemoved(address indexed account, address indexed guardian);

    error GuardianInvalidAddress(address guardian);
    error GuardianAlreadyPresent(address account, address guardian);
    error GuardianNotFound(address account, address guardian);
    error GuardianNotActive(address account, address guardian);
    error RecoveryInProgress(address account);
    error NoRecoveryInProgress(address account);
    error ValidatorNotInstalled(address account, address validator);
    error RecoveryTimestampInvalid(uint48 timestamp);
    error UnsupportedRecoveryType(RecoveryType recoveryType);

    uint256 public constant REQUEST_VALIDITY_TIME = 72 hours;
    uint256 public constant REQUEST_DELAY_TIME = 24 hours;

    address public immutable webAuthValidator;
    address public immutable eoaValidator;

    mapping(address account => EnumerableMap.AddressToUintMap guardians) private accountGuardians;
    mapping(address account => RecoveryRequest recoveryData) public pendingRecovery;

    /// @notice This modifier allows execution only by active guardian of account
    /// @param account Address of account for which we verify guardian existence
    modifier onlyGuardianOf(address account) {
        (bool exists, uint256 guardianData) = accountGuardians[account].tryGet(msg.sender);
        require(exists, GuardianNotFound(account, msg.sender));

        (bool isActive,) = _unpackGuardianData(guardianData);
        require(isActive, GuardianNotActive(account, msg.sender));
        // Continue execution if called by guardian
        _;
    }

    constructor(address _webAuthValidator, address _eoaValidator) {
        webAuthValidator = _webAuthValidator;
        eoaValidator = _eoaValidator;
    }

    /// @notice Validator initiator for given sso account.
    /// @dev This module does not support initialization on creation,
    /// but ensures that the WebAuthValidator is enabled for calling SsoAccount.
    function onInstall(bytes calldata) external view virtual { }

    /// @notice Removes all past guardians when this module is disabled in a account
    function onUninstall(bytes calldata) external virtual {
        accountGuardians[msg.sender].clear();
        discardRecovery();
    }

    function proposeGuardian(address newGuardian) external virtual {
        require(isInitialized(msg.sender), NotInitialized(msg.sender));
        require(newGuardian != address(0) && newGuardian != msg.sender, GuardianInvalidAddress(newGuardian));
        require(!accountGuardians[msg.sender].contains(newGuardian), GuardianAlreadyPresent(msg.sender, newGuardian));

        // slither-disable-next-line unused-return
        accountGuardians[msg.sender].set(newGuardian, _packGuardianData(false, uint48(block.timestamp)));

        emit GuardianProposed(msg.sender, newGuardian);
    }

    function removeGuardian(address guardianToRemove) external virtual {
        require(isInitialized(msg.sender), NotInitialized(msg.sender));
        require(accountGuardians[msg.sender].contains(guardianToRemove), GuardianNotFound(msg.sender, guardianToRemove));

        (bool wasActive,) = _unpackGuardianData(accountGuardians[msg.sender].get(guardianToRemove));
        // slither-disable-next-line unused-return
        accountGuardians[msg.sender].remove(guardianToRemove);

        if (wasActive) {
            // In case an ongoing recovery was started by this guardian, discard it to prevent a potential
            // account overtake by a second malicious guardian.
            discardRecovery();
        }

        emit GuardianRemoved(msg.sender, guardianToRemove);
    }

    function acceptGuardian(address accountToGuard) external virtual returns (bool) {
        require(isInitialized(accountToGuard), NotInitialized(accountToGuard));
        (bool exists, uint256 data) = accountGuardians[accountToGuard].tryGet(msg.sender);
        require(exists, GuardianNotFound(accountToGuard, msg.sender));

        (bool isActive, uint48 addedAt) = _unpackGuardianData(data);
        require(addedAt != 0); // sanity check

        if (isActive) {
            // No need to do anything, guardian already active
            return false;
        }

        // TODO: why do we need this addedAt timestamp at all?
        // slither-disable-next-line unused-return
        accountGuardians[accountToGuard].set(msg.sender, _packGuardianData(true, addedAt));

        emit GuardianAdded(accountToGuard, msg.sender);
        return true;
    }

    function initializeRecovery(address accountToRecover, RecoveryType recoveryType, bytes calldata data)
        external
        virtual
        onlyGuardianOf(accountToRecover)
    {
        require(isInitialized(accountToRecover), NotInitialized(accountToRecover));
        checkInstalledValidator(accountToRecover, recoveryType);
        uint256 pendingRecoveryTimestamp = pendingRecovery[accountToRecover].timestamp;
        require(
            pendingRecoveryTimestamp == 0 || pendingRecoveryTimestamp + REQUEST_VALIDITY_TIME < block.timestamp,
            RecoveryInProgress(accountToRecover)
        );
        RecoveryRequest memory recovery = RecoveryRequest(recoveryType, data, uint48(block.timestamp));
        pendingRecovery[accountToRecover] = recovery;
        emit RecoveryInitiated(accountToRecover, msg.sender, recovery);
    }

    function checkInstalledValidator(address account, RecoveryType recoveryType) internal view {
        // slither-disable-start incorrect-equality
        if (recoveryType == RecoveryType.EOA) {
            require(
                IMSA(account).isModuleInstalled(MODULE_TYPE_VALIDATOR, eoaValidator, ""),
                ValidatorNotInstalled(account, eoaValidator)
            );
        } else if (recoveryType == RecoveryType.Passkey) {
            require(
                IMSA(account).isModuleInstalled(MODULE_TYPE_VALIDATOR, webAuthValidator, ""),
                ValidatorNotInstalled(account, webAuthValidator)
            );
        } else {
            revert UnsupportedRecoveryType(recoveryType);
        }
        // slither-disable-end incorrect-equality
    }

    function finalizeRecovery(address account) external virtual returns (bytes memory returnData) {
        RecoveryRequest memory recovery = pendingRecovery[account];
        checkInstalledValidator(account, recovery.recoveryType);
        require(recovery.timestamp != 0 && recovery.data.length != 0, NoRecoveryInProgress(account));
        require(
            recovery.timestamp + REQUEST_DELAY_TIME < block.timestamp
                && recovery.timestamp + REQUEST_VALIDITY_TIME > block.timestamp,
            RecoveryTimestampInvalid(recovery.timestamp)
        );

        // NOTE: the fact that recovery type is not `None` is checked in `checkInstalledValidator`.
        // slither-disable-next-line incorrect-equality
        address validator = recovery.recoveryType == RecoveryType.EOA ? eoaValidator : webAuthValidator;
        // slither-disable-next-line incorrect-equality
        bytes4 selector = recovery.recoveryType == RecoveryType.EOA
            ? EOAKeyValidator.addOwner.selector
            : WebAuthnValidator.addValidationKey.selector;
        bytes memory execution = abi.encodePacked(validator, uint256(0), abi.encodePacked(selector, recovery.data));

        delete pendingRecovery[account];
        bytes32 mode = LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, 0, 0);
        returnData = IERC7579Account(account).executeFromExecutor(mode, execution)[0];
        emit RecoveryFinished(account);
    }

    function guardiansFor(address account) external view returns (address[] memory) {
        return accountGuardians[account].keys();
    }

    function guardianStatusFor(address account, address guardian)
        external
        view
        returns (bool isPresent, bool isActive, uint48 addedAt)
    {
        uint256 data;
        (isPresent, data) = accountGuardians[account].tryGet(guardian);
        if (isPresent) {
            (isActive, addedAt) = _unpackGuardianData(data);
        }
    }

    function discardRecovery() public virtual {
        RecoveryRequest memory recovery = pendingRecovery[msg.sender];
        delete pendingRecovery[msg.sender];
        if (recovery.timestamp != 0 && recovery.data.length != 0) {
            emit RecoveryDiscarded(msg.sender);
        }
    }

    function _packGuardianData(bool isActive, uint48 addedAt) internal pure returns (uint256) {
        return (isActive ? 1 : 0) | (uint256(addedAt) << 1);
    }

    function _unpackGuardianData(uint256 data) internal pure returns (bool isActive, uint48 addedAt) {
        isActive = (data & 1) != 0;
        addedAt = uint48(data >> 1);
    }

    function isModuleType(uint256 moduleType) external pure returns (bool) {
        return moduleType == MODULE_TYPE_EXECUTOR;
    }

    function isInitialized(address account) public view returns (bool) {
        return IMSA(account).isModuleInstalled(MODULE_TYPE_EXECUTOR, address(this), "");
    }
}
