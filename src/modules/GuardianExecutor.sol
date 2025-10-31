// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import { EnumerableMap } from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import { LibERC7579 } from "solady/accounts/LibERC7579.sol";

import { IExecutor, IModule, MODULE_TYPE_EXECUTOR, MODULE_TYPE_VALIDATOR } from "../interfaces/IERC7579Module.sol";
import { IMSA } from "../interfaces/IMSA.sol";
import { WebAuthnValidator } from "./WebAuthnValidator.sol";
import { EOAKeyValidator } from "./EOAKeyValidator.sol";

/// @title GuardianExecutor
/// @author Matter Labs
/// @custom:security-contact security@matterlabs.dev
/// @dev This contract allows account recovery using trusted guardians.
contract GuardianExecutor is IExecutor, IERC165 {
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
    error EmptyRecoveryData();

    uint256 public constant REQUEST_VALIDITY_TIME = 72 hours;
    uint256 public constant REQUEST_DELAY_TIME = 24 hours;

    address public immutable WEBAUTHN_VALIDATOR;
    address public immutable EOA_VALIDATOR;

    mapping(address account => EnumerableMap.AddressToUintMap guardians) private accountGuardians;
    mapping(address account => RecoveryRequest recoveryData) public pendingRecovery;

    /// @notice This modifier allows execution only by active guardian of account
    /// @param account Address of account for which we verify guardian existence
    modifier onlyGuardianOf(address account) {
        (bool exists, uint256 guardianData) = accountGuardians[account].tryGet(msg.sender);
        require(exists, GuardianNotFound(account, msg.sender));

        bool isActive = _unpackGuardianData(guardianData);
        require(isActive, GuardianNotActive(account, msg.sender));
        // Continue execution if called by guardian
        _;
    }

    constructor(address webAuthValidator, address eoaValidator) {
        WEBAUTHN_VALIDATOR = webAuthValidator;
        EOA_VALIDATOR = eoaValidator;
    }

    /// @inheritdoc IModule
    function onInstall(bytes calldata) external view virtual { }

    /// @inheritdoc IModule
    /// @notice Removes all past guardians when this module is disabled in a account
    function onUninstall(bytes calldata) external virtual {
        accountGuardians[msg.sender].clear();
        discardRecovery();
    }

    /// @notice Propose a new guardian candidate for the caller's account.
    /// @param newGuardian Address of the guardian to add after acceptance.
    function proposeGuardian(address newGuardian) external virtual {
        require(isInitialized(msg.sender), NotInitialized(msg.sender));
        require(newGuardian != address(0) && newGuardian != msg.sender, GuardianInvalidAddress(newGuardian));
        require(!accountGuardians[msg.sender].contains(newGuardian), GuardianAlreadyPresent(msg.sender, newGuardian));

        // slither-disable-next-line unused-return
        accountGuardians[msg.sender].set(newGuardian, _packGuardianData(false));

        emit GuardianProposed(msg.sender, newGuardian);
    }

    /// @notice Remove an existing guardian from the caller's account.
    /// @param guardianToRemove Address of the guardian to remove.
    function removeGuardian(address guardianToRemove) external virtual {
        require(isInitialized(msg.sender), NotInitialized(msg.sender));
        require(accountGuardians[msg.sender].contains(guardianToRemove), GuardianNotFound(msg.sender, guardianToRemove));

        bool wasActive = _unpackGuardianData(accountGuardians[msg.sender].get(guardianToRemove));
        // slither-disable-next-line unused-return
        accountGuardians[msg.sender].remove(guardianToRemove);

        if (wasActive) {
            // In case an ongoing recovery was started by this guardian, discard it to prevent a potential
            // account overtake by a second malicious guardian.
            discardRecovery();
        }

        emit GuardianRemoved(msg.sender, guardianToRemove);
    }

    /// @notice Accept a pending guardian proposal for a given account.
    /// @param accountToGuard Account that requested the caller to become a guardian.
    /// @return bool True if the guardian was activated, false if already active.
    function acceptGuardian(address accountToGuard) external virtual returns (bool) {
        require(isInitialized(accountToGuard), NotInitialized(accountToGuard));
        (bool exists, uint256 data) = accountGuardians[accountToGuard].tryGet(msg.sender);
        require(exists, GuardianNotFound(accountToGuard, msg.sender));

        bool isActive = _unpackGuardianData(data);

        if (isActive) {
            // No need to do anything, guardian already active
            return false;
        }

        // slither-disable-next-line unused-return
        accountGuardians[accountToGuard].set(msg.sender, _packGuardianData(true));

        emit GuardianAdded(accountToGuard, msg.sender);
        return true;
    }

    /// @notice Begin the recovery process for an account using a specified validator type.
    /// @param accountToRecover Account undergoing recovery.
    /// @param recoveryType Validator type that will regain access.
    /// @param data ABI-encoded payload forwarded to the validator.
    function initializeRecovery(address accountToRecover, RecoveryType recoveryType, bytes calldata data)
        external
        virtual
        onlyGuardianOf(accountToRecover)
    {
        _initializeRecovery(accountToRecover, recoveryType, data);
    }

    /// @dev Ensure the appropriate validator module is installed for the requested recovery.
    /// @param account Account to inspect.
    /// @param recoveryType Recovery flow type being requested.
    function checkInstalledValidator(address account, RecoveryType recoveryType) internal view {
        // slither-disable-start incorrect-equality
        if (recoveryType == RecoveryType.EOA) {
            require(
                IMSA(account).isModuleInstalled(MODULE_TYPE_VALIDATOR, EOA_VALIDATOR, ""),
                ValidatorNotInstalled(account, EOA_VALIDATOR)
            );
        } else if (recoveryType == RecoveryType.Passkey) {
            require(
                IMSA(account).isModuleInstalled(MODULE_TYPE_VALIDATOR, WEBAUTHN_VALIDATOR, ""),
                ValidatorNotInstalled(account, WEBAUTHN_VALIDATOR)
            );
        } else {
            revert UnsupportedRecoveryType(recoveryType);
        }
        // slither-disable-end incorrect-equality
    }

    /// @notice Finalize a pending recovery after the delay has elapsed.
    /// @param account Account that requested recovery.
    /// @return returnData ABI-encoded response from validator execution.
    function finalizeRecovery(address account) external virtual returns (bytes memory returnData) {
        return _finalizeRecovery(account);
    }

    /// @notice List all guardians configured for an account.
    /// @param account Account to inspect.
    /// @return Array of guardian addresses.
    function guardiansFor(address account) external view returns (address[] memory) {
        return accountGuardians[account].keys();
    }

    /// @notice Get the status of a specific guardian for an account.
    /// @param account Account to inspect.
    /// @param guardian Guardian address to check.
    /// @return isPresent True if the guardian is configured for the account.
    /// @return isActive True if the guardian is active.
    function guardianStatusFor(address account, address guardian)
        external
        view
        returns (bool isPresent, bool isActive)
    {
        uint256 data;
        (isPresent, data) = accountGuardians[account].tryGet(guardian);
        if (isPresent) {
            isActive = _unpackGuardianData(data);
        }
    }

    /// @notice Cancel any ongoing recovery process for the caller's account.
    function discardRecovery() public virtual {
        RecoveryRequest memory recovery = pendingRecovery[msg.sender];
        delete pendingRecovery[msg.sender];
        if (recovery.timestamp != 0) {
            emit RecoveryDiscarded(msg.sender);
        }
    }

    /// @notice Pack guardian data into a single uint256 for storage.
    /// @dev For now this is only a single bool, but something might be added later.
    function _packGuardianData(bool isActive) internal pure returns (uint256) {
        return (isActive ? 1 : 0);
    }

    function _unpackGuardianData(uint256 data) internal pure returns (bool isActive) {
        isActive = (data & 1) != 0;
    }

    /// @inheritdoc IModule
    function isModuleType(uint256 moduleType) external pure returns (bool) {
        return moduleType == MODULE_TYPE_EXECUTOR;
    }

    /// @inheritdoc IModule
    function isInitialized(address account) public view returns (bool) {
        return IMSA(account).isModuleInstalled(MODULE_TYPE_EXECUTOR, address(this), "");
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) external pure virtual returns (bool) {
        return interfaceId == type(IExecutor).interfaceId || interfaceId == type(IModule).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    /// @dev Internal helper to start a recovery process.
    function _initializeRecovery(address accountToRecover, RecoveryType recoveryType, bytes calldata data) internal {
        require(isInitialized(accountToRecover), NotInitialized(accountToRecover));
        checkInstalledValidator(accountToRecover, recoveryType);
        require(data.length > 0, EmptyRecoveryData());
        uint256 pendingRecoveryTimestamp = pendingRecovery[accountToRecover].timestamp;
        require(
            pendingRecoveryTimestamp == 0 || pendingRecoveryTimestamp + REQUEST_VALIDITY_TIME < block.timestamp,
            RecoveryInProgress(accountToRecover)
        );
        RecoveryRequest memory recovery = RecoveryRequest(recoveryType, data, uint48(block.timestamp));
        pendingRecovery[accountToRecover] = recovery;
        emit RecoveryInitiated(accountToRecover, msg.sender, recovery);
    }

    /// @dev Internal helper to finalize a recovery process.
    function _finalizeRecovery(address account) internal returns (bytes memory returnData) {
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
        address validator = recovery.recoveryType == RecoveryType.EOA ? EOA_VALIDATOR : WEBAUTHN_VALIDATOR;
        // slither-disable-next-line incorrect-equality
        bytes4 selector = recovery.recoveryType == RecoveryType.EOA
            ? EOAKeyValidator.addOwner.selector
            : WebAuthnValidator.addValidationKey.selector;
        bytes memory execution = abi.encodePacked(validator, uint256(0), abi.encodePacked(selector, recovery.data));

        delete pendingRecovery[account];
        bytes32 mode = LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, 0, 0);
        returnData = IMSA(account).executeFromExecutor(mode, execution)[0];
        emit RecoveryFinished(account);
    }

    // Reserve storage space for upgradeability.
    uint256[50] private __gap;
}
