// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import { SafeCast } from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";

import { LibERC7579 } from "solady/accounts/LibERC7579.sol";

import { IExecutor, IModule, MODULE_TYPE_EXECUTOR, MODULE_TYPE_VALIDATOR } from "../../interfaces/IERC7579Module.sol";
import { WebAuthnValidator } from "../WebAuthnValidator.sol";
import { EOAKeyValidator } from "../EOAKeyValidator.sol";
import { GuardianExecutor } from "../GuardianExecutor.sol";
import { IERC7579Account } from "../../interfaces/IERC7579Account.sol";

/// @title GuardianBasedRecoveryExecutor
/// @author Oleg Bedrin - <o.bedrin@xsolla.com> - Xsolla ZK
/// @notice GuardianExecutor with implicit global guardian - no per-account setup required
/// @dev Recovery flow: initializeRecovery() -> wait delay -> finalizeRecovery()
contract GuardianBasedRecoveryExecutor is GuardianExecutor, Initializable, AccessControl {
    /// @notice Role for submitting recovery requests
    bytes32 public constant SUBMITTER_ROLE = keccak256("SUBMITTER_ROLE");
    
    /// @notice Role for finalizing pending recoveries
    bytes32 public constant FINALIZER_ROLE = keccak256("FINALIZER_ROLE");

    /// @notice Thrown when guardian management functions are called
    error GuardianModificationDisabled();

    /// @notice Thrown when trying to discard non-existent recovery
    /// @param account The account with no active recovery
    error CannotDiscardRecoveryFor(address account);

    constructor(address _webAuthValidator, address _eoaValidator) GuardianExecutor(_webAuthValidator, _eoaValidator) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _disableInitializers();
    }

    /// @notice Initializer function.
    /// @param _admin Admin role recipient
    /// @param _finalizer Finalizer role recipient  
    /// @param _submitter Submitter role recipient
    function initialize(address _admin, address _finalizer, address _submitter) external initializer {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(FINALIZER_ROLE, _finalizer);
        _grantRole(SUBMITTER_ROLE, _submitter);
    }

    /// @notice Start recovery process for an account
    /// @param accountToRecover Target smart account
    /// @param recoveryType EOA or Passkey recovery
    /// @param data Encoded validator payload (new key material)
    function initializeRecovery(address accountToRecover, RecoveryType recoveryType, bytes calldata data)
        external
        virtual
        override
        onlyRole(SUBMITTER_ROLE)
    {
        _initializeRecovery(accountToRecover, recoveryType, data);
    }

    /// @notice Execute pending recovery after delay period
    /// @param account Account to recover
    /// @return returnData Result from validator call
    function finalizeRecovery(address account)
        external
        virtual
        override
        onlyRole(FINALIZER_ROLE)
        returns (bytes memory returnData)
    {
        return _finalizeRecovery(account);
    }

    /// @notice Cancel caller's pending recovery
    function discardRecovery() public virtual override {
        _discardRecoveryFor(msg.sender, true);
    }

    /// @notice Cancel pending recovery for target account
    /// @param account Account whose recovery to cancel
    function discardRecoveryFor(address account) external virtual onlyRole(SUBMITTER_ROLE) {
        _discardRecoveryFor(account, true);
    }

    /// @notice Cleanup on module uninstall
    function onUninstall(bytes calldata) external virtual override {
        _discardRecoveryFor(msg.sender, false);
    }

    /// @inheritdoc GuardianExecutor
    /// @notice Disabled in this implementation; always reverts.
    function proposeGuardian(
        address /* newGuardian*/
    )
        external
        pure
        virtual
        override
    {
        revert GuardianModificationDisabled();
    }

    /// @inheritdoc GuardianExecutor
    /// @notice Disabled in this implementation; always reverts.
    function acceptGuardian(
        address /* accountToGuard*/
    )
        external
        pure
        virtual
        override
        returns (bool)
    {
        revert GuardianModificationDisabled();
    }

    /// @inheritdoc GuardianExecutor
    /// @notice Disabled in this implementation; always reverts.
    function removeGuardian(
        address /* guardianToRemove*/
    )
        external
        pure
        virtual
        override
    {
        revert GuardianModificationDisabled();
    }

    /// @dev Internal helper to discard an existing recovery.
    /// Reverts when no active recovery exists (CannotDiscardRecoveryFor).
    /// @param account Target account whose recovery (if active) is removed.
    function _discardRecoveryFor(address account, bool throws) internal {
        RecoveryRequest memory recovery = pendingRecovery[account];
        if (recovery.timestamp != 0 && recovery.data.length != 0) {
            delete pendingRecovery[account];
            emit RecoveryDiscarded(account);
        } else if (throws) {
            revert CannotDiscardRecoveryFor(account);
        }
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId)
        public
        pure
        virtual
        override(GuardianExecutor, AccessControl)
        returns (bool)
    {
        return interfaceId == type(IExecutor).interfaceId || interfaceId == type(IModule).interfaceId
            || interfaceId == type(IERC165).interfaceId || interfaceId == type(IAccessControl).interfaceId;
    }

    // Reserve storage space for upgradeability.
    uint256[50] private __gap;
}
