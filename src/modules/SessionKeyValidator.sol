// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { SessionLib } from "../libraries/SessionLib.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { _packValidationData, SIG_VALIDATION_FAILED } from "account-abstraction/core/Helpers.sol";

import { IMSA } from "../interfaces/IMSA.sol";
import "../interfaces/IERC7579Module.sol";

/// @title SessionKeyValidator
/// @author Matter Labs
/// @custom:security-contact security@matterlabs.dev
/// @notice This contract is used to manage sessions for a smart account.
contract SessionKeyValidator is IValidator, IERC165 {
    using SessionLib for SessionLib.SessionStorage;

    event SessionCreated(address indexed account, bytes32 indexed sessionHash, SessionLib.SessionSpec sessionSpec);
    event SessionRevoked(address indexed account, bytes32 indexed sessionHash);

    mapping(address signer => bytes32 sessionHash) public sessionSigner;
    mapping(bytes32 sessionHash => SessionLib.SessionStorage sessionState) internal sessions;

    /// @notice Get the session state for an account
    /// @param account The account to fetch the session state for
    /// @param spec The session specification to get the state of
    /// @return The session state: status, remaining fee limit, transfer limits, call value and call
    /// parameter limits
    function sessionState(address account, SessionLib.SessionSpec calldata spec)
        external
        view
        virtual
        returns (SessionLib.SessionState memory)
    {
        return sessions[keccak256(abi.encode(spec))].getState(account, spec);
    }

    /// @notice Get the status of a session
    /// @param account The account to fetch the session status for
    /// @param sessionHash The session hash to fetch the status of
    /// @return The status of the session: NotInitialized, Active or Closed
    function sessionStatus(address account, bytes32 sessionHash) external view virtual returns (SessionLib.Status) {
        return sessions[sessionHash].status[account];
    }

    /// @inheritdoc IModule
    /// @param data ABI-encoded session specification to immediately create a session, or empty if not needed.
    function onInstall(bytes calldata data) external virtual {
        if (data.length > 0) {
            // This always either succeeds with `true` or reverts within,
            // so we don't need to check the return value.
            SessionLib.SessionSpec memory sessionSpec = abi.decode(data, (SessionLib.SessionSpec));
            _createSession(sessionSpec);
        }
    }

    /// @inheritdoc IModule
    /// @notice Revokes the provided sessions before uninstalling.
    function onUninstall(bytes calldata data) external virtual {
        // Revoke keys before uninstalling
        bytes32[] memory sessionHashes = abi.decode(data, (bytes32[]));
        for (uint256 i = 0; i < sessionHashes.length; i++) {
            revokeKey(sessionHashes[i]);
        }
    }

    /// @inheritdoc IValidator
    /// @notice This module should not be used to validate signatures (including EIP-1271),
    /// as a signature by itself does not have enough information to validate it against a session.
    function isValidSignatureWithSender(address, bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }

    /// @notice Checks for banned call policies.
    /// @dev Banned policies are:
    /// - all calls to account's validators/hooks, e.g.
    ///   + createSession
    ///   + addValidationKey
    ///   + addGuardian
    /// - all calls to the account itself, e.g.
    ///   + addModuleValidator
    ///   + addHook
    ///   + batchCall
    /// @dev can be extended by derived contracts.
    /// @param target The target address of the call
    /// @return true if the call is banned, false otherwise
    function isBannedCall(address target, bytes4 selector) internal view virtual returns (bool) {
        return target == address(this) // this line is technically unnecessary
            || target == address(msg.sender) || IMSA(msg.sender).isModuleInstalled(MODULE_TYPE_VALIDATOR, target, "")
            || IMSA(msg.sender).isModuleInstalled(MODULE_TYPE_EXECUTOR, target, "")
            || IMSA(msg.sender).isModuleInstalled(MODULE_TYPE_FALLBACK, target, abi.encode(selector));
    }

    /// @notice Create a new session for an account
    /// @param sessionSpec The session specification to create a session with
    /// @dev In the sessionSpec, callPolicies should not have duplicated instances of (target, selector) pairs.
    /// Only the first one of the duplicates is considered when validating transactions.
    function createSession(SessionLib.SessionSpec memory sessionSpec) public virtual {
        require(isInitialized(msg.sender), NotInitialized(msg.sender));
        _createSession(sessionSpec);
    }

    /// @notice Same as `createSession`, but does not check if the validator is initialized for the account.
    function _createSession(SessionLib.SessionSpec memory sessionSpec) internal virtual {
        bytes32 sessionHash = keccak256(abi.encode(sessionSpec));

        uint256 totalCallPolicies = sessionSpec.callPolicies.length;
        for (uint256 i = 0; i < totalCallPolicies; i++) {
            require(
                !isBannedCall(sessionSpec.callPolicies[i].target, sessionSpec.callPolicies[i].selector),
                SessionLib.CallPolicyBanned(sessionSpec.callPolicies[i].target, sessionSpec.callPolicies[i].selector)
            );
        }

        require(sessionSpec.signer != address(0), SessionLib.ZeroSigner());
        // Avoid using same session key for multiple sessions, contract-wide
        require(sessionSigner[sessionSpec.signer] == bytes32(0), SessionLib.SignerAlreadyUsed(sessionSpec.signer));
        require(sessionSpec.feeLimit.limitType != SessionLib.LimitType.Unlimited, SessionLib.UnlimitedFees());
        require(
            sessions[sessionHash].status[msg.sender] == SessionLib.Status.NotInitialized,
            SessionLib.SessionAlreadyExists(sessionHash)
        );
        // Sessions should expire in no less than 60 seconds.
        require(sessionSpec.expiresAt >= block.timestamp + 60, SessionLib.SessionExpiresTooSoon(sessionSpec.expiresAt));

        sessions[sessionHash].status[msg.sender] = SessionLib.Status.Active;
        sessionSigner[sessionSpec.signer] = sessionHash;
        emit SessionCreated(msg.sender, sessionHash, sessionSpec);
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) external pure virtual returns (bool) {
        return interfaceId == type(IERC165).interfaceId || interfaceId == type(IValidator).interfaceId
            || interfaceId == type(IModule).interfaceId;
    }

    /// @notice Revoke a session for an account
    /// @param sessionHash The hash of a session to revoke
    /// @dev Decreases the session counter for the account
    function revokeKey(bytes32 sessionHash) public virtual {
        require(sessions[sessionHash].status[msg.sender] == SessionLib.Status.Active, SessionLib.SessionNotActive());
        sessions[sessionHash].status[msg.sender] = SessionLib.Status.Closed;
        emit SessionRevoked(msg.sender, sessionHash);
    }

    /// @notice Revoke multiple sessions for an account
    /// @param sessionHashes An array of session hashes to revoke
    function revokeKeys(bytes32[] calldata sessionHashes) external virtual {
        for (uint256 i = 0; i < sessionHashes.length; i++) {
            revokeKey(sessionHashes[i]);
        }
    }

    /// @inheritdoc IModule
    function isInitialized(address smartAccount) public view virtual returns (bool) {
        return IMSA(smartAccount).isModuleInstalled(MODULE_TYPE_VALIDATOR, address(this), "");
    }

    /// @inheritdoc IValidator
    /// @dev Session spec and period IDs must be provided as validator data.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) public virtual returns (uint256) {
        (bytes memory transactionSignature, SessionLib.SessionSpec memory spec, uint48[] memory periodIds) =
            abi.decode(userOp.signature[20:], (bytes, SessionLib.SessionSpec, uint48[]));
        require(spec.signer != address(0), SessionLib.ZeroSigner());
        bytes32 sessionHash = keccak256(abi.encode(spec));
        uint192 nonceKey = uint192(userOp.nonce >> 64);
        uint192 expectedNonceKey = uint192(uint160(spec.signer));
        require(nonceKey == expectedNonceKey, SessionLib.InvalidNonceKey(nonceKey, expectedNonceKey));
        // this will revert if session spec is violated
        (uint48 validAfter, uint48 validUntil) = sessions[sessionHash].validate(userOp, spec, periodIds);

        // slither-disable-next-line unused-return
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(userOpHash, transactionSignature);
        if (err != ECDSA.RecoverError.NoError || signer == address(0) || signer != spec.signer) {
            return SIG_VALIDATION_FAILED;
        }
        // This check is separate and performed last to prevent gas estimation failures
        (uint48 newValidAfter, uint48 newValidUntil) =
            sessions[sessionHash].validateFeeLimit(userOp, spec, periodIds[0]);
        validAfter = newValidAfter > validAfter ? validAfter : newValidAfter;
        validUntil = newValidUntil < validUntil ? validUntil : newValidUntil;
        return _packValidationData(false, validUntil, validAfter);
    }

    /// @inheritdoc IModule
    function isModuleType(uint256 moduleTypeId) external pure virtual returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }
}
