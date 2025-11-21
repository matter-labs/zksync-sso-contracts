// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import { AccessControl } from "@openzeppelin/contracts/access/AccessControl.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";

import { SessionLib } from "src/libraries/SessionLib.sol";
import { SessionKeyValidator } from "../SessionKeyValidator.sol";
import { IValidator, IModule } from "src/interfaces/IERC7579Module.sol";

/// @title AllowedSessionsValidator
/// @author Oleg Bedrin - <o.bedrin@xsolla.com> - Xsolla Special Initiatives
/// @custom:security-contact security@matterlabs.dev and o.bedrin@xsolla.com
/// @notice This contract is used to manage allowed sessions for a smart account.
/// @notice This module is controlled by a single entity, which has the power
/// to close all current sessions and disallow any future sessions on this module.
/// @dev This contract has been designed without upgradability in mind.
contract AllowedSessionsValidator is SessionKeyValidator, AccessControl {
    using SessionLib for SessionLib.SessionStorage;

    /// @notice Emitted when session actions are allowed or disallowed.
    /// @param sessionActionsHash The hash of the session actions.
    /// @param allowed Boolean indicating if the session actions are allowed.
    event SessionActionsAllowed(bytes32 indexed sessionActionsHash, bool indexed allowed);

    /// @notice Role identifier for session registry managers.
    bytes32 public constant SESSION_REGISTRY_MANAGER_ROLE = keccak256("SESSION_REGISTRY_MANAGER_ROLE");

    /// @notice Mapping to track whether a session actions is allowed.
    /// @dev The key is the hash of session actions, and the value indicates if the actions are allowed.
    mapping(bytes32 sessionActionsHash => bool allowed) public areSessionActionsAllowed;

    constructor() {
        _grantRole(SESSION_REGISTRY_MANAGER_ROLE, msg.sender);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /// @notice Set whether a session actions hash is allowed or not.
    /// @param sessionActionsHash The hash of the session actions.
    /// @param allowed Boolean indicating if the session actions are allowed.
    /// @dev Session actions represent the set of operations, such as fee limits, call policies, and transfer policies,
    /// that define the behavior and constraints of a session.
    function setSessionActionsAllowed(bytes32 sessionActionsHash, bool allowed)
        external
        virtual
        onlyRole(SESSION_REGISTRY_MANAGER_ROLE)
    {
        if (areSessionActionsAllowed[sessionActionsHash] != allowed) {
            areSessionActionsAllowed[sessionActionsHash] = allowed;
            emit SessionActionsAllowed(sessionActionsHash, allowed);
        }
    }

    /// @notice Get the hash of session actions from a session specification.
    /// @param sessionSpec The session specification.
    /// @return The hash of the session actions.
    /// @dev The session actions hash is derived from the session's fee limits, call policies, and transfer policies.
    function getSessionActionsHash(SessionLib.SessionSpec memory sessionSpec) public view virtual returns (bytes32) {
        uint256 callPoliciesLength = sessionSpec.callPolicies.length;
        bytes memory callPoliciesEncoded;

        for (uint256 i = 0; i < callPoliciesLength; ++i) {
            SessionLib.CallSpec memory policy = sessionSpec.callPolicies[i];
            callPoliciesEncoded = abi.encodePacked(
                callPoliciesEncoded,
                bytes20(policy.target), // Address cast to bytes20
                policy.selector, // Selector
                policy.maxValuePerUse, // Max value per use
                uint256(policy.valueLimit.limitType), // Limit type
                policy.valueLimit.limit, // Limit
                policy.valueLimit.period // Period
            );
        }

        return keccak256(abi.encode(sessionSpec.feeLimit, sessionSpec.transferPolicies, callPoliciesEncoded));
    }

    /// @notice Create a new session for an account.
    /// @param sessionSpec The session specification to create a session with.
    /// @param proof Signature of the session owner to prove address ownership.
    /// @dev A session is a temporary authorization for an account to perform specific actions, defined by the session
    /// specification.
    function _createSession(SessionLib.SessionSpec memory sessionSpec, bytes memory proof)
        internal
        virtual
        override(SessionKeyValidator)
    {
        bytes32 sessionActionsHash = getSessionActionsHash(sessionSpec);
        require(areSessionActionsAllowed[sessionActionsHash], SessionLib.ActionsNotAllowed(sessionActionsHash));
        SessionKeyValidator._createSession(sessionSpec, proof);
    }

    /// @inheritdoc SessionKeyValidator
    function supportsInterface(bytes4 interfaceId)
        public
        pure
        override(SessionKeyValidator, AccessControl)
        returns (bool)
    {
        return interfaceId == type(IERC165).interfaceId || interfaceId == type(IValidator).interfaceId
            || interfaceId == type(IModule).interfaceId || interfaceId == type(IAccessControl).interfaceId;
    }

    /// @notice Validate a session transaction for an account.
    /// @param userOp The user operation to validate.
    /// @param userOpHash The hash of the operation.
    /// @return true if the transaction is valid.
    /// @dev Session spec and period IDs must be provided as validator data.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) public override returns (uint256) {
        // slither-disable-next-line unused-return
        (, SessionLib.SessionSpec memory spec,) =
            abi.decode(userOp.signature, (bytes, SessionLib.SessionSpec, uint48[]));
        bytes32 sessionActionsHash = getSessionActionsHash(spec);
        require(areSessionActionsAllowed[sessionActionsHash], SessionLib.ActionsNotAllowed(sessionActionsHash));
        return SessionKeyValidator.validateUserOp(userOp, userOpHash);
    }
}
