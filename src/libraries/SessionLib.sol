// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { UserOperationLib } from "account-abstraction/core/UserOperationLib.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { LibBytes } from "solady/utils/LibBytes.sol";
import { LibERC7579 } from "solady/accounts/LibERC7579.sol";

import { IERC7579Account } from "../interfaces/IERC7579Account.sol";

/// @title Session Library
/// @author Matter Labs
/// @notice Library for session management, used by SessionKeyValidator
/// @custom:security-contact security@matterlabs.dev
library SessionLib {
    using SessionLib for SessionLib.Constraint;
    using SessionLib for SessionLib.UsageLimit;
    using LibBytes for bytes;
    using UserOperationLib for PackedUserOperation;

    error ZeroSigner();
    error InvalidSigner(address recovered, address expected);
    error InvalidCallType(bytes1 callType, bytes1 expected);
    error InvalidTopLevelSelector(bytes4 selector, bytes4 expected);
    error SessionAlreadyExists(bytes32 sessionHash);
    error UnlimitedFees();
    error SessionExpiresTooSoon(uint256 expiresAt);
    error SessionNotActive();
    error LifetimeUsageExceeded(uint256 lifetimeUsage, uint256 maxUsage);
    error AllowanceExceeded(uint256 allowance, uint256 maxAllowance, uint64 period);
    error InvalidDataLength(uint256 actualLength, uint256 expectedMinimumLength);
    error ConditionViolated(bytes32 param, bytes32 refValue, uint8 condition);
    error CallPolicyViolated(address target, bytes4 selector);
    error TransferPolicyViolated(address target);
    error MaxValueExceeded(uint256 usedValue, uint256 maxValuePerUse);
    error SignerAlreadyUsed(address signer);
    error CallPolicyBanned(address target, bytes4 selector);
    error SessionActionsNotAllowed(bytes32 sessionActionsHash);
    error InvalidNonceKey(uint192 nonceKey, uint192 expectedNonceKey);
    error ActionsNotAllowed(bytes32 actionsHash);

    /// @notice We do not permit opening multiple identical sessions (even after one is closed,
    /// e.g.).
    /// For each session key, its session status can only be changed
    /// from NotInitialized to Active, and from Active to Closed.
    enum Status {
        NotInitialized,
        Active,
        Closed
    }

    /// @notice This struct is used to track usage information for each session.
    /// Along with `status`, this is considered the session state.
    /// While everything else is considered the session spec, and is stored offchain.
    /// @dev Storage layout of this struct is unusual to conform to ERC-7562 storage access
    /// restrictions during validation.
    /// Each innermost mapping is always mapping(address account => ...).
    struct SessionStorage {
        mapping(address => Status) status;
        UsageTracker fee;
        // (target) => transfer value tracker
        mapping(address => UsageTracker) transferValue;
        // (target, selector) => call value tracker
        mapping(address => mapping(bytes4 => UsageTracker)) callValue;
        // (target, selector, index) => call parameter tracker
        // index is the constraint index in callPolicy, not the parameter index
        mapping(address => mapping(bytes4 => mapping(uint256 => UsageTracker))) params;
    }

    struct Constraint {
        Condition condition;
        uint64 index;
        bytes32 refValue;
        UsageLimit limit;
    }

    struct UsageTracker {
        // Used for LimitType.Lifetime
        mapping(address => uint256) lifetimeUsage;
        // Used for LimitType.Allowance
        // period => used that period
        mapping(uint64 => mapping(address => uint256)) allowanceUsage;
    }

    struct UsageLimit {
        LimitType limitType;
        uint256 limit; // ignored if limitType == Unlimited
        uint48 period; // ignored if limitType != Allowance
    }

    enum LimitType {
        Unlimited,
        Lifetime,
        Allowance
    }

    enum Condition {
        Unconstrained,
        Equal,
        Greater,
        Less,
        GreaterOrEqual,
        LessOrEqual,
        NotEqual
    }

    /// @notice This struct is provided by the account to create a session.
    /// It is used to define the session's policies, limits and constraints.
    /// Only its hash is stored onchain, and the full struct is provided with
    /// each transaction in calldata via `validatorData`, encoded in the signature.
    struct SessionSpec {
        address signer;
        uint48 expiresAt;
        UsageLimit feeLimit;
        CallSpec[] callPolicies;
        TransferSpec[] transferPolicies;
    }

    struct CallSpec {
        address target;
        bytes4 selector;
        uint256 maxValuePerUse;
        UsageLimit valueLimit;
        Constraint[] constraints;
    }
    // add max data length restriction?
    // add max number of calls restriction?

    struct TransferSpec {
        address target;
        uint256 maxValuePerUse;
        UsageLimit valueLimit;
    }

    struct LimitState {
        // this might also be limited by a constraint or `maxValuePerUse`,
        // which is not reflected here
        uint256 remaining;
        address target;
        // ignored for transfer value
        bytes4 selector;
        // ignored for transfer and call value
        uint256 index;
    }

    // Info about remaining session limits and its status
    struct SessionState {
        Status status;
        uint256 feesRemaining;
        LimitState[] transferValue;
        LimitState[] callValue;
        LimitState[] callParams;
    }

    /// @notice Checks if the limit is exceeded and updates the usage tracker.
    /// @param limit The limit to check.
    /// @param tracker The usage tracker to update.
    /// @param value The tracked value to check the limit against.
    /// @param period The period ID to check the limit against. Ignored if the limit is not of type
    /// Allowance.
    /// @dev Reverts if the limit is exceeded or the period is invalid.
    function checkAndUpdate(UsageLimit memory limit, UsageTracker storage tracker, uint256 value, uint48 period)
        internal
        returns (uint48 validAfter, uint48 validUntil)
    {
        if (limit.limitType == LimitType.Lifetime) {
            validAfter = 0;
            validUntil = type(uint48).max;
            require(
                tracker.lifetimeUsage[msg.sender] + value <= limit.limit,
                LifetimeUsageExceeded(tracker.lifetimeUsage[msg.sender], limit.limit)
            );
            tracker.lifetimeUsage[msg.sender] += value;
        } else if (limit.limitType == LimitType.Allowance) {
            validAfter = period * limit.period;
            validUntil = (period + 1) * limit.period;
            require(
                tracker.allowanceUsage[period][msg.sender] + value <= limit.limit,
                AllowanceExceeded(tracker.allowanceUsage[period][msg.sender], limit.limit, period)
            );
            tracker.allowanceUsage[period][msg.sender] += value;
        }
    }

    /// @notice Checks if the constraint is met and update the usage tracker.
    /// @param constraint The constraint to check.
    /// @param tracker The usage tracker to update.
    /// @param data The transaction data to check the constraint against.
    /// @param period The period ID to check the allowances against.
    /// @dev Reverts if the constraint is not met.
    /// @dev Forwards the call to `checkAndUpdate(limit, ...)` on the limit of the constraint.
    function checkAndUpdate(
        Constraint memory constraint,
        UsageTracker storage tracker,
        bytes memory data,
        uint48 period
    ) internal returns (uint48, uint48) {
        uint256 expectedLength = 4 + constraint.index * 32 + 32;
        if (data.length < expectedLength) {
            revert InvalidDataLength(data.length, expectedLength);
        }
        bytes32 param = data.load(4 + constraint.index * 32);
        Condition condition = constraint.condition;
        bytes32 refValue = constraint.refValue;

        if (
            (condition == Condition.Equal && param != refValue) || (condition == Condition.Greater && param <= refValue)
                || (condition == Condition.Less && param >= refValue)
                || (condition == Condition.GreaterOrEqual && param < refValue)
                || (condition == Condition.LessOrEqual && param > refValue)
                || (condition == Condition.NotEqual && param == refValue)
        ) {
            revert ConditionViolated(param, refValue, uint8(condition));
        }

        // slither-disable-next-line unused-return
        return constraint.limit.checkAndUpdate(tracker, uint256(param), period);
    }

    /// @notice Validates the fee limit of the session and updates the tracker.
    /// Only performs the checks if the transaction is not using a paymaster.
    /// @param state The session storage to update.
    /// @param userOp The user operation to check the fee of.
    /// @param spec The session spec to check the fee limit against.
    /// @param periodId The period ID to check the fee limit against. Ignored if the limit is not of
    /// type Allowance.
    /// @dev Reverts if the fee limit is exceeded.
    /// @dev This is split from `validate` to prevent gas estimation failures.
    /// When this check was part of `validate`, gas estimation could fail due to
    /// fee limit being smaller than the upper bound of the gas estimation binary search.
    /// By splitting this check, we can now have this order of operations in `validateTransaction`:
    /// 1. session.validate()
    /// 2. ECDSA.tryRecover()
    /// 3. session.validateFeeLimit()
    /// This way, gas estimation will exit on step 2 instead of failing, but will still run through
    /// most of the computation needed to validate the session.
    function validateFeeLimit(
        SessionStorage storage state,
        PackedUserOperation calldata userOp,
        SessionSpec memory spec,
        uint48 periodId
    ) internal returns (uint48 validAfter, uint48 validUntil) {
        // If a paymaster is paying the fee, we don't need to check the fee limit
        if (userOp.paymasterAndData.length == 0) {
            uint256 gasPrice = userOp.gasPrice();
            uint256 gasLimit = userOp.unpackVerificationGasLimit() + userOp.unpackCallGasLimit();
            uint256 fee = gasPrice * gasLimit;
            // slither-disable-next-line unused-return
            return spec.feeLimit.checkAndUpdate(state.fee, fee, periodId);
        } else {
            return (0, type(uint48).max);
        }
    }

    function shrinkRange(uint48[2] memory range, uint48 newAfter, uint48 newUntil) internal pure {
        range[0] = newAfter > range[0] ? newAfter : range[0];
        range[1] = newUntil < range[1] ? newUntil : range[1];
    }

    /// @notice Validates the transaction against the session spec and updates the usage trackers.
    /// @param state The session storage to update.
    /// @param userOp The user operation to validate.
    /// @param spec The session spec to validate against.
    /// @param periodIds The period IDs to check the allowances against.
    /// @dev periodId is defined as block.timestamp / limit.period if limitType == Allowance, and 0
    /// otherwise (which will be ignored).
    /// periodIds[0] is for fee limit (not used in this function),
    /// periodIds[1] is for value limit,
    /// periodIds[2:] are for call constraints, if there are any.
    /// It is required to pass them in (instead of computing via block.timestamp) since during
    /// validation
    /// we can only assert the range of the timestamp, but not access its value.
    function validate(
        SessionStorage storage state,
        PackedUserOperation calldata userOp,
        SessionSpec memory spec,
        uint48[] memory periodIds
    ) internal returns (uint48, uint48) {
        require(state.status[msg.sender] == Status.Active, SessionNotActive());

        bytes4 topLevelSelector = bytes4(userOp.callData[:4]);
        bytes1 callType = userOp.callData[4];

        require(callType == LibERC7579.CALLTYPE_SINGLE, InvalidCallType(callType, LibERC7579.CALLTYPE_SINGLE));
        require(
            topLevelSelector == IERC7579Account.execute.selector,
            InvalidTopLevelSelector(topLevelSelector, IERC7579Account.execute.selector)
        );

        // Function called: execute(bytes32 mode, bytes calldata data)
        // - first 4 bytes: selector
        // - next 32 bytes: mode
        // - next 32 bytes: data offset
        // - at offset: data length
        // - next 32 bytes: data
        uint256 offset = uint256(bytes32(userOp.callData[36:68])) + 4; // offset does not include the selector
        uint256 length = uint256(bytes32(userOp.callData[offset:offset + 32]));
        (address target, uint256 value, bytes calldata callData) =
            LibERC7579.decodeSingle(userOp.callData[offset + 32:offset + 32 + length]);

        // Time range within which the transaction is valid.
        uint48[2] memory timeRange = [0, spec.expiresAt];

        if (callData.length >= 4) {
            bytes4 selector = bytes4(callData[:4]);
            CallSpec memory callPolicy;
            bool found = false;

            for (uint256 i = 0; i < spec.callPolicies.length; i++) {
                if (spec.callPolicies[i].target == target && spec.callPolicies[i].selector == selector) {
                    callPolicy = spec.callPolicies[i];
                    found = true;
                    break;
                }
            }

            require(found, CallPolicyViolated(target, selector));
            require(value <= callPolicy.maxValuePerUse, MaxValueExceeded(value, callPolicy.maxValuePerUse));
            (uint48 newValidAfter, uint48 newValidUntil) =
                callPolicy.valueLimit.checkAndUpdate(state.callValue[target][selector], value, periodIds[1]);
            shrinkRange(timeRange, newValidAfter, newValidUntil);

            for (uint256 i = 0; i < callPolicy.constraints.length; i++) {
                (newValidAfter, newValidUntil) = callPolicy.constraints[i].checkAndUpdate(
                    state.params[target][selector][i], callData, periodIds[2 + i]
                );
                shrinkRange(timeRange, newValidAfter, newValidUntil);
            }
        } else {
            TransferSpec memory transferPolicy;
            bool found = false;

            for (uint256 i = 0; i < spec.transferPolicies.length; i++) {
                if (spec.transferPolicies[i].target == target) {
                    transferPolicy = spec.transferPolicies[i];
                    found = true;
                    break;
                }
            }

            require(found, TransferPolicyViolated(target));
            require(value <= transferPolicy.maxValuePerUse, MaxValueExceeded(value, transferPolicy.maxValuePerUse));
            (uint48 newValidAfter, uint48 newValidUntil) =
                transferPolicy.valueLimit.checkAndUpdate(state.transferValue[target], value, periodIds[1]);
            shrinkRange(timeRange, newValidAfter, newValidUntil);
        }

        return (timeRange[0], timeRange[1]);
    }

    /// @notice Getter for the remainder of a usage limit.
    /// @param limit The limit to check.
    /// @param tracker The corresponding usage tracker to get the usage from.
    /// @param account The account to get the usage for.
    /// @return The remaining limit. If unlimited, returns `type(uint256).max`.
    function remainingLimit(UsageLimit memory limit, UsageTracker storage tracker, address account)
        private
        view
        returns (uint256)
    {
        if (limit.limitType == LimitType.Unlimited) {
            // this might be still limited by `maxValuePerUse` or a constraint
            return type(uint256).max;
        }
        if (limit.limitType == LimitType.Lifetime) {
            return limit.limit - tracker.lifetimeUsage[account];
        }
        if (limit.limitType == LimitType.Allowance) {
            // this is not used during validation, so it's fine to use block.timestamp
            uint64 period = uint64(block.timestamp / limit.period);
            return limit.limit - tracker.allowanceUsage[period][account];
        }
        // Unreachable, but silences warning
        return 0;
    }

    /// @notice Getter for the session state.
    /// @param session The session storage to get the state from.
    /// @param account The account to get the state for.
    /// @param spec The session spec to get the state for.
    /// @return The session state: status, remaining fee limit, transfer limits, call value and call
    /// parameter limits.
    function getState(SessionStorage storage session, address account, SessionSpec calldata spec)
        internal
        view
        returns (SessionState memory)
    {
        uint256 totalConstraints = 0;
        for (uint256 i = 0; i < spec.callPolicies.length; i++) {
            totalConstraints += spec.callPolicies[i].constraints.length;
        }

        LimitState[] memory transferValue = new LimitState[](spec.transferPolicies.length);
        LimitState[] memory callValue = new LimitState[](spec.callPolicies.length);
        LimitState[] memory callParams = new LimitState[](totalConstraints); // there will be empty
            // ones at the end
        uint256 paramLimitIndex = 0;

        for (uint256 i = 0; i < transferValue.length; i++) {
            TransferSpec memory transferSpec = spec.transferPolicies[i];
            transferValue[i] = LimitState({
                remaining: remainingLimit(transferSpec.valueLimit, session.transferValue[transferSpec.target], account),
                target: transferSpec.target,
                selector: bytes4(0),
                index: 0
            });
        }

        for (uint256 i = 0; i < callValue.length; i++) {
            CallSpec memory callSpec = spec.callPolicies[i];
            callValue[i] = LimitState({
                remaining: remainingLimit(
                    callSpec.valueLimit, session.callValue[callSpec.target][callSpec.selector], account
                ),
                target: callSpec.target,
                selector: callSpec.selector,
                index: 0
            });

            for (uint256 j = 0; j < callSpec.constraints.length; j++) {
                if (callSpec.constraints[j].limit.limitType != LimitType.Unlimited) {
                    callParams[paramLimitIndex++] = LimitState({
                        remaining: remainingLimit(
                            callSpec.constraints[j].limit, session.params[callSpec.target][callSpec.selector][j], account
                        ),
                        target: callSpec.target,
                        selector: callSpec.selector,
                        index: callSpec.constraints[j].index
                    });
                }
            }
        }

        // shrink array to actual size
        assembly {
            mstore(callParams, paramLimitIndex)
        }

        return SessionState({
            status: session.status[account],
            feesRemaining: remainingLimit(spec.feeLimit, session.fee, account),
            transferValue: transferValue,
            callValue: callValue,
            callParams: callParams
        });
    }
}
