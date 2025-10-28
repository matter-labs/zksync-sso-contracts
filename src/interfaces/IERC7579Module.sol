// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";

uint256 constant VALIDATION_SUCCESS = 0;
uint256 constant VALIDATION_FAILED = 1;

uint256 constant MODULE_TYPE_VALIDATOR = 1;
uint256 constant MODULE_TYPE_EXECUTOR = 2;
uint256 constant MODULE_TYPE_FALLBACK = 3;
uint256 constant MODULE_TYPE_HOOK = 4;
uint256 constant MODULE_TYPE_PREVALIDATION_HOOK_ERC1271 = 8;
uint256 constant MODULE_TYPE_PREVALIDATION_HOOK_ERC4337 = 9;

interface IModule {
    error AlreadyInitialized(address smartAccount);
    error NotInitialized(address smartAccount);

    /// @dev This function is called by the smart account during installation of the module
    /// @param data arbitrary data that may be required on the module during `onInstall`
    /// initialization
    ///
    /// MUST revert on error
    function onInstall(bytes calldata data) external;

    /// @dev This function is called by the smart account during uninstallation of the module
    /// @param data arbitrary data that may be required on the module during `onUninstall`
    /// de-initialization
    ///
    /// MUST revert on error
    function onUninstall(bytes calldata data) external;

    /// @dev Returns boolean value if module is a certain type
    /// @param moduleTypeId the module type ID according the ERC-7579 spec
    ///
    /// MUST return true if the module is of the given type and false otherwise
    function isModuleType(uint256 moduleTypeId) external view returns (bool);

    /// @dev Returns if the module was already initialized for a provided smartaccount
    function isInitialized(address smartAccount) external view returns (bool);
}

interface IValidator is IModule {
    error InvalidTargetAddress(address target);

    /// @dev Validates a transaction on behalf of the account.
    ///         This function is intended to be called by the MSA during the ERC-4337 validation phase
    ///         Note: solely relying on bytes32 hash and signature is not sufficient for some
    /// validation implementations (i.e. SessionKeys often need access to userOp.calldata)
    /// @param userOp The user operation to be validated. The userOp MUST NOT contain any metadata.
    /// The MSA MUST clean up the userOp before sending it to the validator.
    /// @param userOpHash The hash of the user operation to be validated
    /// @return return value according to ERC-4337
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external returns (uint256);

    /// @notice Validate an ERC-1271 signature with context about the original sender.
    /// @param sender Address that triggered the validation on the account.
    /// @param hash Hash of the signed message being validated.
    /// @param data Additional signature payload supplied by the caller.
    /// @return Selector indicating whether the signature is valid.
    function isValidSignatureWithSender(address sender, bytes32 hash, bytes calldata data)
        external
        view
        returns (bytes4);
}

interface IExecutor is IModule { }

interface IHook is IModule {
    /// @notice Perform logic before the account executes a call.
    /// @param msgSender Original caller forwarded by the account.
    /// @param msgValue ETH value forwarded with the call.
    /// @param msgData Calldata forwarded with the call.
    /// @return hookData Encoded context to feed back into `postCheck`.
    function preCheck(address msgSender, uint256 msgValue, bytes calldata msgData)
        external
        returns (bytes memory hookData);

    /// @notice Finalise hook logic after the account executes a call.
    /// @param hookData Data produced by `preCheck`.
    function postCheck(bytes calldata hookData) external;
}

interface IFallback is IModule { }

interface IPreValidationHookERC1271 is IModule {
    /// @notice Provide supplemental data during ERC-1271 pre-validation.
    /// @param sender Address that initiated the signature validation.
    /// @param hash Hash of the signed payload.
    /// @param data Additional signature data provided by the caller.
    /// @return hookHash Supplemental hash to include in validation.
    /// @return hookSignature Supplemental signature bytes to include in validation.
    function preValidationHookERC1271(address sender, bytes32 hash, bytes calldata data)
        external
        view
        returns (bytes32 hookHash, bytes memory hookSignature);
}

interface IPreValidationHookERC4337 is IModule {
    /// @notice Provide supplemental data during ERC-4337 pre-validation.
    /// @param userOp The user operation being validated.
    /// @param missingAccountFunds Amount of prefund still required.
    /// @param userOpHash Canonical hash of the user operation.
    /// @return hookHash Supplemental hash to include in validation.
    /// @return hookSignature Supplemental signature bytes to include in validation.
    function preValidationHookERC4337(
        PackedUserOperation calldata userOp,
        uint256 missingAccountFunds,
        bytes32 userOpHash
    ) external returns (bytes32 hookHash, bytes memory hookSignature);
}
