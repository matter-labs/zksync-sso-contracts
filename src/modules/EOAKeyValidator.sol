// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS } from "account-abstraction/core/Helpers.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";

import { IMSA } from "../interfaces/IMSA.sol";
import { IValidator, IModule, MODULE_TYPE_VALIDATOR } from "../interfaces/IERC7579Module.sol";

contract EOAKeyValidator is IValidator {
    mapping(address owner => mapping(address account => bool)) private owners;

    event OwnerAdded(address indexed smartAccount, address indexed owner);
    event OwnerRemoved(address indexed smartAccount, address indexed owner);

    error OwnerAlreadyExists(address smartAccount, address owner);
    error OwnerDoesNotExist(address smartAccount, address owner);
    error ZeroAddress(address smartAccount);

    /// @inheritdoc IModule
    /// @notice Adds the provided owners for the installing account.
    function onInstall(bytes calldata data) external {
        address[] memory initialOwners = abi.decode(data, (address[]));
        for (uint256 i = 0; i < initialOwners.length; ++i) {
            _addOwner(initialOwners[i]);
        }
    }

    /// @inheritdoc IModule
    /// @notice Removes the provided owners when the validator is uninstalled.
    function onUninstall(bytes calldata data) external {
        address[] memory ownersToRemove = abi.decode(data, (address[]));
        for (uint256 i = 0; i < ownersToRemove.length; ++i) {
            removeOwner(ownersToRemove[i]);
        }
    }

    /// @inheritdoc IModule
    function isInitialized(address smartAccount) public view returns (bool) {
        return IMSA(smartAccount).isModuleInstalled(MODULE_TYPE_VALIDATOR, address(this), "");
    }

    /// @inheritdoc IModule
    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    /// @inheritdoc IValidator
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external view returns (uint256) {
        bytes calldata signature = userOp.signature[20:];

        // slither-disable-next-line unused-return
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(userOpHash, signature);
        return signer == address(0) || err != ECDSA.RecoverError.NoError || !owners[signer][msg.sender]
            ? SIG_VALIDATION_FAILED
            : SIG_VALIDATION_SUCCESS;
    }

    /// @notice Grant ownership access to an EOA for the caller's account.
    /// @param owner Address to add as a valid owner.
    function addOwner(address owner) public {
        require(isInitialized(msg.sender), NotInitialized(msg.sender));
        require(owner != address(0), ZeroAddress(msg.sender));
        _addOwner(owner);
    }

    /// @notice Helper that records a new owner for the caller.
    /// @param owner Address to add as a valid owner.
    function _addOwner(address owner) public {
        require(!owners[owner][msg.sender], OwnerAlreadyExists(msg.sender, owner));
        owners[owner][msg.sender] = true;
        emit OwnerAdded(msg.sender, owner);
    }

    /// @notice Remove an existing owner from the caller's account.
    /// @param owner Address of the owner to revoke.
    function removeOwner(address owner) public {
        require(owners[owner][msg.sender], OwnerDoesNotExist(msg.sender, owner));
        owners[owner][msg.sender] = false;
        emit OwnerRemoved(msg.sender, owner);
    }

    /// @inheritdoc IValidator
    function isValidSignatureWithSender(
        address, // sender
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        override
        returns (bytes4)
    {
        // slither-disable-next-line unused-return
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, data);
        return err == ECDSA.RecoverError.NoError && owners[signer][msg.sender]
            ? IERC1271.isValidSignature.selector
            : bytes4(0xffffffff);
    }

    /// @notice Check if an address is a registered owner of a smart account.
    /// @param account Account to check ownership for.
    /// @param owner Potential owner address.
    /// @return True if the owner is registered for the account.
    function isOwnerOf(address account, address owner) external view returns (bool) {
        return owners[owner][account];
    }
}
