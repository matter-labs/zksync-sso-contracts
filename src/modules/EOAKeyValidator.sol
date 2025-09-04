// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IValidator, MODULE_TYPE_VALIDATOR } from "../interfaces/IERC7579Module.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS } from "account-abstraction/core/Helpers.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

contract EOAKeyValidator is IValidator {
    using EnumerableSet for EnumerableSet.AddressSet;

    // TODO: is this actually needed?
    mapping(address => bool) internal _initialized;
    mapping(address => EnumerableSet.AddressSet) owners;

    event OwnerAdded(address indexed smartAccount, address indexed owner);
    event OwnerRemoved(address indexed smartAccount, address indexed owner);

    error OwnerAlreadyExists(address smartAccount, address owner);
    error OwnerDoesNotExist(address smartAccount, address owner);

    function onInstall(bytes calldata data) external override {
        if (isInitialized(msg.sender)) revert AlreadyInitialized(msg.sender);
        _initialized[msg.sender] = true;
        address[] memory initialOwners = abi.decode(data, (address[]));
        for (uint256 i = 0; i < initialOwners.length; i++) {
            addOwner(initialOwners[i]);
        }
    }

    function onUninstall(bytes calldata) external override {
        if (!isInitialized(msg.sender)) revert NotInitialized(msg.sender);
        _initialized[msg.sender] = false;
        // TODO: clear owners?
    }

    function isInitialized(address smartAccount) public view override returns (bool) {
        return _initialized[smartAccount];
    }

    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external view returns (uint256) {
        (, bytes memory signature,) = abi.decode(userOp.signature, (address, bytes, bytes));

        // slither-disable-next-line unused-return
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(userOpHash, signature);
        return signer == address(0) || err != ECDSA.RecoverError.NoError || !owners[msg.sender].contains(signer)
            ? SIG_VALIDATION_FAILED
            : SIG_VALIDATION_SUCCESS;
    }

    function addOwner(address owner) public {
        require(isInitialized(msg.sender), NotInitialized(msg.sender));
        require(owners[msg.sender].add(owner), OwnerAlreadyExists(msg.sender, owner));
        emit OwnerAdded(msg.sender, owner);
    }

    function removeOwner(address owner) public {
        require(isInitialized(msg.sender), NotInitialized(msg.sender));
        require(owners[msg.sender].remove(owner), OwnerDoesNotExist(msg.sender, owner));
        emit OwnerRemoved(msg.sender, owner);
    }

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
        return err == ECDSA.RecoverError.NoError && owners[msg.sender].contains(signer)
            ? IERC1271.isValidSignature.selector
            : bytes4(0xffffffff);
    }

    function getOwners(address smartAccount) external view returns (address[] memory) {
        return owners[smartAccount].values();
    }
}
