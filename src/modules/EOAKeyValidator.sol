// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IValidator, MODULE_TYPE_VALIDATOR } from "../interfaces/IERC7579Module.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS } from "account-abstraction/core/Helpers.sol";

import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { console } from "forge-std/console.sol";

contract EOAKeyValidator is IValidator {
    using EnumerableSet for EnumerableSet.AddressSet;

    // TODO: is this actually needed?
    mapping(address => bool) internal _initialized;
    mapping(address => EnumerableSet.AddressSet) owners;

    // TODO: addowner, removeowner

    function onInstall(bytes calldata data) external override {
        if (isInitialized(msg.sender)) revert AlreadyInitialized(msg.sender);
        _initialized[msg.sender] = true;
        address[] memory initialOwners = abi.decode(data, (address[]));
        for (uint256 i = 0; i < initialOwners.length; i++) {
            addOwner(initialOwners[i]);
        }
    }

    function onUninstall(
        bytes calldata // data
    )
        external
        override
    {
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
        console.log("EOAKeyValidator.validateUserOp");
        (, bytes memory signature,) = abi.decode(userOp.signature, (address, bytes, bytes));

        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(userOpHash, signature);
        return signer == address(0) || err != ECDSA.RecoverError.NoError || !owners[msg.sender].contains(signer)
            ? SIG_VALIDATION_FAILED
            : SIG_VALIDATION_SUCCESS;
    }

    function addOwner(address owner) public {
        if (!owners[msg.sender].add(owner)) {
            revert("Owner already exists");
        }
        // TODO emit event?
    }

    function removeOwner(address owner) public {
        if (!owners[msg.sender].remove(owner)) {
            revert("Owner does not exist");
        }
        // TODO emit event?
    }

    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        override
        returns (bytes4)
    {
        // TODO
    }
}
