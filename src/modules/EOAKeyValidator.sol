// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS } from "account-abstraction/core/Helpers.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { EnumerableSet } from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import { IMSA } from "../interfaces/IMSA.sol";
import { IValidator, MODULE_TYPE_VALIDATOR } from "../interfaces/IERC7579Module.sol";

contract EOAKeyValidator is IValidator {
    using EnumerableSet for EnumerableSet.AddressSet;

    // mapping(address => bool) internal _initialized;
    mapping(address eoa => mapping(address account => bool)) private owners;

    event OwnerAdded(address indexed smartAccount, address indexed owner);
    event OwnerRemoved(address indexed smartAccount, address indexed owner);

    error OwnerAlreadyExists(address smartAccount, address owner);
    error OwnerDoesNotExist(address smartAccount, address owner);

    function onInstall(bytes calldata data) external {
        address[] memory initialOwners = abi.decode(data, (address[]));
        for (uint256 i = 0; i < initialOwners.length; i++) {
            _addOwner(initialOwners[i]);
        }
    }

    function onUninstall(bytes calldata data) external {
        address[] memory ownersToRemove = abi.decode(data, (address[]));
        for (uint256 i = 0; i < ownersToRemove.length; i++) {
            removeOwner(ownersToRemove[i]);
        }
    }

    function isInitialized(address smartAccount) public view returns (bool) {
        return IMSA(smartAccount).isModuleInstalled(MODULE_TYPE_VALIDATOR, address(this), "");
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external view returns (uint256) {
        bytes calldata signature = userOp.signature[20:];

        // slither-disable-next-line unused-return
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(userOpHash, signature);
        return signer == address(0) || err != ECDSA.RecoverError.NoError || !owners[signer][msg.sender]
            ? SIG_VALIDATION_FAILED
            : SIG_VALIDATION_SUCCESS;
    }

    function addOwner(address owner) public {
        require(isInitialized(msg.sender), NotInitialized(msg.sender));
        _addOwner(owner);
    }

    function _addOwner(address owner) public {
        require(!owners[owner][msg.sender], OwnerAlreadyExists(msg.sender, owner));
        owners[owner][msg.sender] = true;
        emit OwnerAdded(msg.sender, owner);
    }

    function removeOwner(address owner) public {
        require(isInitialized(msg.sender), NotInitialized(msg.sender));
        require(owners[owner][msg.sender], OwnerDoesNotExist(msg.sender, owner));
        owners[owner][msg.sender] = false;
        emit OwnerRemoved(msg.sender, owner);
    }

    function isValidSignatureWithSender(
        address, // sender
        bytes32 hash,
        bytes calldata data
    ) external view override returns (bytes4) {
        // slither-disable-next-line unused-return
        (address signer, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, data);
        return err == ECDSA.RecoverError.NoError && owners[signer][msg.sender]
            ? IERC1271.isValidSignature.selector
            : bytes4(0xffffffff);
    }

    function isOwnerOf(address account, address owner) external view returns (bool) {
        return owners[owner][account];
    }
}
