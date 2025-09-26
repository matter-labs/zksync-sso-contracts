// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { ERC1271 } from "solady/accounts/ERC1271.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { ModuleManager } from "./ModuleManager.sol";
import { IValidator } from "../interfaces/IERC7579Module.sol";

/// @title ERC1271Handler
/// @author Matter Labs
/// @notice Contract which provides ERC1271 signature validation
/// @notice Uses ERC7739 for signature replay protection
abstract contract ERC1271Handler is ERC1271, ModuleManager {
    /// @notice Returns the domain name and version for the EIP-712 signature.
    /// @return name string - The name of the domain
    /// @return version string - The version of the domain
    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        return ("zksync-sso-1271", "1.0.0");
    }

    /// @notice Indicates whether or not the contract may cache the domain name and version.
    /// @return bool - Whether the domain name and version may change.
    function _domainNameAndVersionMayChange() internal pure override returns (bool) {
        return true;
    }

    // @notice Returns whether the signature provided is valid for the provided hash.
    // @dev Does not run validation hooks. Is used internally after ERC7739 unwrapping.
    // @param hash bytes32 - Hash of the data that is signed
    // @param signature bytes calldata - K1 owner signature OR validator address concatenated to signature
    // @return bool - Whether the signature is valid
    function _erc1271IsValidSignatureNowCalldata(bytes32 hash, bytes calldata data)
        internal
        view
        virtual
        override
        returns (bool)
    {
        address validator = address(bytes20(data[:20]));
        if (!_isValidatorInstalled(validator)) {
            revert InvalidModule(validator);
        }
        return IValidator(validator).isValidSignatureWithSender(msg.sender, hash, data[20:])
            == IERC1271.isValidSignature.selector;
    }

    /// @notice This function is not used anywhere in the contract, but is required to be implemented.
    function _erc1271Signer() internal pure override returns (address) {
        revert();
    }

    /// @dev Returns whether the `msg.sender` is considered safe, such
    /// that we don't need to use the nested EIP-712 workflow.
    /// @return bool - currently, always returns false
    function _erc1271CallerIsSafe() internal pure override returns (bool) {
        return false;
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }
}
