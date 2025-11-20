// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { IERC7484Registry } from "../interfaces/IERC7484Registry.sol";
import { AccountBase } from "./AccountBase.sol";

/// @title RegistryAdapter
/// @author Matter Labs
/// @custom:security-contact security@matterlabs.dev
/// @notice The implementation is inspired by https://github.com/erc7579/erc7579-implementation
/// @dev This contract uses ERC-7484 to check if a module is attested to and exposes a modifier to use it.
abstract contract RegistryAdapter is AccountBase {
    event ERC7484RegistryConfigured(address indexed registry);

    IERC7484Registry internal $registry;

    /// @dev Reverts if the module is not attested for the given type in the registry.
    modifier withRegistry(address module, uint256 moduleTypeId) {
        checkWithRegistry(module, moduleTypeId);
        _;
    }

    /// @notice Check the registry to see if the module is attested for the given type.
    /// @notice If no registry is set, this function does nothing.
    /// @param module Module address to check.
    /// @param moduleTypeId Type ID of the module to check.
    /// @dev Reverts if the module is not attested.
    function checkWithRegistry(address module, uint256 moduleTypeId) internal view {
        IERC7484Registry registry = $registry;
        if (address(registry) != address(0)) {
            registry.check(module, moduleTypeId);
        }
    }

    /// @notice Configure the ERC-7484 registry used to attest modules for the account.
    /// @param registry Registry contract to use.
    /// @param attesters List of attesters to trust immediately.
    /// @param threshold Minimum number of trusted attesters required by the registry.
    function setRegistry(IERC7484Registry registry, address[] calldata attesters, uint8 threshold)
        external
        onlyEntryPointOrSelf
    {
        $registry = registry;
        if (attesters.length > 0) {
            registry.trustAttesters(threshold, attesters);
        }
        emit ERC7484RegistryConfigured(address(registry));
    }

    function getRegistry() external view returns (IERC7484Registry) {
        return $registry;
    }
}
