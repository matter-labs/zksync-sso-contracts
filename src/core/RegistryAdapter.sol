// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { IERC7484Registry } from "../interfaces/IERC7484Registry.sol";
import { AccountBase } from "./AccountBase.sol";

/// @title RegistryAdapter
/// @author kopy-kat | rhinestone.wtf
/// @dev This contract uses ERC-7484 to check if a module is attested to and exposes a modifier to use it.
abstract contract RegistryAdapter is AccountBase {
    event ERC7484RegistryConfigured(address indexed registry);

    IERC7484Registry internal $registry;

    modifier withRegistry(address module, uint256 moduleTypeId) {
        IERC7484Registry registry = $registry;
        if (address(registry) != address(0)) {
            registry.check(module, moduleTypeId);
        }
        _;
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
}
