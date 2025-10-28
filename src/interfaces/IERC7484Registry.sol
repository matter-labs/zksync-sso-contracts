// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IERC7484Registry {
    /// @notice Verify that a module is attested by the sender's internal attesters.
    /// @param module Address of the module being queried.
    function check(address module) external view;

    /// @notice Verify that a module is attested for a specific smart account.
    /// @param smartAccount Account whose attesters are being queried.
    /// @param module Address of the module being checked.
    function checkForAccount(address smartAccount, address module) external view;

    /// @notice Verify that a module of a certain type is attested by the sender's internal attesters.
    /// @param module Address of the module being queried.
    /// @param moduleType Module type identifier defined by the registry.
    function check(address module, uint256 moduleType) external view;

    /// @notice Verify that a module of a certain type is attested for a smart account.
    /// @param smartAccount Account whose attesters are being queried.
    /// @param module Address of the module being checked.
    /// @param moduleType Module type identifier defined by the registry.
    function checkForAccount(address smartAccount, address module, uint256 moduleType) external view;

    /// @notice Verify that a module is attested by at least a threshold of external attesters.
    /// @param module Address of the module being queried.
    /// @param attesters List of external attesters to trust.
    /// @param threshold Minimum number of attesters required.
    function check(address module, address[] calldata attesters, uint256 threshold) external view;

    /// @notice Verify that a module of a certain type meets the attestation threshold from external attesters.
    /// @param module Address of the module being queried.
    /// @param moduleType Module type identifier defined by the registry.
    /// @param attesters List of external attesters to trust.
    /// @param threshold Minimum number of attesters required.
    function check(address module, uint256 moduleType, address[] calldata attesters, uint256 threshold) external view;

    /// @notice Authorize a new set of external attesters for the sender.
    /// @param threshold Minimum number of attesters required for a module to be considered trusted.
    /// @param attesters List of attester addresses for the sender to trust.
    function trustAttesters(uint8 threshold, address[] calldata attesters) external;
}
