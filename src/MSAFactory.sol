// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { BeaconProxy } from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title MSAFactory
/// @author Matter Labs
/// @custom:security-contact security@matterlabs.dev
/// @dev This contract is used to deploy SSO accounts as beacon proxies.
contract MSAFactory is ReentrancyGuard {
    /// @dev The address of the beacon contract used for the accounts' beacon proxies.
    address public immutable beacon;

    /// @notice A mapping from unique account IDs to their corresponding deployed account addresses.
    mapping(bytes32 accountId => address deployedAccount) public accountRegistry;

    /// @notice Emitted when a new account is successfully created.
    /// @param accountAddress The address of the newly created account.
    /// @param accountId A unique identifier for the account.
    event AccountCreated(address indexed accountAddress, bytes32 accountId);

    error AccountAlreadyExists(bytes32 accountId);

    constructor(address _beacon) {
        beacon = _beacon;
    }

    /// @notice Deploy a new smart account using the configured beacon.
    /// @param accountId Unique identifier used as salt for deterministic deployment.
    /// @param initData Initialization calldata forwarded to the beacon proxy;
    /// Usually, an abi-encoded call to IMSA.initializeAccount.
    /// @return account Address of the deployed account proxy.
    function deployAccount(bytes32 accountId, bytes calldata initData) external nonReentrant returns (address account) {
        require(accountRegistry[accountId] == address(0), AccountAlreadyExists(accountId));

        // slither-disable-next-line reentrancy-no-eth
        account = address(new BeaconProxy{ salt: accountId }(beacon, initData));
        accountRegistry[accountId] = account;

        emit AccountCreated(account, accountId);
    }
}
