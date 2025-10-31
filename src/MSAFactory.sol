// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { BeaconProxy } from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";

/// @title MSAFactory
/// @author Matter Labs
/// @custom:security-contact security@matterlabs.dev
/// @dev This contract is used to deploy SSO accounts as beacon proxies.
contract MSAFactory {
    /// @dev The address of the beacon contract used for the accounts' beacon proxies.
    address public immutable BEACON;

    /// @notice Emitted when a new account is successfully created.
    /// @param account The address of the newly created account.
    /// @param deployer The address of the account creator.
    event AccountCreated(address indexed account, address indexed deployer);

    constructor(address beacon) {
        BEACON = beacon;
    }

    /// @notice Deploy a new smart account using the configured beacon.
    /// @param salt A unique salt used to derive the account address.
    /// @param initData Initialization calldata forwarded to the beacon proxy;
    /// Usually, an abi-encoded call to IMSA.initializeAccount.
    /// @return account Address of the deployed account proxy.
    function deployAccount(bytes32 salt, bytes calldata initData) external returns (address account) {
        // This hash prevents DoS via front-running with this same salt.
        salt = keccak256(abi.encodePacked(msg.sender, salt));
        account = address(new BeaconProxy{ salt: salt }(BEACON, initData));
        emit AccountCreated(account, msg.sender);
    }
}
