// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import { IERC7484 } from "src/interfaces/IERC7484.sol";

contract MockRegistry is IERC7484 {
    using EnumerableSet for EnumerableSet.AddressSet;

    struct Attestation {
        uint256 moduleType;
        uint48 validUntil; // expiry timestamp
    }

    mapping(address => EnumerableSet.AddressSet) internal _attesters;
    mapping(address => uint8) public _threshold;
    mapping(address => mapping(address => Attestation)) internal _attestations;

    function check(address module) external view {
        _checkN(module, 0, false, _attesters[msg.sender].values(), _threshold[msg.sender]);
    }

    function checkForAccount(address smartAccount, address module) external view {
        _checkN(module, 0, false, _attesters[smartAccount].values(), _threshold[smartAccount]);
    }

    function check(address module, uint256 moduleType) external view {
        _checkN(module, moduleType, true, _attesters[msg.sender].values(), _threshold[msg.sender]);
    }

    function checkForAccount(address smartAccount, address module, uint256 moduleType) external view {
        _checkN(module, moduleType, true, _attesters[smartAccount].values(), _threshold[smartAccount]);
    }

    function check(address module, address attester) external view {
        require(_check(module, attester, false, 0), "Not attested");
    }

    function check(address module, uint256 moduleType, address attester) external view {
        require(_check(module, attester, true, moduleType), "Not attested");
    }

    function checkN(address module, address[] memory attesters, uint256 threshold) external view {
        _checkN(module, 0, false, attesters, threshold);
    }

    function checkN(address module, uint256 moduleType, address[] calldata attesters, uint256 threshold)
        external
        view
    {
        _checkN(module, moduleType, true, attesters, threshold);
    }

    function trustAttesters(uint8 threshold, address[] calldata attesters) external {
        _threshold[msg.sender] = threshold;
        for (uint256 i; i < attesters.length; i++) {
            require(_attesters[msg.sender].add(attesters[i]), "Attester already trusted");
        }
    }

    function attest(address module, uint256 moduleType, uint48 validFor) external {
        _attestations[msg.sender][module] =
            Attestation({ moduleType: moduleType, validUntil: uint48(block.timestamp) + validFor });
    }

    function revokeAttestation(address module) external {
        delete _attestations[msg.sender][module];
    }

    function _check(address module, address attester, bool checkModuleType, uint256 moduleType)
        internal
        view
        returns (bool)
    {
        Attestation memory attestation = _attestations[attester][module];
        // if not attested, timestamp will be 0 and the first check will fail
        return attestation.validUntil > block.timestamp && (!checkModuleType || attestation.moduleType == moduleType);
    }

    function _checkN(
        address module,
        uint256 moduleType,
        bool checkModuleType,
        address[] memory attesters,
        uint256 threshold
    ) internal view {
        require(threshold > 0, "Threshold must be > 0");
        uint256 attested = 0;
        for (uint256 i; i < attesters.length; i++) {
            attested += _check(module, attesters[i], checkModuleType, moduleType) ? 1 : 0;
        }
        require(attested >= threshold, "Threshold not met");
    }
}
