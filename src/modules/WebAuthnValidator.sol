// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import { SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS } from "account-abstraction/core/Helpers.sol";
import { Base64 } from "solady/utils/Base64.sol";
import { JSONParserLib } from "solady/utils/JSONParserLib.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { P256 } from "solady/utils/P256.sol";

import { IMSA } from "../interfaces/IMSA.sol";
import { IValidator, IModule, MODULE_TYPE_VALIDATOR } from "../interfaces/IERC7579Module.sol";

/// @title WebAuthnValidator
/// @author Matter Labs
/// @custom:security-contact security@matterlabs.dev
/// @dev This contract allows secure user authentication using WebAuthn public keys.
contract WebAuthnValidator is IValidator, IERC165 {
    using JSONParserLib for JSONParserLib.Item;
    using JSONParserLib for string;

    error KeyAlreadyExists();
    error EmptyKey();
    error BadDomainLength();
    error BadCredentialIDLength();
    error KeyNotFound(string originDomain, bytes credentialId, address account);
    error InvalidClientData(string field);
    error InvalidAuthDataFlags(bytes1 flags);

    /// @notice Represents a passkey identifier, which includes the domain and credential ID
    struct PasskeyId {
        string domain;
        bytes credentialId;
    }

    /// @notice Emitted when a passkey is created
    /// @param keyOwner The address of the account that owns the passkey
    /// @param originDomain The domain for which the passkey was created, typically an Auth Server
    /// @param credentialId The unique identifier for the passkey
    event PasskeyCreated(address indexed keyOwner, string originDomain, bytes credentialId);
    /// @notice Emitted when a passkey is removed from the account
    /// @param keyOwner The address of the account that owned the passkey
    /// @param originDomain The domain for which the that passkey was used
    /// @param credentialId The unique identifier for the passkey that was removed
    event PasskeyRemoved(address indexed keyOwner, string originDomain, bytes credentialId);

    /// @dev Mapping of public keys to the account address that owns them
    mapping(string originDomain => mapping(bytes32 keyId => mapping(address account => bytes32[2] publicKey))) private
        publicKeys;

    /// @dev check for secure validation: bit 0 = 1 (user present), bit 2 = 1 (user verified)
    bytes1 private constant AUTH_DATA_MASK = 0x05;
    bytes32 private constant WEBAUTHN_GET_HASH = keccak256("webauthn.get");
    bytes32 private constant FALSE_HASH = keccak256("false");

    /// @notice This is helper function that returns the whole public key, as of solidity 0.8.24 the
    /// auto-generated getters only return half of the key
    /// @param originDomain the domain this key is associated with (the auth-server)
    /// @param credentialId the passkey unique identifier given by the authenticator
    /// @param accountAddress the address of the account that owns the key
    /// @return publicKeys the public key
    function getAccountKey(string calldata originDomain, bytes calldata credentialId, address accountAddress)
        external
        view
        returns (bytes32[2] memory)
    {
        return publicKeys[originDomain][keyId(credentialId, accountAddress)][accountAddress];
    }

    /// @dev Computes a unique key identifier based on the credential ID and account address
    /// @param credentialId The credential identifier associated with the key (usually provided by authenticator).
    /// @param account The address of the account owning the key.
    function keyId(bytes memory credentialId, address account) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(credentialId, account));
    }

    /// @inheritdoc IModule
    /// @param data ABI-encoded WebAuthn passkey to add immediately, or empty if not needed.
    function onInstall(bytes calldata data) external override {
        if (data.length > 0) {
            (bytes memory credentialId, bytes32[2] memory rawPublicKey, string memory originDomain) =
                abi.decode(data, (bytes, bytes32[2], string));
            _addValidationKey(credentialId, rawPublicKey, originDomain);
        }
    }

    /// @inheritdoc IModule
    /// @param data ABI-encoded array of origin domains to remove keys for.
    function onUninstall(bytes calldata data) external override {
        PasskeyId[] memory passkeyIds = abi.decode(data, (PasskeyId[]));
        for (uint256 i = 0; i < passkeyIds.length; ++i) {
            PasskeyId memory passkeyId = passkeyIds[i];
            removeValidationKey(passkeyId.credentialId, passkeyId.domain);
        }
    }

    /// @inheritdoc IModule
    function isInitialized(address account) public view override returns (bool) {
        return IMSA(account).isModuleInstalled(MODULE_TYPE_VALIDATOR, address(this), "");
    }

    /// @inheritdoc IModule
    function isModuleType(uint256 moduleType) external pure returns (bool) {
        return moduleType == MODULE_TYPE_VALIDATOR;
    }

    /// @notice Remove an existing WebAuthn passkey belonging to the caller.
    /// @param credentialId Credential identifier associated with the key.
    /// @param domain Domain for which the key was registered.
    function removeValidationKey(bytes memory credentialId, string memory domain) public {
        bytes32 id = keyId(credentialId, msg.sender);
        publicKeys[domain][id][msg.sender] = [bytes32(0), bytes32(0)];

        emit PasskeyRemoved(msg.sender, domain, credentialId);
    }

    /// @notice Register a new WebAuthn passkey for the caller's account.
    /// @param credentialId Credential identifier received from the authenticator.
    /// @param newKey The WebAuthn public key encoded as two 32-byte words.
    /// @param originDomain Domain that scoped the passkey.
    function addValidationKey(bytes memory credentialId, bytes32[2] memory newKey, string memory originDomain) public {
        require(isInitialized(msg.sender), NotInitialized(msg.sender));
        _addValidationKey(credentialId, newKey, originDomain);
    }

    /// @notice Adds a WebAuthn passkey for the caller, reverts otherwise
    /// @param credentialId unique public identifier for the key
    /// @param newKey New WebAuthn public key to add
    /// @param originDomain the domain this associated with
    function _addValidationKey(bytes memory credentialId, bytes32[2] memory newKey, string memory originDomain)
        internal
    {
        // This key ID is calculated to prevent frontrunning
        // by adding a key with the same credentialID.
        bytes32 id = keyId(credentialId, msg.sender);
        bytes32[2] memory oldKey = publicKeys[originDomain][id][msg.sender];
        // only allow adding new keys, no overwrites/updates
        require(oldKey[0] == 0 && oldKey[1] == 0, KeyAlreadyExists());
        // empty keys aren't valid
        require(newKey[0] != 0 || newKey[1] != 0, EmptyKey());
        // RFC 1035 sets domains between 1-253 characters
        uint256 domainLength = bytes(originDomain).length;
        require(domainLength >= 1 && domainLength <= 253, BadDomainLength());
        // min length from: https://www.w3.org/TR/webauthn-2/#credential-id
        require(credentialId.length >= 16, BadCredentialIDLength());

        publicKeys[originDomain][id][msg.sender] = newKey;

        emit PasskeyCreated(msg.sender, originDomain, credentialId);
    }

    /// @inheritdoc IValidator
    function isValidSignatureWithSender(
        address, // sender
        bytes32 signedHash,
        bytes calldata signature
    )
        external
        view
        returns (bytes4)
    {
        return webAuthVerify(signedHash, signature) ? IERC1271.isValidSignature.selector : bytes4(0xffffffff);
    }

    /// @inheritdoc IValidator
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 signedHash) external view returns (uint256) {
        return webAuthVerify(signedHash, userOp.signature[20:]) ? SIG_VALIDATION_SUCCESS : SIG_VALIDATION_FAILED;
    }

    /// @notice Validates a WebAuthn signature
    /// @dev Performs r & s range validation to prevent signature malleability
    /// @dev Checks passkey authenticator data flags (valid number of credentials)
    /// @dev Requires that the transaction signature hash was the signed challenge
    /// @dev Verifies that the signature was performed by a 'get' request
    /// @param signedHash The hash of the signed message
    /// @param fatSignature The signature to validate (authenticator data, client data, [r, s], credential ID)
    /// @return true if the signature is valid
    function webAuthVerify(bytes32 signedHash, bytes memory fatSignature) internal view returns (bool) {
        (
            bytes memory authenticatorData,
            string memory clientDataJSON,
            bytes32[2] memory rs,
            bytes memory credentialId
        ) = abi.decode(fatSignature, (bytes, string, bytes32[2], bytes));
        bytes32 id = keyId(credentialId, msg.sender);

        // https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data#attestedcredentialdata
        require(authenticatorData[32] & AUTH_DATA_MASK == AUTH_DATA_MASK, InvalidAuthDataFlags(authenticatorData[32]));

        // parse out the required fields (type, challenge, crossOrigin): https://goo.gl/yabPex
        JSONParserLib.Item memory root = JSONParserLib.parse(clientDataJSON);
        // challenge should contain the transaction hash, ensuring that the transaction is signed
        string memory challenge = root.at('"challenge"').value().decodeString();
        bytes memory challengeData = Base64.decode(challenge);
        bool challengeValid = (challengeData.length == 32 && bytes32(challengeData) == signedHash);

        // type ensures the signature was created from a validation request
        string memory webauthnType = root.at('"type"').value().decodeString();
        require(WEBAUTHN_GET_HASH == keccak256(bytes(webauthnType)), InvalidClientData("type"));

        // the origin determines which key to validate against
        // as passkeys are linked to domains, so the storage mapping reflects that
        string memory origin = root.at('"origin"').value().decodeString();
        bytes32[2] memory publicKey = publicKeys[origin][id][msg.sender];

        // cross-origin validation is optional, but explicitly not supported.
        // cross-origin requests would be from embedding the auth request
        // from another domain. The current SSO setup uses a pop-up instead of
        // an i-frame, so we're rejecting these until the implementation supports it
        JSONParserLib.Item memory crossOriginItem = root.at('"crossOrigin"');
        if (!crossOriginItem.isUndefined()) {
            string memory crossOrigin = crossOriginItem.value();
            require(FALSE_HASH == keccak256(bytes(crossOrigin)), InvalidClientData("crossOrigin"));
        }

        bytes32 clientDataHash = sha256(bytes(clientDataJSON));
        bytes32 message = sha256(bytes.concat(authenticatorData, clientDataHash));
        // Malleability checks are done in this call as well
        bool signatureValid = P256.verifySignature(message, rs[0], rs[1], publicKey[0], publicKey[1]);
        return signatureValid && challengeValid;
    }

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC165).interfaceId || interfaceId == type(IValidator).interfaceId
            || interfaceId == type(IModule).interfaceId;
    }
}
