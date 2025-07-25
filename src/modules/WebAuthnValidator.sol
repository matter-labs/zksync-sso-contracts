// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import { Strings } from "@openzeppelin/contracts/utils/Strings.sol";
import { Base64 } from "solady/utils/Base64.sol";
import { JSONParserLib } from "solady/utils/JSONParserLib.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";

import { IMSA } from "../interfaces/IMSA.sol";
import { IValidator, IModule, MODULE_TYPE_VALIDATOR } from "../interfaces/IERC7579Module.sol";

/// @title WebAuthnValidator
/// @author Matter Labs
/// @custom:security-contact security@matterlabs.dev
/// @dev This contract allows secure user authentication using WebAuthn public keys.
contract WebAuthnValidator is IValidator {
  using JSONParserLib for JSONParserLib.Item;
  using JSONParserLib for string;

  error NotKeyOwner(address account);
  error KeyAlreadyExists();
  error AccountAlreadyExists();
  error EmtpyKey();
  error BadDomainLength();
  error BadCredentialIDLength();

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
  mapping(string originDomain => mapping(bytes credentialId => mapping(address accountAddress => bytes32[2] publicKey)))
    private publicKeys;

  /// @dev Mapping of domain-bound credential IDs to the account address that owns them
  mapping(string originDomain => mapping(bytes credentialId => address accountAddress)) public registeredAddress;

  /// @dev P256Verify precompile implementation, as defined in RIP-7212, is found at
  /// https://github.com/matter-labs/era-contracts/blob/main/system-contracts/contracts/precompiles/P256Verify.yul
  // TODO: is this the same in EVM?
  address private constant P256_VERIFIER = address(0x100);

  /// @dev check for secure validation: bit 0 = 1 (user present), bit 2 = 1 (user verified)
  bytes1 private constant AUTH_DATA_MASK = 0x05;
  bytes32 private constant LOW_S_MAX = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;
  bytes32 private constant HIGH_R_MAX = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
  bytes32 private constant WEBAUTHN_GET_HASH = keccak256("webauthn.get");
  bytes32 private constant FALSE_HASH = keccak256("false");

  /// @notice This is helper function that returns the whole public key, as of solidity 0.8.24 the auto-generated getters only return half of the key
  /// @param originDomain the domain this key is associated with (the auth-server)
  /// @param credentialId the passkey unique identifier
  /// @param accountAddress the address of the account that owns the key
  /// @return publicKeys the public key
  function getAccountKey(
    string calldata originDomain,
    bytes calldata credentialId,
    address accountAddress
  ) external view returns (bytes32[2] memory) {
    return publicKeys[originDomain][credentialId][accountAddress];
  }

  /// @notice Runs on module install
  /// @param data ABI-encoded WebAuthn passkey to add immediately, or empty if not needed
  function onInstall(bytes calldata data) external override {
    if (data.length > 0) {
      (bytes memory credentialId, bytes32[2] memory rawPublicKey, string memory originDomain) = abi.decode(
        data,
        (bytes, bytes32[2], string)
      );
      addValidationKey(credentialId, rawPublicKey, originDomain);
    }
  }

  /// @notice Runs on module uninstall, does not manage any dependant modules
  /// @param data ABI-encoded array of origin domains to remove keys for
  function onUninstall(bytes calldata data) external override {
    PasskeyId[] memory passkeyIds = abi.decode(data, (PasskeyId[]));
    for (uint256 i = 0; i < passkeyIds.length; ++i) {
      PasskeyId memory passkeyId = passkeyIds[i];
      removeValidationKey(passkeyId.credentialId, passkeyId.domain);
    }
  }

  function isInitialized(address account) external view override returns (bool) {
    return IMSA(account).isModuleInstalled(MODULE_TYPE_VALIDATOR, address(this), "");
  }

  function isModuleType(uint256 moduleType) external pure returns (bool) {
    return moduleType == MODULE_TYPE_VALIDATOR;
  }

  function removeValidationKey(bytes memory credentialId, string memory domain) public {
    address registered = registeredAddress[domain][credentialId];
    if (registered != msg.sender) {
      revert NotKeyOwner(registered);
    }
    registeredAddress[domain][credentialId] = address(0);
    publicKeys[domain][credentialId][msg.sender] = [bytes32(0), bytes32(0)];

    emit PasskeyRemoved(msg.sender, domain, credentialId);
  }

  /// @notice Adds a WebAuthn passkey for the caller, reverts otherwise
  /// @param credentialId unique public identifier for the key
  /// @param rawPublicKey ABI-encoded WebAuthn public key to add
  /// @param originDomain the domain this associated with
  function addValidationKey(
    bytes memory credentialId,
    bytes32[2] memory rawPublicKey,
    string memory originDomain
  ) public {
    bytes32[2] memory initialAccountKey = publicKeys[originDomain][credentialId][msg.sender];
    if (uint256(initialAccountKey[0]) != 0 || uint256(initialAccountKey[1]) != 0) {
      // only allow adding new keys, no overwrites/updates
      revert KeyAlreadyExists();
    }
    if (registeredAddress[originDomain][credentialId] != address(0)) {
      // this key already exists on the domain for an existing account
      revert AccountAlreadyExists();
    }
    if (rawPublicKey[0] == 0 && rawPublicKey[1] == 0) {
      // empty keys aren't valid
      revert EmtpyKey();
    }
    uint256 domainLength = bytes(originDomain).length;
    if (domainLength < 1 || domainLength > 253) {
      // RFC 1035 sets domains between 1-253 characters
      revert BadDomainLength();
    }
    if (credentialId.length < 16) {
      // min length from: https://www.w3.org/TR/webauthn-2/#credential-id
      revert BadCredentialIDLength();
    }

    publicKeys[originDomain][credentialId][msg.sender] = rawPublicKey;
    registeredAddress[originDomain][credentialId] = msg.sender;

    emit PasskeyCreated(msg.sender, originDomain, credentialId);
  }

  /// @notice Validates a WebAuthn signature
  /// @param signedHash The hash of the signed message
  /// @param signature The signature to validate
  // TODO return
  function isValidSignatureWithSender(address sender, bytes32 signedHash, bytes calldata signature) external view returns (bytes4) {
    return webAuthVerify(signedHash, signature) ? bytes4(0x1626ba7e) : bytes4(0x00000000);
  }

  /// @notice Validates a transaction signed with a passkey
  /// @dev Does not validate the transaction signature field, which is expected to be different due to the modular format
  /// @param signedHash The hash of the signed transaction
  /// @param userOp The user operation to validate
  // TODO return
  function validateUserOp(PackedUserOperation calldata userOp, bytes32 signedHash) external view returns (uint256) {
    (bytes memory signature, , ) = abi.decode(userOp.signature, (bytes, address, bytes));
    return webAuthVerify(signedHash, signature) ? 0 : 1;
  }

  /// @notice Validates a WebAuthn signature
  /// @dev Performs r & s range validation to prevent signature malleability
  /// @dev Checks passkey authenticator data flags (valid number of credentials)
  /// @dev Requires that the transaction signature hash was the signed challenge
  /// @dev Verifies that the signature was performed by a 'get' request
  /// @param transactionHash The hash of the signed message
  /// @param fatSignature The signature to validate (authenticator data, client data, [r, s])
  /// @return true if the signature is valid
  function webAuthVerify(bytes32 transactionHash, bytes memory fatSignature) internal view returns (bool) {
    (
      bytes memory authenticatorData,
      string memory clientDataJSON,
      bytes32[2] memory rs,
      bytes memory credentialId
    ) = _decodeFatSignature(fatSignature);

    // prevent signature replay https://yondon.blog/2019/01/01/how-not-to-use-ecdsa/
    if (uint256(rs[0]) == 0 || rs[0] > HIGH_R_MAX || uint256(rs[1]) == 0 || rs[1] > LOW_S_MAX) {
      return false;
    }

    // https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data#attestedcredentialdata
    if (authenticatorData[32] & AUTH_DATA_MASK != AUTH_DATA_MASK) {
      return false;
    }

    // parse out the required fields (type, challenge, crossOrigin): https://goo.gl/yabPex
    JSONParserLib.Item memory root = JSONParserLib.parse(clientDataJSON);
    // challenge should contain the transaction hash, ensuring that the transaction is signed
    string memory challenge = root.at('"challenge"').value().decodeString();
    bytes memory challengeData = Base64.decode(challenge);
    if (challengeData.length != 32) {
      return false; // wrong hash size
    }
    if (bytes32(challengeData) != transactionHash) {
      return false;
    }

    // type ensures the signature was created from a validation request
    string memory webauthn_type = root.at('"type"').value().decodeString();
    if (WEBAUTHN_GET_HASH != keccak256(bytes(webauthn_type))) {
      return false;
    }

    // the origin determines which key to validate against
    // as passkeys are linked to domains, so the storage mapping reflects that
    string memory origin = root.at('"origin"').value().decodeString();
    bytes32[2] memory publicKey = publicKeys[origin][credentialId][msg.sender];
    if (uint256(publicKey[0]) == 0 && uint256(publicKey[1]) == 0) {
      // no key found!
      return false;
    }

    // cross-origin validation is optional, but explicitly not supported.
    // cross-origin requests would be from embedding the auth request
    // from another domain. The current SSO setup uses a pop-up instead of
    // an i-frame, so we're rejecting these until the implemention supports it
    JSONParserLib.Item memory crossOriginItem = root.at('"crossOrigin"');
    if (!crossOriginItem.isUndefined()) {
      string memory crossOrigin = crossOriginItem.value();
      if (FALSE_HASH != keccak256(bytes(crossOrigin))) {
        return false;
      }
    }

    bytes32 message = _createMessage(authenticatorData, bytes(clientDataJSON));
    return callVerifier(P256_VERIFIER, message, rs, publicKey);
  }

  function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
    return
      interfaceId == type(IERC165).interfaceId ||
      interfaceId == type(IValidator).interfaceId ||
      interfaceId == type(IModule).interfaceId;
  }

  function _createMessage(
    bytes memory authenticatorData,
    bytes memory clientData
  ) private pure returns (bytes32 message) {
    bytes32 clientDataHash = sha256(clientData);
    message = sha256(bytes.concat(authenticatorData, clientDataHash));
  }

  function _decodeFatSignature(
    bytes memory fatSignature
  )
    private
    pure
    returns (
      bytes memory authenticatorData,
      string memory clientDataSuffix,
      bytes32[2] memory rs,
      bytes memory credentialId
    )
  {
    (authenticatorData, clientDataSuffix, rs, credentialId) = abi.decode(
      fatSignature,
      (bytes, string, bytes32[2], bytes)
    );
  }

  /**
   * @notice Calls the verifier function with given params
   * @param verifier address     - Address of the verifier contract
   * @param hash bytes32         - Signed data hash
   * @param rs bytes32[2]        - Signature array for the r and s values
   * @param pubKey bytes32[2]    - Public key coordinates array for the x and y values
   * @return - bool - Return the success of the verification
   */
  function callVerifier(
    address verifier,
    bytes32 hash,
    bytes32[2] memory rs,
    bytes32[2] memory pubKey
  ) internal view returns (bool) {
    /**
     * Prepare the input format
     * input[  0: 32] = signed data hash
     * input[ 32: 64] = signature r
     * input[ 64: 96] = signature s
     * input[ 96:128] = public key x
     * input[128:160] = public key y
     */
    bytes memory input = abi.encodePacked(hash, rs[0], rs[1], pubKey[0], pubKey[1]);

    // Make a call to verify the signature
    (bool success, bytes memory data) = verifier.staticcall(input);

    uint256 returnValue;
    // Return true if the call was successful and the return value is 1
    if (success && data.length > 0) {
      assembly {
        returnValue := mload(add(data, 0x20))
      }
      return returnValue == 1;
    }

    // Otherwise return false for the unsuccessful calls and invalid signatures
    return false;
  }
}
