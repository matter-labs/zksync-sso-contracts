// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { WebAuthnValidator } from "src/modules/WebAuthnValidator.sol";
import { JSONParserLib } from "solady/utils/JSONParserLib.sol";
import { Base64 } from "solady/utils/Base64.sol";

contract WebAuthnHarness is WebAuthnValidator {
    using JSONParserLib for JSONParserLib.Item;
    using JSONParserLib for string;

    uint256 private constant HIGH_R_MAX_LOCAL = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
    uint256 private constant LOW_S_MAX_LOCAL = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;
    bytes1 private constant AUTH_DATA_MASK_LOCAL = 0x05;
    bytes32 private constant FALSE_HASH_LOCAL = keccak256("false");

    function debug_webAuthVerify(bytes32 txHash, bytes calldata fatSignature) external view returns (bool) {
        return webAuthVerify(txHash, fatSignature);
    }

    function debug_checks(
        bytes32 txHash,
        bytes calldata fatSignature
    )
        external
        view
        returns (bool rsOk, bool flagsOk, bool challengeOk, bool typeOk, bool keyOk, bool crossOk, bytes32 message)
    {
        (bytes memory authenticatorData, string memory clientDataJSON, bytes32[2] memory rs, bytes memory credentialId)
        = abi.decode(fatSignature, (bytes, string, bytes32[2], bytes));

        uint256 rVal = uint256(rs[0]);
        uint256 sVal = uint256(rs[1]);
        rsOk = !(rVal == 0 || rVal > HIGH_R_MAX_LOCAL || sVal == 0 || sVal > LOW_S_MAX_LOCAL);
        flagsOk =
            authenticatorData.length > 32 && (authenticatorData[32] & AUTH_DATA_MASK_LOCAL == AUTH_DATA_MASK_LOCAL);

        JSONParserLib.Item memory root = JSONParserLib.parse(clientDataJSON);
        string memory challenge = root.at('"challenge"').value().decodeString();
        bytes memory challengeData = Base64.decode(challenge);
        challengeOk = challengeData.length == 32 && bytes32(challengeData) == txHash;

        string memory webauthnType = root.at('"type"').value().decodeString();
        typeOk = (keccak256(bytes(webauthnType)) == keccak256("webauthn.get"));

        string memory origin = root.at('"origin"').value().decodeString();
        bytes32[2] memory publicKey = this.getAccountKey(origin, credentialId, msg.sender);
        keyOk = !(uint256(publicKey[0]) == 0 && uint256(publicKey[1]) == 0);

        JSONParserLib.Item memory crossOriginItem = root.at('"crossOrigin"');
        if (!crossOriginItem.isUndefined()) {
            string memory crossOrigin = crossOriginItem.value();
            crossOk = (FALSE_HASH_LOCAL == keccak256(bytes(crossOrigin)));
        } else {
            crossOk = true;
        }

        bytes32 clientDataHash = sha256(bytes(clientDataJSON));
        message = sha256(bytes.concat(authenticatorData, clientDataHash));
    }
}
