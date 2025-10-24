// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { EIP712 } from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";

struct MockMessage {
    string message;
    uint256 value;
}

contract MockERC1271Caller is EIP712 {
    constructor() EIP712("ERC1271Caller", "1.0.0") { }

    function validateStruct(MockMessage calldata mockMessage, address signer, bytes calldata signature)
        external
        view
        returns (bool)
    {
        require(signer != address(0), "Invalid signer address");

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("MockMessage(string message,uint256 value)"),
                keccak256(bytes(mockMessage.message)),
                mockMessage.value
            )
        );

        bytes32 digest = _hashTypedDataV4(structHash);

        if (signer.code.length > 0) {
            // Call the ERC1271 contract
            bytes4 magic = IERC1271(signer).isValidSignature(digest, signature);
            return magic == IERC1271.isValidSignature.selector;
        } else {
            return ECDSA.recover(digest, signature) == signer;
        }
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }
}
