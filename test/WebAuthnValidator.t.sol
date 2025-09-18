// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import { WebAuthnValidator } from "src/modules/WebAuthnValidator.sol";

contract WebAuthnValidatorHarness is WebAuthnValidator {
    function exposed_webAuthVerify(bytes32 hash, bytes memory fatSignature) external view returns (bool) {
        return webAuthVerify(hash, fatSignature);
    }
}

contract WebAuthnValidatorTest is Test {
    WebAuthnValidatorHarness internal validator;
    address internal constant ACCOUNT = address(0x1234);

    function setUp() public {
        validator = new WebAuthnValidatorHarness();
        bytes memory passthrough = hex"600160005260206000f3";
        vm.etch(address(uint160(0x0100)), passthrough);
        vm.etch(0x000000000000D01eA45F9eFD5c54f037Fa57Ea1a, passthrough);
        vm.etch(0x0000000000001Ab2e8006Fd8B71907bf06a5BDEE, passthrough);
    }

    function test_webAuthVerifySampleVector() public {
        bytes32[2] memory publicKey = [
            bytes32(0xdb9459a8e40aea942cb1f9ec2cf67c601bb152b9a67ed822a33d33299d83a75e),
            bytes32(0x63601b6ea06083d975fa3929980481ba9e40e5f7afa90367999dd04539fc683d)
        ];

        bytes memory credentialId = hex"26297dec52fc8943538108380adc9693d913add0bb2173fe29c6587ed46a299d";

        vm.prank(ACCOUNT);
        validator.addValidationKey(credentialId, publicKey, "https://example.com");

        bytes memory authenticatorData = hex"a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce19470500000001";
        string memory clientDataJSON =
            "{\"type\":\"webauthn.get\",\"challenge\":\"4ZGhDJjTm/3ZEjnaBv/n2epbmR0+DYlOcUSE+adv40U=\",\"origin\":\"https://example.com\",\"crossOrigin\":false}";

        bytes32[2] memory rs = [
            bytes32(0xd53ad7e2914b6a79533210e2a7a060cc5704c9602c4bb930c71bd744fb272699),
            bytes32(0x2433fc9277ab7890de8aae6d6b7ecd631cac1883f47d375873a759c152ca29d6)
        ];

        bytes memory fatSignature = abi.encode(authenticatorData, clientDataJSON, rs, credentialId);

        bytes32 hash = 0xe191a10c98d39bfdd91239da06ffe7d9ea5b991d3e0d894e714484f9a76fe345;

        vm.prank(ACCOUNT);
        bool ok = validator.exposed_webAuthVerify(hash, fatSignature);

        assertTrue(ok, "webAuthVerify should accept the reference signature");
    }
}
