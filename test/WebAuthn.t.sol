// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IERC1271 } from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { Base64 } from "solady/utils/Base64.sol";

import { WebAuthnValidator } from "src/modules/WebAuthnValidator.sol";
import { IMSA } from "src/interfaces/IMSA.sol";
import { ModularSmartAccount } from "src/ModularSmartAccount.sol";
import { MODULE_TYPE_VALIDATOR } from "src/interfaces/IERC7579Module.sol";
import { IERC7579Account } from "src/interfaces/IERC7579Account.sol";

import { MSATest } from "./MSATest.sol";

contract WebAuthnValidatorTest is MSATest {
    WebAuthnValidator internal validator;

    string internal constant ORIGIN_DOMAIN = "http://localhost:3005";

    /// See: https://gist.github.com/Vectorized/599b0d8a94d21bc74700eb1354e2f55c
    bytes internal constant VERIFIER_BYTECODE =
        hex"3d604052610216565b60008060006ffffffffeffffffffffffffffffffffff60601b19808687098188890982838389096004098384858485093d510985868b8c096003090891508384828308850385848509089650838485858609600809850385868a880385088509089550505050808188880960020991505093509350939050565b81513d83015160408401516ffffffffeffffffffffffffffffffffff60601b19808384098183840982838388096004098384858485093d510985868a8b096003090896508384828308850385898a09089150610102848587890960020985868787880960080987038788878a0387088c0908848b523d8b015260408a0152565b505050505050505050565b81513d830151604084015185513d87015160408801518361013d578287523d870182905260408701819052610102565b80610157578587523d870185905260408701849052610102565b6ffffffffeffffffffffffffffffffffff60601b19808586098183840982818a099850828385830989099750508188830383838809089450818783038384898509870908935050826101be57836101be576101b28a89610082565b50505050505050505050565b808485098181860982828a09985082838a8b0884038483860386898a09080891506102088384868a0988098485848c09860386878789038f088a0908848d523d8d015260408c0152565b505050505050505050505050565b6020357fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325513d6040357f7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a88111156102695782035b60206108005260206108205260206108405280610860526002830361088052826108a0526ffffffffeffffffffffffffffffffffff60601b198060031860205260603560803560203d60c061080060055afa60203d1416837f5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b8585873d5189898a09080908848384091484831085851016888710871510898b108b151016609f3611161616166103195760206080f35b60809182523d820152600160c08190527f6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2966102009081527f4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f53d909101526102405261038992509050610100610082565b610397610200610400610082565b6103a7610100608061018061010d565b6103b7610200608061028061010d565b6103c861020061010061030061010d565b6103d961020061018061038061010d565b6103e9610400608061048061010d565b6103fa61040061010061050061010d565b61040b61040061018061058061010d565b61041c61040061020061060061010d565b61042c610600608061068061010d565b61043d61060061010061070061010d565b61044e61060061018061078061010d565b81815182350982825185098283846ffffffffeffffffffffffffffffffffff60601b193d515b82156105245781858609828485098384838809600409848586848509860986878a8b096003090885868384088703878384090886878887880960080988038889848b03870885090887888a8d096002098882830996508881820995508889888509600409945088898a8889098a098a8b86870960030908935088898687088a038a868709089a5088898284096002099950505050858687868709600809870387888b8a0386088409089850505050505b61018086891b60f71c16610600888a1b60f51c16176040810151801585151715610564578061055357506105fe565b81513d8301519750955093506105fe565b83858609848283098581890986878584098b0991508681880388858851090887838903898a8c88093d8a015109089350836105b957806105b9576105a9898c8c610008565b9a509b50995050505050506105fe565b8781820988818309898285099350898a8586088b038b838d038d8a8b0908089b50898a8287098b038b8c8f8e0388088909089c5050508788868b098209985050505050505b5082156106af5781858609828485098384838809600409848586848509860986878a8b096003090885868384088703878384090886878887880960080988038889848b03870885090887888a8d096002098882830996508881820995508889888509600409945088898a8889098a098a8b86870960030908935088898687088a038a868709089a5088898284096002099950505050858687868709600809870387888b8a0386088409089850505050505b61018086891b60f51c16610600888a1b60f31c161760408101518015851517156106ef57806106de5750610789565b81513d830151975095509350610789565b83858609848283098581890986878584098b0991508681880388858851090887838903898a8c88093d8a01510908935083610744578061074457610734898c8c610008565b9a509b5099505050505050610789565b8781820988818309898285099350898a8586088b038b838d038d8a8b0908089b50898a8287098b038b8c8f8e0388088909089c5050508788868b098209985050505050505b50600488019760fb19016104745750816107a2573d6040f35b81610860526002810361088052806108a0523d3d60c061080060055afa898983843d513d510987090614163d525050505050505050503d3df3fea264697066735822122063ce32ec0e56e7893a1f6101795ce2e38aca14dd12adb703c71fe3bee27da71e64736f6c634300081a0033";
    // "

    // Random bytes
    bytes internal constant CREDENTIAL_ID = hex"26297dec52fc8943538108380adc9693d913add0bb2173fe29c6587ed46a299d";

    function setUp() public override {
        super.setUp();
        validator = new WebAuthnValidator();
        vm.etch(0x000000000000D01eA45F9eFD5c54f037Fa57Ea1a, VERIFIER_BYTECODE);
    }

    function test_isValidSignature() public {
        test_deployAccountWithPasskey();

        // Test vector taken from
        // https://github.com/Vectorized/solady/blob/208e4f31cfae26e4983eb95c3488a14fdc497ad7/test/WebAuthn.t.sol#L27
        bytes memory challenge = abi.encode(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);
        bytes memory authenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000101";
        string memory clientDataJSON = string(
            abi.encodePacked(
                '{"type":"webauthn.get","challenge":"',
                Base64.encode(challenge, true, true),
                '","origin":"', ORIGIN_DOMAIN, '"}'
            )
        );
        uint256 r = 0x60946081650523acad13c8eff94996a409b1ed60e923c90f9e366aad619adffa;
        uint256 s = 0x3216a237b73765d01b839e0832d73474bc7e63f4c86ef05fbbbfbeb34b35602b;

        bytes32[2] memory rs = [bytes32(r), bytes32(s)];
        bytes memory fatSignature = abi.encode(authenticatorData, clientDataJSON, rs, CREDENTIAL_ID);

        vm.prank(address(account));
        bytes4 result = validator.isValidSignatureWithSender(address(0), bytes32(challenge), fatSignature);
        vm.assertEq(result, IERC1271.isValidSignature.selector);
    }

    function test_deployAccountWithPasskey() public {
        bytes32[2] memory publicKey = [
            bytes32(0x3f2be075ef57d6c8374ef412fe54fdd980050f70f4f3a00b5b1b32d2def7d28d),
            bytes32(0x57095a365acc2590ade3583fabfe8fbd64a9ed3ec07520da00636fb21f0176c1)
        ];

        address[] memory modules = new address[](2);
        modules[0] = address(validator);
        modules[1] = address(eoaValidator);

        address[] memory owners = new address[](1);
        owners[0] = owner.addr;

        bytes[] memory initData = new bytes[](2);
        initData[0] = abi.encode(CREDENTIAL_ID, publicKey, ORIGIN_DOMAIN);
        initData[1] = abi.encode(owners);

        bytes memory data = abi.encodeCall(IMSA.initializeAccount, (modules, initData));
        account = ModularSmartAccount(payable(factory.deployAccount(keccak256("my-other-account-id"), data)));
        vm.deal(address(account), 1 ether);

        vm.assertTrue(validator.isInitialized(address(account)), "Validator not initialized");
        vm.assertTrue(validator.isModuleType(MODULE_TYPE_VALIDATOR), "Wrong module type");

        bytes32[2] memory accountKey = validator.getAccountKey(ORIGIN_DOMAIN, CREDENTIAL_ID, address(account));
        vm.assertEq(accountKey[0], publicKey[0], "Public key X mismatch");
        vm.assertEq(accountKey[1], publicKey[1], "Public key Y mismatch");
    }

    function test_uninstallValidator() public {
        test_deployAccountWithPasskey();

        WebAuthnValidator.PasskeyId[] memory passkeys = new WebAuthnValidator.PasskeyId[](1);
        passkeys[0] = WebAuthnValidator.PasskeyId({ credentialId: CREDENTIAL_ID, domain: ORIGIN_DOMAIN });

        bytes memory data =
            abi.encodeCall(ModularSmartAccount.uninstallModule, (MODULE_TYPE_VALIDATOR, address(validator), abi.encode(passkeys)));
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeSignedUserOp(data, owner.key, address(eoaValidator));
        vm.expectEmit(true, true, true, true);
        emit IERC7579Account.ModuleUninstalled(MODULE_TYPE_VALIDATOR, address(validator));
        entryPoint.handleOps(userOps, bundler);

        vm.assertTrue(!validator.isInitialized(address(account)), "Validator not uninitialized");

        bytes32[2] memory accountKey = validator.getAccountKey(ORIGIN_DOMAIN, CREDENTIAL_ID, address(account));
        vm.assertEq(accountKey[0], 0, "Public key X not cleared");
        vm.assertEq(accountKey[1], 0, "Public key Y not cleared");
    }
}
