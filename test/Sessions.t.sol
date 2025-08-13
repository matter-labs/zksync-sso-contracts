// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

// NOTE: this contract has to be licensed under the GPL-3.0
// since it uses EntryPoint.sol which is licensed under the same license.
import { EntryPoint } from "account-abstraction/core/EntryPoint.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";
import { Test } from "forge-std/Test.sol";
import { console } from "forge-std/console.sol";
import { ModularSmartAccount } from "src/ModularSmartAccount.sol";
import { MSAProxy } from "src/utils/MSAProxy.sol";
import { EOAKeyValidator } from "src/modules/EOAKeyValidator.sol";
import { SessionKeyValidator } from "src/modules/SessionKeyValidator.sol";
import { IMSA } from "src/interfaces/IMSA.sol";
import { ExecutionLib } from "src/libraries/ExecutionLib.sol";
import { ModeLib } from "src/libraries/ModeLib.sol";
import { MODULE_TYPE_VALIDATOR } from "src/interfaces/IERC7579Module.sol";
import { IERC7579Account } from "src/interfaces/IERC7579Account.sol";
import { SessionLib } from "src/libraries/SessionLib.sol";

contract SessionsTest is Test {
    EntryPoint public entryPoint;
    ModularSmartAccount public account;
    IMSA public accountProxy;
    uint256 accountNonce = 0;

    EOAKeyValidator public eoaValidator;
    SessionKeyValidator public sessionKeyValidator;
    Account public owner;
    Account public sessionOwner;
    address recipient;
    address payable bundler;

    SessionLib.SessionSpec public spec;

    function setUp() public {
        owner = makeAccount("owner");
        sessionOwner = makeAccount("sessionOwner");
        recipient = makeAddr("sessionRecipient");
        bundler = payable(makeAddr("bundler"));

        address[] memory owners = new address[](1);
        owners[0] = owner.addr;

        account = new ModularSmartAccount();
        eoaValidator = new EOAKeyValidator();
        sessionKeyValidator = new SessionKeyValidator();

        vm.etch(account.ENTRY_POINT(), address(new EntryPoint()).code);
        entryPoint = EntryPoint(payable(account.ENTRY_POINT()));
        accountProxy = IMSA(
            address(
                new MSAProxy(
                    address(account),
                    abi.encodeCall(IMSA.initializeAccount, (address(eoaValidator), abi.encode(owners)))
                )
            )
        );

        vm.deal(address(accountProxy), 1 ether);
    }

    function makeUserOp(
        bytes memory data,
        uint256 signerKey,
        address validator,
        bytes memory validatorData
    )
        public
        returns (PackedUserOperation memory userOp)
    {
        userOp = PackedUserOperation({
            sender: address(accountProxy),
            nonce: accountNonce++,
            initCode: "",
            callData: data,
            accountGasLimits: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            preVerificationGas: 2e6,
            gasFees: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            paymasterAndData: "",
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, userOpHash);
        userOp.signature = abi.encode(address(validator), abi.encodePacked(r, s, v), validatorData);
    }

    function makeUserOp(
        address target,
        uint256 value,
        bytes memory data,
        uint256 signerKey,
        address validator,
        bytes memory validatorData
    )
        public
        returns (PackedUserOperation memory)
    {
        bytes memory callData = ExecutionLib.encodeSingle(target, value, data);
        bytes memory executeData = abi.encodeCall(IERC7579Account.execute, (ModeLib.encodeSimpleSingle(), callData));
        return makeUserOp(executeData, signerKey, validator, validatorData);
    }

    function test_installValidator() public {
        bytes memory data =
            abi.encodeCall(ModularSmartAccount.installModule, (MODULE_TYPE_VALIDATOR, address(sessionKeyValidator), ""));
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeUserOp(data, owner.key, address(eoaValidator), "");

        vm.expectEmit(true, false, false, false);
        emit IERC7579Account.ModuleInstalled(MODULE_TYPE_VALIDATOR, address(sessionKeyValidator));
        entryPoint.handleOps(userOps, bundler);
    }

    function test_createSession() public {
        test_installValidator();

        SessionLib.TransferSpec[] memory transferPolicies = new SessionLib.TransferSpec[](1);
        transferPolicies[0] = SessionLib.TransferSpec({
            target: recipient,
            maxValuePerUse: 0.1 ether,
            valueLimit: SessionLib.UsageLimit({ limitType: SessionLib.LimitType.Unlimited, limit: 0, period: 0 })
        });

        spec = SessionLib.SessionSpec({
            signer: sessionOwner.addr,
            expiresAt: uint48(block.timestamp + 1000),
            transferPolicies: transferPolicies,
            callPolicies: new SessionLib.CallSpec[](0),
            feeLimit: SessionLib.UsageLimit({ limitType: SessionLib.LimitType.Lifetime, limit: 0.15 ether, period: 0 })
        });

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeUserOp(
            address(sessionKeyValidator),
            0,
            abi.encodeCall(SessionKeyValidator.createSession, (spec)),
            owner.key,
            address(eoaValidator),
            ""
        );

        bytes32 sessionHash = keccak256(abi.encode(spec));
        vm.expectEmit(true, true, true, true);
        emit SessionKeyValidator.SessionCreated(address(accountProxy), sessionHash, spec);
        entryPoint.handleOps(userOps, bundler);

        SessionLib.Status status = sessionKeyValidator.sessionStatus(address(accountProxy), sessionHash);
        vm.assertTrue(status == SessionLib.Status.Active);
    }

    function test_useSession() public {
        test_createSession();

        vm.deal(address(accountProxy), 0.2 ether);
        accountNonce = uint256(uint160(sessionOwner.addr)) << 64;
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeUserOp(
            recipient, 0.05 ether, "", sessionOwner.key, address(sessionKeyValidator), abi.encode(spec, new uint48[](2))
        );

        entryPoint.handleOps(userOps, bundler);
        vm.assertEq(recipient.balance, 0.05 ether);
    }

    function testRevert_useSession() public {
        test_createSession();

        vm.deal(address(accountProxy), 0.2 ether);
        accountNonce = uint256(uint160(sessionOwner.addr)) << 64;
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = makeUserOp(
            recipient,
            0.11 ether, // more than maxValuePerUse
            "",
            sessionOwner.key,
            address(sessionKeyValidator),
            abi.encode(spec, new uint48[](2))
        );

        vm.expectRevert();
        entryPoint.handleOps(userOps, bundler);
    }
}
