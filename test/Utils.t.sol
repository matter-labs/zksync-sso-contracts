// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "src/libraries/ExecutionLib.sol";
import "src/libraries/ModeLib.sol";

contract UtilsTest is Test {
    function setUp() public { }

    function decode(bytes calldata encoded) public pure returns (address, uint256, bytes calldata) {
        return ExecutionLib.decodeSingle(encoded);
    }

    function test_encodeDecodeExecution(address target, uint256 value, bytes memory callData) public view {
        bytes memory encoded = ExecutionLib.encodeSingle(target, value, callData);
        (address _target, uint256 _value, bytes memory _callData) = this.decode(encoded);

        vm.assertTrue(_target == target);
        vm.assertTrue(_value == value);
        vm.assertTrue(keccak256(_callData) == keccak256(callData));
    }

    function test_encodeDecodeMode() public pure {
        CallType callType = CALLTYPE_SINGLE;
        ExecType execType = EXECTYPE_DEFAULT;
        ModeSelector modeSelector = MODE_DEFAULT;
        ModePayload payload = ModePayload.wrap(bytes22(hex"01"));
        ModeCode enc = ModeLib.encode(callType, execType, modeSelector, payload);

        (CallType _calltype, ExecType _execType, ModeSelector _mode, ModePayload _payload) = ModeLib.decode(enc);
        vm.assertTrue(_calltype == callType);
        vm.assertTrue(_execType == execType);
        vm.assertTrue(_mode == modeSelector);
        vm.assertTrue(ModePayload.unwrap(_payload) == ModePayload.unwrap(payload));
    }
}
