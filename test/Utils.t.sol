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

    function test_encodeAndDecode(address target, uint256 value, bytes memory callData) public view {
        bytes memory encoded = ExecutionLib.encodeSingle(target, value, callData);
        (address _target, uint256 _value, bytes memory _callData) = this.decode(encoded);

        assertTrue(_target == target);
        assertTrue(_value == value);
        assertTrue(keccak256(_callData) == keccak256(callData));
    }

    function test_encodeDecodeSingle() public pure {
        CallType callType = CALLTYPE_SINGLE;
        ExecType execType = EXECTYPE_DEFAULT;
        ModeSelector modeSelector = MODE_DEFAULT;
        ModePayload payload = ModePayload.wrap(bytes22(hex"01"));
        ModeCode enc = ModeLib.encode(callType, execType, modeSelector, payload);

        (CallType _calltype, ExecType _execType, ModeSelector _mode,) = ModeLib.decode(enc);
        assertTrue(_calltype == callType);
        assertTrue(_execType == execType);
        assertTrue(_mode == modeSelector);
        // assertTrue(_payload == payload);
    }

    function test_encodeDecodeBatch() public pure {
        CallType callType = CALLTYPE_BATCH;
        ExecType execType = EXECTYPE_DEFAULT;
        ModeSelector modeSelector = MODE_DEFAULT;
        ModePayload payload = ModePayload.wrap(bytes22(hex"01"));
        ModeCode enc = ModeLib.encode(callType, execType, modeSelector, payload);

        (CallType _calltype, ExecType _execType, ModeSelector _mode,) = ModeLib.decode(enc);
        assertTrue(_calltype == callType);
        assertTrue(_execType == execType);
        assertTrue(_mode == modeSelector);
        // assertTrue(_payload == payload);
    }
}
