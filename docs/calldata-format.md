# General ERC-7579 Calldata Format

There are 2 possible scenarios for a call from `EntryPoint` to the smart account:

1. Call to a **core account method**, e.g. `installModule`
2. Call to an **external address**

Calls to **core account methods** are trivially formatted: method selector + ABI encoded parameters.

Calls to **external addresses** are made via `execute(ModeCode code, bytes calldata data)` method. `code` is a `bytes32` value created according to the [standard](https://eips.ethereum.org/EIPS/eip-7579#execution-behavior):

- `callType` (1 byte): `0x00` for a single `call`, `0x01` for a batch `call`, `0xfe` for `staticcall` and `0xff` for `delegatecall`
- `execType` (1 byte): `0x00` for executions that revert on failure, `0x01` for executions that do not revert on failure but emit `event TryExecuteUnsuccessful(uint256 batchExecutionindex, bytes returnData)` on error
- unused (4 bytes): this range is reserved for future standardization
- `modeSelector` (4 bytes): an additional mode selector that can be used to create further execution modes, **currently unused**
- `modePayload` (22 bytes): additional data to be passed, **currently unused**

Depending on the value of the `callType`, data is one of the following:

- if `callType == CALLTYPE_SINGLE`, `data` is `abi.encodePacked(target, value, callData)`
- if `callType == CALLTYPE_DELEGATECALL`, `data` is `abi.encodePacked(target, callData)`
- if `callType == CALLTYPE_BATCH`, `data` is `abi.encode(executions)` where `executions` is an array `Execution[]` and

```solidity
struct Execution {
    address target;
    uint256 value;
    bytes callData;
}
```

## Example

An external call to the contract `Storage` method `setValue(uint256 value)` with parameter 42 would have calldata as follows:

```solidity
abi.encodeCall(IERC7579Account.execute, (
    bytes32(0), // callType: single, execType: default
    abi.encodePacked(
        storageAddress, // target
        0, // value
        abi.encodeCall(Storage.setValue, (42)) // callData
    )
)
```
