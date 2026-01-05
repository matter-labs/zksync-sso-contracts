# Developer documentation

## Overview

ZKsync SSO is a modular smart account compliant with [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) and [ERC-7579](https://eips.ethereum.org/EIPS/eip-7579) and based on the [ERC-7579 reference implementation](https://github.com/erc7579/erc7579-implementation).

Being familiar with these standards can prove useful while reading this documentation.

## Architecture

![Architecture](./architecture.png)

The factory and all modules are behind `TransparentUpgradeableProxy`s.

Factory deploys `BeaconProxy`s that point to the `UpgradeableBeacon` which in turn has the account implementation address.

The following is a sequence diagram for the general SSO user flow:

![General flow](./general-flow.png)

## Deploying

To deploy the contracts, use the `Deploy.s.sol` script.

To deploy the factory and 4 modules (`EOAKeyValidator`, `SessionKeyValidator`, `WebAuthnValidator` and `GuardianExecutor`):

```bash
forge script script/Deploy.s.sol \
    --rpc-url $RPC_URL \
    --private-key $DEPLOYER \
    --broadcast
```

To deploy an account from an existing factory with preinstalled modules:

```bash
forge script script/Deploy.s.sol --sig 'deployAccount(address,address[])' $FACTORY_ADDR $MODULES_ADDRS \
    --rpc-url $RPC_URL \
    --private-key $DEPLOYER \
    --broadcast
```

To deploy everything at once (all 4 modules will be installed on the account):

```bash
forge script script/Deploy.s.sol --sig 'deployAll()' \
    --rpc-url $RPC_URL \
    --private-key $DEPLOYER \
    --broadcast
```

In each case, admin of the factory and all modules will be the deployer.
For the account, the deployer's key will be registered as an EOA owner in the `EOAKeyValidator`.

Address of the new account can be found in the emitted event `AccountCreated(address indexed newAccount, address indexed deployer)`.

### Manually

To deploy an account from an existing factory, call `deployAccount(bytes32 salt, bytes calldata initData)` on the factory. `initData` must be encoded in the following format:

```solidity
address[] memory modules = ...  // modules to be installed on the new account
bytes[] memory data = ...       // initialization data for each module (empty if not needed)
initData = abi.encodeCall(IMSA.initializeAccount, (modules, data))
```

Modules installed this way have to be of single type and must not repeat in the array.

## Modules

Currently, only validator, fallback and executor module types are supported (as defined in the standard).

To install, uninstall or unlink a module, call the corresponding core functions on the account contract:

- `installModule(uint256 typeId, address module, bytes calldata initData)`
- `uninstallModule(uint256 typeId, address module, bytes calldata deinitData)`
- `uninstallModule(uint256 typeId, address module, bytes calldata deinitData)`

`typeId`, according to the [standard](https://eips.ethereum.org/EIPS/eip-7579):
- 1 for validator
- 2 for executor
- 3 for fallback

The account will call module's `onInstall(bytes)` hook upon installation and `onUninstall(bytes)` hook upon uninstall and unlink. The format for the supplied data is different for each module and is described below.

Unlinking is the same as uninstalling, but does not fail if `onUninstall` call to the module fails. Instead, error is emitted as `ModuleUnlinked(uint256 indexed typeId, address indexed module, bytes errorMsg)` event.

A single contract can house multiple module types, each type is installed separately.

### `EOAKeyValidator`

Stores EOA addresses as account owners. Each address has full "admin" privileges to the account, as long as this validator is installed.

- `onInstall` data format: ABI-encoded array of addresses - initial owners
- `onUninstall` data format: ABI-encoded array of addresses - owners to remove

Other methods:
- `addOwner(address owner)` - adds an EOA owner, emits `OwnerAdded(address indexed account, address indexed owner)`
- `removeOwner(address owner)` - removes existing EOA owner, emits `OwnerRemoved(address indexed account, address indexed owner)`
- `isOwnerOf(address account, address owner) returns (bool)` - whether or not an address is an owner of the account

### `WebAuthnValidator`

Stores WebAuthn passkeys per origin domain for each account. Each passkey has full "admin" privileges to the account, as long as this validator is installed.

- `onInstall` data format: ABI-encoded `(bytes credentialId, bytes32[2] publicKey, string domain)` - initial passkey, or empty
- `onUninstall` data format: ABI-encoded array of `(string domain, bytes credentialId)` - passkeys to remove

Other methods:
- `addValidationKey(bytes credentialId, bytes32[2] newKey, string domain)` - adds new passkey
- `removeValidationKey(bytes credentialId, string domain)` - removes existing passkey
- `getAccountKey(string domain, bytes credentialId, address account) returns (bytes32[2])` - account's public key on the domain with given credential ID
- `getAccountList(string domain, bytes credentialId) returns (address[])` - list of accounts on the domain with given credential ID (normally length of 1)

### `SessionKeyValidator`

Grants a 3rd party limited access to the account with configured permissions.

A session is defined by the following structure:

```solidity
struct SessionSpec {
    address signer;
    uint48 expiresAt;
    UsageLimit feeLimit;
    CallSpec[] callPolicies;
    TransferSpec[] transferPolicies;
}
```

- `signer` - Address corresponding to an EOA private key that will be used to sign session transactions. **Signers are required to be globally unique.**
- `expiresAt` - Timestamp after which the session no longer can be used. **Session expiration is required to be no earlier than 60 seconds after session creation.**
- `feeLimit` - a `UsageLimit` (explained below) structure that limits how much fees this session can spend. **Required to not be `Unlimited`.**
- `callPolicies` - a `CallSpec` (explained below) array that defines what kinds of calls are permitted in the session. **The array has to have unique (`target`, `selector`) pairs.**
- `transferPolicies` - a `TransferSpec` (explained below) array that defines that kinds of transfers (calls with no calldata) are permitted in the session. **The array has to have unique targets**

All usage limits are defined by the following structure:

```solidity
struct UsageLimit {
    LimitType limitType;  // can be Unlimited (0), Lifetime (1) or Allowance (2)
    uint256 limit;        // ignored if limitType == Unlimited
    uint48 period;        // ignored if limitType != Allowance
}
```

- `limitType` defines what kind of limit (if any) this is.
    - `Unlimited` does not define any limits.
    - `Lifetime` defines a cumulative lifetime limit: sum of all uses of the value in the current session has to not surpass `limit`.
    - `Allowance` defines a periodically refreshing limit: sum of all uses of the value during the current `period` has not surpass `limit`.
- `limit` - the actual number to limit by.
- `period` - length of the period in seconds.

Transfer policies are defined by the following structure:

```solidity
struct TransferSpec {
    address target;
    uint256 maxValuePerUse;
    UsageLimit valueLimit;
}
```

- `target` - address to which transfer is being made.
- `maxValuePerUse` - maximum value that is possible to send in one transfer.
- `valueLimit` - cumulative transfer value limit.

Call policies are defined by the following structure:

```solidity
struct CallSpec {
    address target;
    bytes4 selector;
    uint256 maxValuePerUse;
    UsageLimit valueLimit;
    Constraint[] constraints;
}
```

- `target` - address to which call is being made.
- `selector` - selector of the method being called.
- `maxValuePerUse` - maximum value that is possible to send in one call.
- `valueLimit` - cumulative call value limit.
- `constraints` - array of `Constraint` (explained below) structures that define constraints on method arguments.

Call constraints are defined by the following structures:

```solidity
struct Constraint {
    Condition condition;
    uint64 index;
    bytes32 refValue;
    UsageLimit limit;
}


enum Condition {
    Unconstrained,
    Equal,
    Greater,
    Less,
    GreaterOrEqual,
    LessOrEqual,
    NotEqual
}
```

- `index` - index of the argument in the called method, starting with 0, assuming all arguments are 32-byte words after ABI-encoding.
    - E.g., specifying `index: X` will constrain calldata bytes `4+32*X:4+32*(X+1)`
- `limit` - usage limit for the argument interpreted as `uint256`.
- `condition` - how the argument is required to relate to `refValue`: see `enum Condition` above.
- `refValue` - reference value for the condition; ignored if condition is `Unconstrained`.

---

- `onInstall` data format: empty
- `onUninstall` data format: ABI-encoded array of session hashes to revoke

Other methods:
- `createSession(SessionSpec spec, bytes proof)` - create a new session; requires `proof` - a signature of the hash `keccak256(abi.encode(sessionHash, accountAddress))` signed by session `signer`
- `revokeKey(bytes32 sessionHash)` - closes an active session by the provided hash
- `revokeKeys(bytes32[] sessionHashes)` - same as `revokeKey` but closes multiple sessions at once
- `sessionStatus(address account, bytes32 sessionHash) returns (SessionStatus)` - returns `NotInitialized` (0), `Active` (1) or `Closed` (2); note: expired sessions are still considered active if not revoked explicitly
- `sessionState(address account, SessionSpec spec) returns (SessionState)` - returns the session status and the state of all cumulative limits used in the session as a following structure:

```solidity
// Info about remaining session limits and its status
struct SessionState {
    Status status;
    uint256 feesRemaining;
    LimitState[] transferValue;
    LimitState[] callValue;
    LimitState[] callParams;
}

struct LimitState {
    uint256 remaining; // this might also be limited by a constraint or `maxValuePerUse`, which is not reflected here
    address target;
    bytes4 selector;   // ignored for transfer value
    uint256 index;     // ignored for transfer and call value
}
```

Note: `sessionHash` is what is stored on-chain, and is defined by `keccak256(abi.encode(sessionSpec))`.

### `GuardianExecutor`

Stores addresses trusted by the account to perform an EOA or WebAutn key recovery. Either `EOAKeyValidator` or `WebAuthnValidator` must be installed.

The flow is the following:

```mermaid
sequenceDiagram
    actor Guardian
    participant GuardiansExecutor
    participant SmartAccount as SmartAccount (ERC-7579)
    participant WebauthnValidator
    actor User

    User->>SmartAccount: proposeGuardian(guardian)
    SmartAccount-->>WebauthnValidator: validate
    WebauthnValidator-->>SmartAccount: ok
    SmartAccount->>GuardiansExecutor: proposeGuardian(guardian)
    Guardian->>GuardiansExecutor: acceptGuardian(account)

    Note over User: Lose passkey

    Guardian->>GuardiansExecutor: initializeRecovery(account, new passkey)
    Note over Guardian: Wait 24 hours
    Guardian->>GuardiansExecutor: finalizeRecovery(account, new passkey)
    GuardiansExecutor->>SmartAccount: executeFromExecutor("add new passkey")
    SmartAccount->>WebauthnValidator: addValidationKey(new passkey)
```

Important notes:
- Account owner has to first propose to another address to be its guardian
- After the guardian address accepts, it can initiate a recovery
- Recovery can be either for an EOA key or a Webauthn passkey, given that a corresponding validator is installed on the account
- Any guardian can initiate a recovery alone. Guardians can themselves be multisig accounts if that is desired
- A user can discard an initiated recovery in case one of the guardians is malicious
- Recovery can be finalized not earlier than 24 hours and not later than 72 hours after initiating it
- Only one recovery can be ongoing at a time

---

- `onInstall` data format: empty
- `onUninstall` data format: empty

Other methods:
- `proposeGuardian(address newGuardian)` - propose an address to be a guardian
- `acceptGuardian(address accountToGuard)` - an address that was proposed to can accept its role as a guardian
- `initializeRecovery(address accountToRecover, RecoveryType recoveryType, bytes data)` - initialize recovery of an EOA key (`recoveryType` 1) or passkey (`recoveryType` 2) of an account; `data` is ABI-encoded arguments to `EOAKeyValidator.addOwner` or `WebAuthnValidator.addValidationKey`
- `finalizeRecovery(address account, bytes data)` - finalize an ongoing recovery; the same data has to be passed in as was passed during initializing
- `discardRecovery()` - discard an ongoing recovery
- `guardianStatusFor(address account, address guardian) returns (bool isPresent, bool isActive)` - whether a given address was proposed to (is present) and has accepted (is active)

## Registry

The default registry is not implemented but the account supports having a [ERC-7484](https://eips.ethereum.org/EIPS/eip-7484) to check all modules against. The modules are checked upon installation, and upon `executeFromExecutor` call.

By default, no registry is installed on the account so no modules are validated.

## General ERC-7579 calldata format

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

For example, an external call to the contract `Storage` method `setValue(uint256 value)` with parameter 42 would have calldata as follows:

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

## Signature formats

### `isValidSignature` signature format

```solidity
abi.encodePacked(
	validatorAddress,  // address of the validator that would check the signature
	erc7739Signature   // signature, formatted according to https://eips.ethereum.org/EIPS/eip-7739
)
```

### `validateUserOp` signature format

Signatures are formatted as follows:

```solidity
abi.encodePacked(
	validatorAddress,  // address of the validator that would check the signature
	signatureWithData, // actual signature of the PackedUserOperation along with any additional data,
                       // depending on the validator (described below)
                       // e.g. for EOAKeyValidator this is (r, s, v)
)
```

Note: `EOAValidator` does not require additional data in the userOp signature, but both `SessionKeyValidator` and `WebAuthnValidator` do and the format is described below.

---

The following validator-specific signatures are to be appended after the validator address, as described above:

### `EOAKeyValidator` signature format

```solidity
abi.encodePacked(r, s, v) // your standard 65-byte ECDSA signature
```

### `SessionKeyValidator` signature format

```solidity
abi.encode(
    signature    // ECDSA signature of the session owner -- (r, s, v)
    sessionSpec, // a session spec of the active session with fields in the exact order
    periodIds    // a uint48[] array of periodIds
    // A single periodId is defined as block.timestamp / limit.period if
    // limitType == Allowance, and 0 otherwise (which will be ignored).
    // periodIds[0] is for fee limit,
    // periodIds[1] is for value limit,
    // periodIds[2:] are for call constraints for the particular call being made, if there are any.
    // The contract will panic if periodIds.length < 2.
)
```

Additionally, since ERC-4337 supports keyed nonces, when using the `SessionKeyValidator`, nonce key has to be equal to `uint192(sessionSigner)` — the address of the session signer.

### `WebAuthnValidator` signature format

```solidity
abi.encode(
	authenticatorData,
	clientDataJSON,
	bytes32[2] rs,
	credentialId
)
```

---

Examples on how to encode all of the above in solidity and/or typescript can be found in the [test folder](https://github.com/matter-labs/zksync-sso-contracts/tree/main/test).
