# Signature Formats

## `isValidSignature` Signature Format

```solidity
abi.encodePacked(
	validatorAddress,  // address of the validator that would check the signature
	erc7739Signature   // signature, formatted according to https://eips.ethereum.org/EIPS/eip-7739
)
```

## `validateUserOp` Signature Format

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

## `EOAKeyValidator` Signature Format

```solidity
abi.encodePacked(r, s, v) // your standard 65-byte ECDSA signature
```

## `SessionKeyValidator` Signature Format

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

## `WebAuthnValidator` Signature Format

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
