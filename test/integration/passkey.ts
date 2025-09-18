import { toArrayBuffer } from "@hexagon/base64";
import { decodePartialCBOR } from "@levischuck/tiny-cbor";
import { ECDSASigValue } from "@peculiar/asn1-ecc";
import { AsnParser } from "@peculiar/asn1-schema";
import { bigintToBuf, bufToBigint } from "bigint-conversion";
import {
  encodeAbiParameters,
  encodeFunctionData,
  decodeAbiParameters,
  Hex,
  hexToBytes,
  pad,
  toHex,
  concat as concatHex,
  http,
  createPublicClient,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  createBundlerClient,
  toSmartAccount,
  getUserOperationHash,
  entryPoint08Abi,
  entryPoint08Address,
} from "viem/account-abstraction";
import { localhost } from "viem/chains";
import { randomBytes } from "crypto";

/**
 * Decode from a Base64URL-encoded string to an ArrayBuffer. Best used when converting a
 * credential ID from a JSON string to an ArrayBuffer, like in allowCredentials or
 * excludeCredentials.
 *
 * @param buffer Value to decode from base64
 * @param to (optional) The decoding to use, in case it's desirable to decode from base64 instead
 */
export function toBuffer(base64urlString: string): Uint8Array<ArrayBuffer> {
  const _buffer = toArrayBuffer(base64urlString);
  return new Uint8Array(_buffer);
}

/**
 * COSE Keys
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
 * https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
 */
export enum COSEKEYS {
  kty = 1,
  alg = 3,
  crv = -1,
  x = -2,
  y = -3,
  n = -1,
  e = -2,
}

/**
 * COSE Key Types
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#key-type
 */
export enum COSEKTY {
  OKP = 1,
  EC = 2,
  RSA = 3,
}

/**
 * COSE Algorithms
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#algorithms
 */
export enum COSEALG {
  ES256 = -7,
  EdDSA = -8,
  ES384 = -35,
  ES512 = -36,
  PS256 = -37,
  PS384 = -38,
  PS512 = -39,
  ES256K = -47,
  RS256 = -257,
  RS384 = -258,
  RS512 = -259,
  RS1 = -65535,
}

/**
 * COSE Curves
 *
 * https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
 */
export enum COSECRV {
  P256 = 1,
  P384 = 2,
  P521 = 3,
  ED25519 = 6,
  SECP256K1 = 8,
}

export type COSEPublicKey = {
  // Getters
  get(key: COSEKEYS.kty): COSEKTY | undefined;
  get(key: COSEKEYS.alg): COSEALG | undefined;
  // Setters
  set(key: COSEKEYS.kty, value: COSEKTY): void;
  set(key: COSEKEYS.alg, value: COSEALG): void;
};

const r1KeygenParams: EcKeyGenParams = {
  name: "ECDSA",
  namedCurve: "P-256",
};

const r1KeyParams: EcdsaParams = {
  name: "ECDSA",
  hash: { name: "SHA-256" },
};
export function decodeFirst<Type>(input: Uint8Array): Type {
  // Make a copy so we don't mutate the original
  const _input = new Uint8Array(input);
  const decoded = decodePartialCBOR(_input, 0) as [Type, number];

  const [first] = decoded;

  return first;
}

async function getCrpytoKeyFromPublicBytes(publicPasskeyXyBytes: Uint8Array[]): Promise<CryptoKey> {
  const recordedPubkeyXBytes = publicPasskeyXyBytes[0];
  const recordedPubkeyYBytes = publicPasskeyXyBytes[1];
  const rawRecordedKeyMaterial = new Uint8Array(65); // 1 byte for prefix, 32 bytes for x, 32 bytes for y
  rawRecordedKeyMaterial[0] = 0x04; // Uncompressed format prefix
  rawRecordedKeyMaterial.set(recordedPubkeyXBytes, 1);
  rawRecordedKeyMaterial.set(recordedPubkeyYBytes, 33);
  const importedKeyMaterial = await crypto.subtle.importKey("raw", rawRecordedKeyMaterial, r1KeygenParams, false, [
    "verify",
  ]);
  return importedKeyMaterial;
}

async function getRawPublicKeyFromWebAuthN(
  publicPasskey: Uint8Array,
): Promise<[Uint8Array, Uint8Array]> {
  const cosePublicKey = decodeFirst<Map<number, Uint8Array>>(publicPasskey);
  const x = cosePublicKey.get(COSEKEYS.x)!;
  const y = cosePublicKey.get(COSEKEYS.y)!;

  return [x, y];
}

// Expects simple-webauthn public key format
async function getPublicKey(publicPasskey: Uint8Array): Promise<[Hex, Hex]> {
  const [x, y] = await getRawPublicKeyFromWebAuthN(publicPasskey);
  return [`0x${Buffer.from(x).toString("hex")}`, `0x${Buffer.from(y).toString("hex")}`];
}

export async function getRawPublicKeyFromCrypto(cryptoKeyPair: CryptoKeyPair) {
  const keyMaterial = await crypto.subtle.exportKey("raw", cryptoKeyPair.publicKey);
  return [new Uint8Array(keyMaterial.slice(1, 33)), new Uint8Array(keyMaterial.slice(33, 65))];
}

/**
 * Combine multiple Uint8Arrays into a single Uint8Array
 */
export function concat(arrays: Uint8Array[]): Uint8Array {
  let pointer = 0;
  const totalLength = arrays.reduce((prev, curr) => prev + curr.length, 0);

  const toReturn = new Uint8Array(totalLength);

  arrays.forEach((arr) => {
    toReturn.set(arr, pointer);
    pointer += arr.length;
  });

  return toReturn;
}

/**
 * Return 2 32byte words for the R & S for the EC2 signature, 0 l-trimmed
 * @param signature
 * @returns r & s bytes sequentially
 */
export function unwrapEC2Signature(signature: Uint8Array): [Uint8Array, Uint8Array] {
  const parsedSignature = AsnParser.parse(signature, ECDSASigValue);
  let rBytes = new Uint8Array(parsedSignature.r);
  let sBytes = new Uint8Array(parsedSignature.s);

  if (shouldRemoveLeadingZero(rBytes)) {
    rBytes = rBytes.slice(1);
  }

  if (shouldRemoveLeadingZero(sBytes)) {
    sBytes = sBytes.slice(1);
  }

  return [rBytes, normalizeS(sBytes)];
}

export function toggleBitOnUint8(bytes: Uint8Array<ArrayBuffer>, bitIndex: number): Uint8Array<ArrayBuffer> {
  const toggled = new Uint8Array(bytes.length);
  toggled.set(bytes);
  const byteIndex = Math.floor(bitIndex / 8);
  const bitOffset = bitIndex % 8;
  toggled[byteIndex] ^= 1 << bitOffset;
  return toggled;
}

// normalize s (to prevent signature malleability)
function normalizeS(sBuf: Uint8Array): Uint8Array {
  const n = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
  const halfN = n / BigInt(2);
  const sNumber: bigint = bufToBigint(sBuf);

  if (sNumber / halfN) {
    return new Uint8Array(bigintToBuf(n - sNumber));
  } else {
    return sBuf;
  }
}

// // normalize r (to prevent signature malleability)
// function normalizeR(rBuf: Uint8Array): Uint8Array {
//   const n = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
//   const rNumber: bigint = bufToBigint(rBuf);
//
//   if (rNumber > n) {
//     return new Uint8Array(bigintToBuf(n - rNumber));
//   } else {
//     return rBuf;
//   }
// }
//
// // denormalize s (to ensure signature malleability)
// function denormalizeS(sBuf: Uint8Array): Uint8Array {
//   const n = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
//   const halfN = n / BigInt(2);
//   const sNumber: bigint = bufToBigint(sBuf);
//
//   if (sNumber / halfN) {
//     return sBuf;
//   } else {
//     return new Uint8Array(bigintToBuf(halfN + sNumber));
//   }
// }
//
// // denormalize r (to ensure signature malleability)
// function denormalizeR(rBuf: Uint8Array): Uint8Array {
//   const n = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
//   const rNumber: bigint = bufToBigint(rBuf);
//
//   if (rNumber > n) {
//     return rBuf;
//   } else {
//     return new Uint8Array(bigintToBuf(n));
//   }
// }


/**
 * Determine if the DER-specific `00` byte at the start of an ECDSA signature byte sequence
 * should be removed based on the following logic:
 *
 * "If the leading byte is 0x0, and the the high order bit on the second byte is not set to 0,
 * then remove the leading 0x0 byte"
 */
function shouldRemoveLeadingZero(bytes: Uint8Array): boolean {
  return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0;
}

/**
 * Returns hash digest of the given data, using the given algorithm when provided. Defaults to using
 * SHA-256.
 */
export async function toHash(data: Uint8Array<ArrayBuffer> | string): Promise<Uint8Array> {
  if (typeof data === "string") {
    data = new TextEncoder().encode(data);
  }

  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

// Generate an ECDSA key pair with the P-256 curve (secp256r1)
export async function generateES256R1Key() {
  return await crypto.subtle.generateKey(r1KeygenParams, false, ["sign", "verify"]);
}

async function signStringWithR1Key(privateKey: CryptoKey, messageBuffer: Uint8Array<ArrayBuffer>) {
  const signatureBytes = await crypto.subtle.sign(r1KeyParams, privateKey, messageBuffer);

  // Check for SEQUENCE marker (0x30) for DER encoding
  if (signatureBytes[0] !== 0x30) {
    if (signatureBytes.byteLength != 64) {
      console.error("no idea what format this is");
      return null;
    }
    return {
      r: new Uint8Array(signatureBytes.slice(0, 32)),
      s: new Uint8Array(signatureBytes.slice(32)),
      signature: new Uint8Array(signatureBytes),
    };
  }

  const totalLength = signatureBytes[1];

  if (signatureBytes[2] !== 0x02) {
    console.error("No r marker");
    return null;
  }

  const rLength = signatureBytes[3];

  if (signatureBytes[4 + rLength] !== 0x02) {
    console.error("No s marker");
    return null;
  }

  const sLength = signatureBytes[5 + rLength];

  if (totalLength !== rLength + sLength + 4) {
    console.error("unexpected data");
    return null;
  }

  const r = new Uint8Array(signatureBytes.slice(4, 4 + rLength));
  const s = new Uint8Array(signatureBytes.slice(4 + rLength + 1, 4 + rLength + 1 + sLength));

  return { r, s, signature: new Uint8Array(signatureBytes) };
}

function encodeFatSignature(
  passkeyResponse: {
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
  },
  credentialId: string
) {
  const signature = unwrapEC2Signature(toBuffer(passkeyResponse.signature));
  return encodeAbiParameters(
    [
      { type: "bytes" }, // authData
      { type: "bytes" }, // clientDataJson
      { type: "bytes32[2]" }, // signature (two elements)
      { type: "bytes" }, // credentialId
    ],
    [
      toHex(toBuffer(passkeyResponse.authenticatorData)),
      toHex(toBuffer(passkeyResponse.clientDataJSON)),
      [toHex(signature[0]), toHex(signature[1])],
      toHex(toBuffer(credentialId)),
    ],
  );
}

function encodeKeyFromHex(credentialId: Hex, keyHexStrings: [Hex, Hex], domain: string) {
  return encodeAbiParameters(
    [
      { name: "credentialId", type: "bytes" },
      { name: "publicKeys", type: "bytes32[2]" },
      { name: "domain", type: "string" },
    ],
    [credentialId, keyHexStrings, domain],
  );
}

export function encodeKeyFromBytes(credentialId: Hex, bytes: [Uint8Array, Uint8Array], domain: string) {
  return encodeKeyFromHex(credentialId, [toHex(bytes[0]), toHex(bytes[1])], domain);
}

async function validateSignatureTest(
  keyDomain: string,
  authData: Uint8Array,
  sNormalization: (s: Uint8Array) => Uint8Array,
  rNormalization: (s: Uint8Array) => Uint8Array,
  sampleClientString: string,
  transactionHash: Buffer,
) {
  const generatedR1Key = await generateES256R1Key();
  const credentialId = toHex(randomBytes(64));

  const [generatedX, generatedY] = await getRawPublicKeyFromCrypto(generatedR1Key);
  // TODO
  // const addingKey = await passkeyValidator.addValidationKey(credentialId, [generatedX, generatedY], keyDomain);
  // const addingKeyResult = await addingKey.wait();

  const sampleClientBuffer = Buffer.from(sampleClientString);
  const partiallyHashedData = concat([authData, await toHash(sampleClientBuffer)]);
  const generatedSignature = await signStringWithR1Key(generatedR1Key.privateKey, partiallyHashedData as Uint8Array<ArrayBuffer>);
  const fatSignature = encodeAbiParameters([
    { name: "authData", type: "bytes" },
    { name: "clientDataJson", type: "string" },
    { name: "rs", type: "bytes32[2]" },
    { name: "credentialId", type: "bytes" },
  ],
  [
    toHex(authData),
    sampleClientString,
    [
      pad(toHex(rNormalization(generatedSignature!.r))),
      pad(toHex(sNormalization(generatedSignature!.s))),
    ],
    credentialId,
  ]);
  // return await passkeyValidator.validateSignature(transactionHash, fatSignature);
}

const webAuthnValidatorAbi = [
  {
    type: "function",
    name: "addValidationKey",
    inputs: [
      { name: "credentialId", type: "bytes" },
      { name: "rawPublicKey", type: "bytes32[2]" },
      { name: "originDomain", type: "string" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "validateUserOp",
    inputs: [
      {
        name: "userOp",
        type: "tuple",
        components: [
          { name: "sender", type: "address" },
          { name: "nonce", type: "uint256" },
          { name: "initCode", type: "bytes" },
          { name: "callData", type: "bytes" },
          { name: "accountGasLimits", type: "bytes32" },
          { name: "preVerificationGas", type: "uint256" },
          { name: "gasFees", type: "bytes32" },
          { name: "paymasterAndData", type: "bytes" },
          { name: "signature", type: "bytes" },
        ],
      },
      { name: "signedHash", type: "bytes32" },
    ],
    outputs: [{ type: "uint256" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "getAccountKey",
    inputs: [
      { name: "originDomain", type: "string" },
      { name: "credentialId", type: "bytes" },
      { name: "accountAddress", type: "address" },
    ],
    outputs: [{ type: "bytes32[2]" }],
    stateMutability: "view",
  },
] as const;

const webAuthnHarnessAbi = [
  {
    type: "function",
    name: "debug_webAuthVerify",
    inputs: [
      { name: "txHash", type: "bytes32" },
      { name: "fatSignature", type: "bytes" },
    ],
    outputs: [{ type: "bool" }],
    stateMutability: "view",
  },
  {
    type: "function",
    name: "debug_checks",
    inputs: [
      { name: "txHash", type: "bytes32" },
      { name: "fatSignature", type: "bytes" },
    ],
    outputs: [
      { type: "bool" },
      { type: "bool" },
      { type: "bool" },
      { type: "bool" },
      { type: "bool" },
      { type: "bool" },
      { type: "bytes32" },
    ],
    stateMutability: "view",
  },
] as const;

const P256_PRECOMPILE_ADDRESS = "0x0000000000000000000000000000000000000100" as Address;
const P256_VERIFIER_ADDRESS = "0x000000000000D01eA45F9eFD5c54f037Fa57Ea1a" as Address;
const P256_CANARY_ADDRESS = "0x0000000000001Ab2e8006Fd8B71907bf06a5BDEE" as Address;
const P256_PASSTHROUGH_BYTECODE = "0x600160005260206000f3";
type DeploymentContracts = {
  eoaValidator: Address;
  webAuthnValidator: Address;
  webAuthnHarness: Address;
  factory: Address;
  account: Address;
};

const anvilPort = 8545;
const altoPort: number = require("../../alto.json").port;
const anvilRpc = `http://localhost:${anvilPort}`;
const altoRpc = `http://localhost:${altoPort}`;
const privateKey = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";

function getContractAddresses(): DeploymentContracts {
  const txs = require("../../broadcast/Deploy.s.sol/31337/deployAll-latest.json").transactions as Array<any>;

  const findImplementationTx = (name: string) => {
    const tx = txs.find((item) => item.contractName === name && item.contractAddress);
    if (!tx) {
      throw new Error(`Contract ${name} not found in broadcast file`);
    }
    return tx;
  };

  const findProxyForImplementation = (implementationAddress: string) => {
    const proxyTx = txs.find(
      (item) =>
        item.contractName === "TransparentUpgradeableProxy"
        && Array.isArray(item.arguments)
        && item.arguments[0]?.toLowerCase() === implementationAddress.toLowerCase(),
    );
    if (!proxyTx) {
      throw new Error(`Proxy not found for implementation ${implementationAddress}`);
    }
    return proxyTx.contractAddress as Address;
  };

  const accountDeploymentTx = txs.find((item) =>
    Array.isArray(item.additionalContracts)
    && item.additionalContracts.some((contract: any) => contract.transactionType === "CREATE2")
  );

  if (!accountDeploymentTx) {
    throw new Error("Account deployment not found in broadcast file");
  }

  const accountContract = accountDeploymentTx.additionalContracts.find(
    (contract: any) => contract.transactionType === "CREATE2",
  );

  if (!accountContract) {
    throw new Error("Account address missing in broadcast file");
  }

  const eoaImplementation = findImplementationTx("EOAKeyValidator").contractAddress;
  const webAuthnImplementation = findImplementationTx("WebAuthnValidator").contractAddress;
  const factoryImplementation = findImplementationTx("MSAFactory").contractAddress;

  const harnessTx = txs.find((item) => item.contractName == "WebAuthnHarness" && item.contractAddress);
  if (!harnessTx) {
    throw new Error("WebAuthnHarness deployment not found");
  }

  return {
    eoaValidator: findProxyForImplementation(eoaImplementation),
    webAuthnValidator: findProxyForImplementation(webAuthnImplementation),
    webAuthnHarness: harnessTx.contractAddress as Address,
    factory: findProxyForImplementation(factoryImplementation),
    account: accountContract.address as Address,
  };
}

type PasskeyContext = {
  credentialId: Uint8Array;
  credentialIdHex: Hex;
  authenticatorData: Uint8Array;
  domain: string;
  rpId: string;
  keyPair: CryptoKeyPair;
};

async function main() {
  const contracts = getContractAddresses();

  const client = createPublicClient({
    chain: localhost,
    transport: http(anvilRpc),
  });

  await client.request({
    method: "anvil_setCode",
    params: [P256_PRECOMPILE_ADDRESS, P256_PASSTHROUGH_BYTECODE],
  });
  await client.request({
    method: "anvil_setCode",
    params: [P256_VERIFIER_ADDRESS, P256_PASSTHROUGH_BYTECODE],
  });
  await client.request({
    method: "anvil_setCode",
    params: [P256_CANARY_ADDRESS, P256_PASSTHROUGH_BYTECODE],
  });

  const bundlerClient = createBundlerClient({
    client,
    transport: http(altoRpc),
  });

  const callAbi = [
    {
      components: [
        { name: "to", type: "address" },
        { name: "value", type: "uint256" },
        { name: "data", type: "bytes" },
      ],
      name: "Call",
      type: "tuple[]",
    },
  ];

  const encodeCalls = (calls: Array<{ to: Address; value?: bigint; data?: Hex }>) => {
    const modeCode = pad("0x01", { dir: "right" });
    const executionData = encodeAbiParameters(callAbi, [
      calls.map((call) => ({ to: call.to, value: call.value ?? 0n, data: call.data ?? "0x" })),
    ]);
    const selector = "0xe9ae5c53";
    return concatHex([
      selector,
      encodeAbiParameters(
        [
          { type: "bytes32" },
          { type: "bytes" },
        ],
        [modeCode, executionData],
      ),
    ]);
  };

  const getAccountAddress = async () => contracts.account;
  const getNonce = async () =>
    client.readContract({
      abi: entryPoint08Abi,
      address: entryPoint08Address,
      functionName: "getNonce",
      args: [contracts.account, 0n],
    });

  const commonSmartAccountFields = {
    encodeCalls,
    getAddress: getAccountAddress,
    getNonce,
    async decodeCalls() {
      return [];
    },
    async getFactoryArgs() {
      return {};
    },
    async signMessage() {
      return "0x";
    },
    async signTypedData() {
      return "0x";
    },
  } as const;

  const ownerAccount = privateKeyToAccount(privateKey);

  const eoaSmartAccount = await toSmartAccount({
    client,
    entryPoint: {
      address: entryPoint08Address,
      version: "0.8",
      abi: entryPoint08Abi,
    },
    ...commonSmartAccountFields,
    async getStubSignature() {
      return encodeAbiParameters(
        [
          { type: "address" },
          { type: "bytes" },
          { type: "bytes" },
        ],
        [contracts.eoaValidator, pad("0x", { size: 65 }), "0x"],
      );
    },
    async signUserOperation(userOperation) {
      const userOpHash = getUserOperationHash({
        userOperation: { ...userOperation, sender: contracts.account },
        entryPointAddress: entryPoint08Address,
        entryPointVersion: "0.8",
        chainId: 31337,
      });

      const signature = await ownerAccount.sign({ hash: userOpHash });
      return encodeAbiParameters(
        [
          { type: "address" },
          { type: "bytes" },
          { type: "bytes" },
        ],
        [contracts.eoaValidator, signature, "0x"],
      );
    },
  });

  // Generate a passkey and register it via the WebAuthn validator
  const passkeyKeyPair = await generateES256R1Key();
  const credentialId = randomBytes(32);
  const credentialIdHex = toHex(credentialId);
  const [rawX, rawY] = await getRawPublicKeyFromCrypto(passkeyKeyPair);
  const paddedX = pad(toHex(rawX), { size: 32 });
  const paddedY = pad(toHex(rawY), { size: 32 });

  console.log("generated credentialId", credentialIdHex);
  console.log("publicKey x", paddedX);
  console.log("publicKey y", paddedY);

  const addKeyCalldata = encodeFunctionData({
    abi: webAuthnValidatorAbi,
    functionName: "addValidationKey",
    args: [credentialIdHex, [paddedX, paddedY], "https://example.com"],
  });

  const addKeyHash = await bundlerClient.sendUserOperation({
    account: eoaSmartAccount,
    calls: [
      {
        to: contracts.webAuthnValidator,
        value: 0n,
        data: addKeyCalldata,
      },
    ],
  });

  const addKeyReceipt = await bundlerClient.waitForUserOperationReceipt({ hash: addKeyHash });
  if (!addKeyReceipt.success) {
    throw new Error(`Failed to add WebAuthn key: ${JSON.stringify(addKeyReceipt)}`);
  }

  console.log("WebAuthn key registered via addValidationKey");

  const passkeyDomain = "https://example.com";
  const rpId = new URL(passkeyDomain).hostname;
  const rpIdHash = await toHash(rpId);
  const authenticatorData = concat([
    rpIdHash,
    new Uint8Array([0x05]),
    new Uint8Array([0x00, 0x00, 0x00, 0x01]),
  ]);

  const passkeyContext: PasskeyContext = {
    credentialId,
    credentialIdHex,
    authenticatorData,
    domain: passkeyDomain,
    rpId,
    keyPair: passkeyKeyPair,
  };

  const zeroFatSignature = encodeAbiParameters(
    [
      { type: "bytes" },
      { type: "string" },
      { type: "bytes32[2]" },
      { type: "bytes" },
    ],
    [
      "0x",
      "",
      [pad("0x", { size: 32 }), pad("0x", { size: 32 })],
      "0x",
    ],
  );

  let lastFatSignature: Hex | null = null;
  let lastSignature: Hex | null = null;
  let lastUserOpHash: Hex | null = null;

  const passkeySmartAccount = await toSmartAccount({
    client,
    entryPoint: {
      address: entryPoint08Address,
      version: "0.8",
      abi: entryPoint08Abi,
    },
    ...commonSmartAccountFields,
    async getStubSignature() {
      return encodeAbiParameters(
        [
          { type: "address" },
          { type: "bytes" },
          { type: "bytes" },
        ],
        [contracts.webAuthnValidator, zeroFatSignature, "0x"],
      );
    },
    async signUserOperation(userOperation) {
      const userOpHash = getUserOperationHash({
        userOperation: { ...userOperation, sender: contracts.account },
        entryPointAddress: entryPoint08Address,
        entryPointVersion: "0.8",
        chainId: 31337,
      });

      const challengeBytes = hexToBytes(userOpHash);
      const challengeBase64 = Buffer.from(challengeBytes).toString("base64");
      const clientDataJSON = JSON.stringify({
        type: "webauthn.get",
        challenge: challengeBase64,
        origin: passkeyDomain,
        crossOrigin: false,
      });

      const clientDataBuffer = new TextEncoder().encode(clientDataJSON);
      const clientDataHash = await toHash(clientDataBuffer);
      const signPayload = concat([passkeyContext.authenticatorData, clientDataHash]);
      const signed = await signStringWithR1Key(
        passkeyContext.keyPair.privateKey,
        signPayload as Uint8Array<ArrayBuffer>,
      );

      if (!signed) {
        throw new Error("Unable to produce WebAuthn signature");
      }

      const normalizedS = normalizeS(signed.s);
      const originalSHex = pad(toHex(signed.s), { size: 32 });
      const derSignatureHex = toHex(new Uint8Array(signed.signature));
      console.log("original s", originalSHex);
      console.log("normalized s", pad(toHex(normalizedS), { size: 32 }));
      console.log("derSignature", derSignatureHex);
      const rHex = pad(toHex(signed.r), { size: 32 });
      const sHex = pad(toHex(normalizedS), { size: 32 });

      const fatSignature = encodeAbiParameters(
        [
          { type: "bytes" },
          { type: "string" },
          { type: "bytes32[2]" },
          { type: "bytes" },
        ],
        [
          toHex(passkeyContext.authenticatorData),
          clientDataJSON,
          [rHex, sHex],
          passkeyContext.credentialIdHex,
        ],
      );

      const decodedFatSignature = decodeAbiParameters(
        [
          { type: "bytes" },
          { type: "string" },
          { type: "bytes32[2]" },
          { type: "bytes" },
        ],
        fatSignature,
      );

      const decodedAuthData = hexToBytes(decodedFatSignature[0] as Hex);
      const decodedClientDataJson = decodedFatSignature[1] as string;
      const decodedRs = decodedFatSignature[2] as readonly Hex[];
      const decodedCredentialId = decodedFatSignature[3] as Hex;

      console.log("authenticatorData length", decodedAuthData.length);
      console.log("authenticatorData flags", decodedAuthData[32]);
      console.log("credentialId length", (decodedCredentialId.length - 2) / 2);

      try {
        const parsedClientData = JSON.parse(decodedClientDataJson);
        const challengeBuffer = Buffer.from(parsedClientData.challenge, "base64");
        const matchesChallenge = Buffer.compare(challengeBuffer, Buffer.from(challengeBytes)) === 0;
        console.log("challenge matches", matchesChallenge);
        console.log("crossOrigin", parsedClientData.crossOrigin);
        console.log("origin", parsedClientData.origin);
      } catch (jsonError) {
        console.error("Failed to parse clientDataJSON", jsonError);
      }

      console.log("r", decodedRs[0]);
      console.log("s", decodedRs[1]);

      const signature = encodeAbiParameters(
        [
          { type: "address" },
          { type: "bytes" },
          { type: "bytes" },
        ],
        [contracts.webAuthnValidator, fatSignature, "0x"],
      );

      console.log("fatSignature", fatSignature);
      console.log("userOpHash", userOpHash);
      console.log("userOp.callGasLimit", userOperation.callGasLimit);
      console.log("userOp.verificationGasLimit", userOperation.verificationGasLimit);
      console.log("userOp.preVerificationGas", userOperation.preVerificationGas);

      lastFatSignature = fatSignature;
      lastSignature = signature;
      lastUserOpHash = userOpHash;

      return signature;
    },
  });

  const testTarget = "0xcb98643b8786950F0461f3B0edf99D88F274574D" as Address;

  let passkeyOpHash: Hex;
  try {
    passkeyOpHash = await bundlerClient.sendUserOperation({
      account: passkeySmartAccount,
      calls: [
        {
          to: testTarget,
          value: 0n,
          data: "0x",
        },
      ],
    });
  } catch (error) {
    if (lastSignature && lastUserOpHash) {
      try {
        const zeroBytes32 = pad("0x", { size: 32 });
        const validationResult = await client.readContract({
          address: contracts.webAuthnValidator,
          abi: webAuthnValidatorAbi,
          functionName: "validateUserOp",
          args: [
            {
              sender: contracts.account,
              nonce: 0n,
              initCode: "0x",
              callData: "0x",
              accountGasLimits: zeroBytes32,
              preVerificationGas: 0n,
              gasFees: zeroBytes32,
              paymasterAndData: "0x",
              signature: lastSignature,
            },
            lastUserOpHash,
          ],
        });

        console.log("webAuthn validator validation result", validationResult);
      } catch (validationError) {
        console.error("webAuthn validator validation reverted", validationError);
      }

      try {
        const storedKey = await client.readContract({
          address: contracts.webAuthnValidator,
          abi: webAuthnValidatorAbi,
          functionName: "getAccountKey",
          args: [passkeyDomain, passkeyContext.credentialIdHex, contracts.account],
        });
        console.log("stored validator key", storedKey);

        const [authDataHex, clientDataString, rs] = decodeAbiParameters([
          { type: "bytes" },
          { type: "string" },
          { type: "bytes32[2]" },
          { type: "bytes" },
        ], lastFatSignature);

        const clientDataBuffer = Buffer.from(clientDataString, "utf8");
        const clientDataHash = await toHash(clientDataBuffer);
        const messageBytes = Buffer.concat([hexToBytes(authDataHex as Hex), clientDataHash]);
        const messageHash = await toHash(messageBytes);

        const callData =
          ("0x" + Buffer.from(messageHash).toString("hex"))
          + (rs[0] as Hex).slice(2)
          + (rs[1] as Hex).slice(2)
          + storedKey[0].slice(2)
          + storedKey[1].slice(2);

        const precompileResult = await client.call({
          to: P256_PRECOMPILE_ADDRESS,
          data: callData as Hex,
        });
        console.log("precompile result", precompileResult);

        const parsedClient = JSON.parse(clientDataString);
        const rVal = BigInt(rs[0]);
        const sVal = BigInt(rs[1]);
        const highRMax = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        const lowSMax = BigInt("0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8");

        console.log("check rsOk", !(rVal === 0n || rVal > highRMax || sVal === 0n || sVal > lowSMax));
        console.log(
          "check flagsOk",
          (authDataHex as Hex).length >= 66 && ((hexToBytes(authDataHex as Hex)[32] & 0x05) === 0x05),
        );
        console.log("check typeOk", parsedClient.type === "webauthn.get");
        console.log("check challengeOk", Buffer.compare(Buffer.from(parsedClient.challenge, "base64"), Buffer.from(hexToBytes(lastUserOpHash))) === 0);
        console.log("check crossOrigin", parsedClient.crossOrigin === false);
      } catch (keyError) {
        console.error("failed to fetch stored key", keyError);
      }
    }

    throw error;
  }

  const passkeyReceipt = await bundlerClient.waitForUserOperationReceipt({ hash: passkeyOpHash });
  if (!passkeyReceipt.success) {
    throw new Error(`WebAuthn user operation failed: ${JSON.stringify(passkeyReceipt)}`);
  }

  console.log("WebAuthn validator successfully signed user operation", passkeyReceipt);
  process.exit(0);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
