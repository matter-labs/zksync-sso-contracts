import { fromArrayBuffer, toArrayBuffer } from "@hexagon/base64";
import { decodePartialCBOR } from "@levischuck/tiny-cbor";
import { ECDSASigValue } from "@peculiar/asn1-ecc";
import { AsnParser } from "@peculiar/asn1-schema";
import { bigintToBuf, bufToBigint } from "bigint-conversion";
import { encodeAbiParameters, hashMessage, Hex, hexToBytes, pad, toBytes, toHex } from "viem";
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
