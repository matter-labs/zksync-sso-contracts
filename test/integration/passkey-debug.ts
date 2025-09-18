import {
  encodeAbiParameters,
  decodeAbiParameters,
  Hex,
  hexToBytes,
  toHex,
  pad,
  http,
  createPublicClient,
  type Address,
} from "viem";
import { localhost } from "viem/chains";
import {
  generateES256R1Key,
  getRawPublicKeyFromCrypto,
  toggleBitOnUint8,
  unwrapEC2Signature,
  toHash,
} from "./passkey";
import { randomBytes } from "crypto";

const P256_PRECOMPILE_ADDRESS = "0x0000000000000000000000000000000000000100" as Address;
const P256_VERIFIER_ADDRESS = "0x000000000000D01eA45F9eFD5c54f037Fa57Ea1a" as Address;
const P256_CANARY_ADDRESS = "0x0000000000001Ab2e8006Fd8B71907bf06a5BDEE" as Address;
const P256_PASSTHROUGH_BYTECODE = "0x600160005260206000f3";

async function setupP256(client = createPublicClient({ chain: localhost, transport: http("http://localhost:8545") })) {
  await client.request({ method: "anvil_setCode", params: [P256_PRECOMPILE_ADDRESS, P256_PASSTHROUGH_BYTECODE] });
  await client.request({ method: "anvil_setCode", params: [P256_VERIFIER_ADDRESS, P256_PASSTHROUGH_BYTECODE] });
  await client.request({ method: "anvil_setCode", params: [P256_CANARY_ADDRESS, P256_PASSTHROUGH_BYTECODE] });
  return client;
}

async function debugWebAuthn() {
  const client = await setupP256();

  const keyPair = await generateES256R1Key();
  const credentialId = randomBytes(32);
  const [rawX, rawY] = await getRawPublicKeyFromCrypto(keyPair);
  const paddedX = pad(toHex(rawX), { size: 32 });
  const paddedY = pad(toHex(rawY), { size: 32 });

  console.log("x", paddedX);
  console.log("y", paddedY);

  const authenticatorData = Buffer.concat([
    await toHash("example.com"),
    Buffer.from([0x05]),
    Buffer.alloc(4),
  ]);
  const passkeyDomain = "https://example.com";
  const userOpHash = toHex(randomBytes(32));
  const challengeBase64 = Buffer.from(hexToBytes(userOpHash)).toString("base64");
  const clientDataJSON = JSON.stringify({
    type: "webauthn.get",
    challenge: challengeBase64,
    origin: passkeyDomain,
    crossOrigin: false,
  });

  const clientDataBuffer = Buffer.from(clientDataJSON, "utf8");
  const clientDataHash = await toHash(clientDataBuffer);
  const signPayload = Buffer.concat([authenticatorData, Buffer.from(clientDataHash)]);

  const signatureBytes = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: { name: "SHA-256" } }, keyPair.privateKey, signPayload),
  );
  let [rBytes, sBytes] = unwrapEC2Signature(signatureBytes);
  rBytes = toggleBitOnUint8(rBytes, 0);
  const rHex = pad(toHex(rBytes), { size: 32 });
  const sHex = pad(toHex(sBytes), { size: 32 });

  const fatSignature = encodeAbiParameters(
    [{ type: "bytes" }, { type: "string" }, { type: "bytes32[2]" }, { type: "bytes" }],
    [toHex(authenticatorData), clientDataJSON, [rHex, sHex], toHex(credentialId)],
  );

  const decoded = decodeAbiParameters(
    [{ type: "bytes" }, { type: "string" }, { type: "bytes32[2]" }, { type: "bytes" }],
    fatSignature,
  );

  console.log("decoded", decoded);

  await client.request({
    method: "eth_call",
    params: [{
      to: P256_PRECOMPILE_ADDRESS,
      data: userOpHash + rHex.slice(2) + sHex.slice(2) + paddedX.slice(2) + paddedY.slice(2),
    }, "latest"],
  }).then((result) => {
    console.log("eth_call result", result);
  });
}

debugWebAuthn().catch((error) => {
  console.error(error);
  process.exit(1);
});
