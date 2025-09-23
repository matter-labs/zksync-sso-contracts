import {
  encodeFunctionData,
  toHex,
  http,
  createPublicClient,
  parseAbi,
} from "viem";

import { createBundlerClient, } from "viem/account-abstraction";
import { localhost } from "viem/chains";
import crypto from "crypto";

import { SsoAccount } from "./account";
import { contractAddresses, toEoaSigner, toPasskeySigner } from "./utils";

const anvilPort = 8545;
const altoPort = require("../../alto.json").port;
const anvilRpc = `http://localhost:${anvilPort}`;
const altoRpc = `http://localhost:${altoPort}`;
const privateKey = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";

(async () => {
    const { account, webauthnValidator } = contractAddresses();

    const keyPair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = keyPair.publicKey.export({ format: "jwk" }) as JsonWebKey;
    const publicKey = {
        x: toHex(Buffer.from(jwk.x!, "base64url")),
        y: toHex(Buffer.from(jwk.y!, "base64url")),
    }

    const client = createPublicClient({
        chain: localhost,
        transport: http(anvilRpc),
    })

    const bundlerClient = createBundlerClient({
        client,
        transport: http(altoRpc)
    })

    const sso = await SsoAccount.create(client, account, toEoaSigner(privateKey));
    const credentialId = toHex(crypto.randomBytes(16));

    // add validation key
    const addValidationKey = await bundlerClient.sendUserOperation({
        account: sso.account,
        calls: [{
            to: webauthnValidator,
            value: 0n,
            data: encodeFunctionData({
                abi: parseAbi(["function addValidationKey(bytes memory credentialId, bytes32[2] memory newKey, string memory originDomain) public"]),
                args: [credentialId, [publicKey.x, publicKey.y], "https://example.com"]
            })
        }],
    });

    let receipt = await bundlerClient.waitForUserOperationReceipt({ hash: addValidationKey });
    console.log(receipt.receipt.status);

    // hot-swap signing function
    sso.signer = toPasskeySigner(keyPair.privateKey, credentialId);

    // zero transfer to a random address using passkey signer
    const hash = await bundlerClient.sendUserOperation({
        account: sso.account,
        calls: [{ to: '0xcb98643b8786950F0461f3B0edf99D88F274574D' }],
    })

    receipt = await bundlerClient.waitForUserOperationReceipt({ hash });
    console.log(receipt.receipt.status);

    process.exit(0)
})()
