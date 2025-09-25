import test from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import { encodeFunctionData, toHex, parseAbi } from "viem";

import { SsoAccount } from "./account";
import { contractAddresses, toEOASigner, toPasskeySigner, createClients } from "./utils";

const anvilPort = 8545;
const altoPort = require("../../alto.json").port;
const privateKey = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";

test("executes a simple transfer signed using Passkey", { timeout: 120_000 }, async () => {
    const keyPair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = keyPair.publicKey.export({ format: "jwk" });
    const publicKey = {
        x: toHex(Buffer.from(jwk.x!, "base64url")),
        y: toHex(Buffer.from(jwk.y!, "base64url")),
    };

    const { account, webauthnValidator } = contractAddresses();
    const { client, bundlerClient } = createClients(anvilPort, altoPort);
    const sso = await SsoAccount.create(client, account, toEOASigner(privateKey));
    const credentialId = toHex(crypto.randomBytes(16));

    // add validation key via the passkey validator contract
    const addValidationKeyHash = await bundlerClient.sendUserOperation({
        account: sso.account,
        calls: [{
            to: webauthnValidator,
            value: 0n,
            data: encodeFunctionData({
                abi: parseAbi(["function addValidationKey(bytes memory credentialId, bytes32[2] memory newKey, string memory originDomain) public"]),
                args: [credentialId, [publicKey.x, publicKey.y], "https://example.com"],
            }),
        }],
    });

    const addValidationKeyReceipt = await bundlerClient.waitForUserOperationReceipt({
        hash: addValidationKeyHash,
        timeout: 0,
    });

    assert.equal(
        addValidationKeyReceipt.receipt.status,
        "success",
        "adding a validation key should succeed",
    );

    // hot-swap signing function
    sso.signer = toPasskeySigner(keyPair.privateKey, credentialId);

    // transfer to a random address using passkey signer
    const hash = await bundlerClient.sendUserOperation({
        account: sso.account,
        calls: [{
            to: "0xcb98643b8786950F0461f3B0edf99D88F274574D",
            value: 1n
        }],
    });

    const receipt = await bundlerClient.waitForUserOperationReceipt({
        hash,
        timeout: 0,
    });

    assert.equal(
        receipt.receipt.status,
        "success",
        "user operation with passkey signer should succeed",
    );
});
