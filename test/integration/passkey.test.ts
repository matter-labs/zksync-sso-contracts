import test from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import { encodeFunctionData, toHex, parseAbi } from "viem";

import { SsoAccount } from "./account";
import { contractAddresses, toEOASigner, toPasskeySigner, createClients, randomAddress, deployContract } from "./utils";

const anvilPort = process.env.PORT ?? 8545;
const altoPort = require("../../alto.json").port;
const privateKey = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";

const credentialId = toHex(crypto.randomBytes(16));
const keyPair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const jwk = keyPair.publicKey.export({ format: "jwk" });
const publicKey = {
    x: toHex(Buffer.from(jwk.x!, "base64url")),
    y: toHex(Buffer.from(jwk.y!, "base64url")),
};

test("adds a Passkey to the account", { timeout: 120_000 }, async () => {
    const { account, webauthnValidator } = contractAddresses();
    const { client, bundlerClient } = createClients(anvilPort, altoPort);
    const sso = await SsoAccount.create(client, account, toEOASigner(privateKey));

    // add validation key via the passkey validator contract
    const hash = await bundlerClient.sendUserOperation({
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

    const receipt = await bundlerClient.waitForUserOperationReceipt({ hash, timeout: 0 });
    assert.equal(
        receipt.receipt.status,
        "success",
        "adding a validation key should succeed",
    );
});

test("executes a simple transfer signed using Passkey", { timeout: 120_000 }, async () => {
    const { account } = contractAddresses();
    const { client, bundlerClient } = createClients(anvilPort, altoPort);
    const sso = await SsoAccount.create(client, account, toPasskeySigner(keyPair.privateKey, credentialId));

    // transfer to a random address using passkey signer
    const target = randomAddress();
    const hash = await bundlerClient.sendUserOperation({
        account: sso.account,
        calls: [{
            to: target,
            value: 1n
        }],
    });

    const receipt = await bundlerClient.waitForUserOperationReceipt({ hash, timeout: 0 });
    assert.equal(
        receipt.receipt.status,
        "success",
        "user operation with passkey signer should succeed",
    );

    const balance = await client.getBalance({ address: target });
    assert.equal(balance, 1n, "target should receive 1 wei");
});

test("checks ERC7739 Passkey signature using ERC1271", { timeout: 120_000 }, async () => {
    const { account } = contractAddresses();
    const { client } = createClients(anvilPort, altoPort);
    const sso = await SsoAccount.create(client, account, toPasskeySigner(keyPair.privateKey, credentialId));

    const erc1271Caller = await deployContract(client, privateKey, "MockERC1271Caller");
    const mockMessage = {
        message: "hello",
        value: 18n
    };

    const signature = await sso.account.signTypedData({
        types: {
            MockMessage: [
                { name: "message", type: "string" },
                { name: "value", type: "uint256" }
            ]
        },
        domain: {
            chainId: process.env.CHAIN_ID ?? 1337,
            name: "ERC1271Caller",
            version: "1.0.0",
            verifyingContract: erc1271Caller,
        },
        primaryType: "MockMessage",
        message: mockMessage
    });

    const isValid = await client.readContract({
        address: erc1271Caller,
        abi: parseAbi([
            "struct MockMessage { string message; uint256 value; }",
            "function validateStruct(MockMessage calldata, address, bytes calldata) public view returns (bool)"
        ]),
        functionName: "validateStruct",
        args: [mockMessage, account, signature]
    });

    assert.equal(isValid, true, "signature should be valid");
});
