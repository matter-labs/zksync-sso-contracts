import test from "node:test";
import assert from "node:assert/strict";
import { localhost } from "viem/chains";
import { createBundlerClient } from "viem/account-abstraction";
import { http, createPublicClient } from "viem";

import { SsoAccount } from "./account";
import { contractAddresses, toEoaSigner } from "./utils";

const anvilPort = 8545;
const altoPort = require("../../alto.json").port;
const anvilRpc = `http://localhost:${anvilPort}`;
const altoRpc = `http://localhost:${altoPort}`;
const privateKey = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";

test("executes a simple transfer signed using EOA", { timeout: 120_000 }, async () => {
    const { account } = contractAddresses();

    const client = createPublicClient({
        chain: localhost,
        transport: http(anvilRpc),
    });

    const bundlerClient = createBundlerClient({
        client,
        transport: http(altoRpc),
    });

    const sso = await SsoAccount.create(client, account, toEoaSigner(privateKey));

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
        "user operation should execute successfully",
    );
});
