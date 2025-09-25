import test from "node:test";
import assert from "node:assert/strict";
import crypto from "crypto";
import type { Address } from "viem";

import { SsoAccount } from "./account";
import { contractAddresses, toEOASigner, createClients } from "./utils";

const anvilPort = 8545;
const altoPort = require("../../alto.json").port;
const privateKey = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";

test("executes a simple transfer signed using EOA", { timeout: 120_000 }, async () => {
    const { account } = contractAddresses();
    const { client, bundlerClient } = createClients(anvilPort, altoPort);
    const sso = await SsoAccount.create(client, account, toEOASigner(privateKey));

    const target: Address = `0x${crypto.randomBytes(20).toString("hex")}`;
    const hash = await bundlerClient.sendUserOperation({
        account: sso.account,
        calls: [{
            to: target,
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

    const balance = await client.getBalance({ address: target });
    assert.equal(balance, 1n, "target should receive 1 wei");
});

test("checks ERC779 signature via ERC1271", { timeout: 120_000 }, async () => {

});
