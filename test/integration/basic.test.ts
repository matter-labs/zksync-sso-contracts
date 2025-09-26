import test from "node:test";
import assert from "node:assert/strict";
import { parseAbi } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { SsoAccount } from "./account";
import { contractAddresses, toEOASigner, createClients, randomAddress, deployContract } from "./utils";

const anvilPort = 8545;
const altoPort = require("../../alto.json").port;
const privateKey = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";

test("executes a simple transfer signed using EOA", { timeout: 120_000 }, async () => {
    const { account } = contractAddresses();
    const { client, bundlerClient } = createClients(anvilPort, altoPort);
    const sso = await SsoAccount.create(client, account, toEOASigner(privateKey));

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
        "user operation should execute successfully",
    );

    const balance = await client.getBalance({ address: target });
    assert.equal(balance, 1n, "target should receive 1 wei");
});

test("executes a transaction sponsored by a paymaster", { timeout: 120_000 }, async () => {
    const { account } = contractAddresses();
    const { client, bundlerClient } = createClients(anvilPort, altoPort);
    const sso = await SsoAccount.create(client, account, toEOASigner(privateKey));
    const deployer = privateKeyToAccount(privateKey);
    const paymaster = await deployContract(client, privateKey, "MockPaymaster");
    const depositHash = await client.writeContract({
        account: deployer,
        address: paymaster,
        abi: parseAbi(["function deposit() external payable"]),
        functionName: "deposit",
        args: [],
        value: 10n ** 18n, // 1 ETH
    })
    await client.waitForTransactionReceipt({ hash: depositHash, timeout: 0 });

    const balanceBefore = await client.getBalance({ address: account });
    const sponsored = await bundlerClient.sendUserOperation({
        account: sso.account,
        calls: [{ to: randomAddress() }],
        paymaster,
    });

    const receipt = await bundlerClient.waitForUserOperationReceipt({ hash: sponsored, timeout: 0 });
    const balanceAfter = await client.getBalance({ address: account });

    assert.equal(receipt.receipt.status, "success", "sponsored user operation should execute successfully");
    assert.equal(balanceAfter, balanceBefore, "account balance should not change");
});

test("checks ERC7739 EOA signature using ERC1271", { timeout: 120_000 }, async () => {
    const { account } = contractAddresses();
    const { client } = createClients(anvilPort, altoPort);
    const sso = await SsoAccount.create(client, account, toEOASigner(privateKey));

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
            chainId: 1337,
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
        args: [mockMessage, sso.account.address, signature]
    });

    assert.equal(isValid, true, "signature should be valid");
});
