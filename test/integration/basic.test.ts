import { localhost } from "viem/chains"
import { createBundlerClient } from 'viem/account-abstraction'
import { http, createPublicClient } from 'viem'

import { SsoAccount } from './account';
import { contractAddresses, toEoaSigner } from './utils';

const anvilPort = 8545
const altoPort = require("../../alto.json").port
const anvilRpc = `http://localhost:${anvilPort}`
const altoRpc = `http://localhost:${altoPort}`
const privateKey = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";

(async () => {

    const { account } = contractAddresses()

    const client = createPublicClient({
        chain: localhost,
        transport: http(anvilRpc),
    })

    const bundlerClient = createBundlerClient({
        client,
        transport: http(altoRpc)
    })

    const sso = await SsoAccount.create(client, account, toEoaSigner(privateKey));

    // zero transfer to a random address
    const hash = await bundlerClient.sendUserOperation({
        account: sso.account,
        calls: [{ to: '0xcb98643b8786950F0461f3B0edf99D88F274574D' }]
    })

    const receipt = await bundlerClient.waitForUserOperationReceipt({ hash });
    console.log(receipt.receipt.status);

    process.exit(0)
})()
