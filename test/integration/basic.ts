import { privateKeyToAccount } from 'viem/accounts';
import { localhost } from "viem/chains"
import { createBundlerClient, toSmartAccount, getUserOperationHash, entryPoint08Abi, entryPoint08Address } from 'viem/account-abstraction'
import { encodeAbiParameters, pad, concat, type Address, http, createPublicClient } from 'viem'
import { writeFileSync } from 'fs'
import path from 'path'

const anvilPort = 8545
const altoPort = require("../../alto.json").port
const anvilRpc = `http://localhost:${anvilPort}`
const altoRpc = `http://localhost:${altoPort}`
const privateKey = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"

function getContractAddresses() {
    const txs = require('../../broadcast/Deploy.s.sol/31337/deployAll-latest.json').transactions;
    return {
        eoaValidator: txs[1].contractAddress as Address,
        factory: txs[txs.length - 3].contractAddress as Address,
        account: txs[txs.length - 2].additionalContracts[0].address as Address
    }
}

(async () => {
    const contracts = getContractAddresses();
    console.log(contracts)

    const client = createPublicClient({
        chain: localhost,
        transport: http(anvilRpc),
    })

    const bundlerClient = createBundlerClient({
        client,
        transport: http(altoRpc)
    })

    const callAbi = [{
        components: [
            {
                name: 'to',
                type: 'address',
            },
            {
                name: 'value',
                type: 'uint256',
            },
            {
                name: 'data',
                type: 'bytes',
            },
        ],
        name: 'Call',
        type: 'tuple[]',
    }];

    const account = await toSmartAccount({
        client,
        entryPoint: {
            address: entryPoint08Address,
            version: '0.8',
            abi: entryPoint08Abi
        },
        async encodeCalls(calls) {
            const modeCode = pad('0x01', { dir: 'right' }); // simple batch execute
            const executionData = encodeAbiParameters(callAbi, [calls.map(call => ({ to: call.to, value: call.value ?? 0n, data: call.data ?? '0x' }))])
            const selector = '0xe9ae5c53'; // execute(bytes32,bytes)
            return concat([selector, encodeAbiParameters([{ type: 'bytes32' }, { type: 'bytes' }], [modeCode, executionData])])
        },
        async getAddress() {
            return contracts.account
        },
        async getNonce() {
            return await client.readContract({ abi: entryPoint08Abi, address: entryPoint08Address, functionName: 'getNonce', args: [contracts.account, 0n] })
        },
        async getStubSignature() {
            return encodeAbiParameters(
                [{ type: "address" }, { type: "bytes" }, { type: "bytes" }],
                [contracts.eoaValidator, pad("0x", { size: 65 }), "0x"]
            )
        },
        async signUserOperation(userOperation) {
            // Print and persist the userOperation for downstream unit testing
            const userOperationWithSender = { ...userOperation, sender: contracts.account }
            console.log("userOperation:", userOperationWithSender)

            // Create a clean user operation object without the account reference
            const cleanUserOp = {
                sender: userOperationWithSender.sender,
                nonce: userOperationWithSender.nonce,
                initCode: userOperationWithSender.initCode || '0x',
                callData: userOperationWithSender.callData,
                callGasLimit: userOperationWithSender.callGasLimit,
                verificationGasLimit: userOperationWithSender.verificationGasLimit,
                preVerificationGas: userOperationWithSender.preVerificationGas,
                maxFeePerGas: userOperationWithSender.maxFeePerGas,
                maxPriorityFeePerGas: userOperationWithSender.maxPriorityFeePerGas,
                paymasterAndData: userOperationWithSender.paymasterAndData || '0x',
                signature: userOperationWithSender.signature || '0x'
            }

            const outPath = path.join(__dirname, 'erc4337-userop.json')
            const replacer = (_key: string, value: unknown) => typeof value === 'bigint' ? `0x${(value as bigint).toString(16)}` : value
            writeFileSync(outPath, JSON.stringify({
                userOperation: cleanUserOp,
                metadata: {
                    chainId: 31337,
                    entryPointAddress: entryPoint08Address,
                    entryPointVersion: '0.8'
                }
            }, replacer, 2))
            console.log(`Saved userOperation to ${outPath}`)

            // Compute hash and signature as in original basic.ts
            const userOpHash = getUserOperationHash({
                userOperation: userOperationWithSender,
                entryPointAddress: entryPoint08Address,
                entryPointVersion: '0.8',
                chainId: 31337
            });
            console.log("userOperationHash:", userOpHash)

            const signature = await privateKeyToAccount(privateKey).sign({ hash: userOpHash });

            console.log("signature:", signature)
            const encodedSignaturePayload = encodeAbiParameters(
                [{ type: "address" }, { type: "bytes" }, { type: "bytes" }],
                [contracts.eoaValidator, signature, "0x"]
            );
            console.log("encodedSignaturePayload:", encodedSignaturePayload);
            return encodedSignaturePayload;
        },
        async decodeCalls(data) {
            // Not used in this test
            return [];
        },
        async getFactoryArgs() {
            // Not used in this test
            return {}
        },
        async signMessage(message) {
            // Not used in this test
            return "0x"
        },
        async signTypedData(typedData) {
            // Not used in this test
            return "0x"
        },
    })

    // zero transfer to a random address
    const hash = await bundlerClient.sendUserOperation({
        account,
        calls: [{
            to: '0xcb98643b8786950F0461f3B0edf99D88F274574D',
            value: 0n,
            data: '0x'
        }]
    })
    const receipt = await bundlerClient.waitForUserOperationReceipt({ hash });
    console.log(receipt);

    process.exit(0)
})()
