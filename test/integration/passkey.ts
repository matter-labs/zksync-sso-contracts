import {
  encodeAbiParameters,
  encodeFunctionData,
  Hex,
  pad,
  toHex,
  concat,
  http,
  createPublicClient,
  parseAbi,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  createBundlerClient,
  toSmartAccount,
  getUserOperationHash,
  entryPoint08Abi,
  entryPoint08Address,
} from "viem/account-abstraction";
import { localhost } from "viem/chains";
import crypto from "crypto";

function sha256(buffer: Buffer): Buffer {
    return crypto.createHash('sha256').update(buffer).digest();
}

function normalizeS(s: Hex) {
    const n = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    const halfN = n / BigInt(2);
    let sBigInt = BigInt(s);
    if (sBigInt > halfN) {
        sBigInt = n - sBigInt;
    }
    return pad(toHex(sBigInt));
}

function signWithPasskey(data: Buffer, privateKey: crypto.KeyObject) {
    const clientData = {
        type: "webauthn.get",
        challenge: data.toString("base64url"),
        origin: "https://example.com",
        crossOrigin: false
    };
    const clientDataJSON = Buffer.from(JSON.stringify(clientData));
    const clientDataHash = sha256(clientDataJSON);

    const rpIdHash = sha256(Buffer.from("example.com")); // SHA256(RP ID)
    const flags = Buffer.from([0x05]); // user present & user verified
    const signCount = Buffer.alloc(4); // 4-byte counter (0)

    const authenticatorData = Buffer.concat([
        rpIdHash,
        flags,
        signCount
    ]);

    const signData = Buffer.concat([
        authenticatorData,
        clientDataHash
    ]);

    const signer = crypto.createSign("SHA256");
    signer.update(signData);
    signer.end();
    const raw = signer.sign({ key: privateKey, dsaEncoding: "ieee-p1363" });
    const r = raw.subarray(0, raw.length / 2);
    const s = raw.subarray(raw.length / 2);

    return {
        authenticatorData: toHex(authenticatorData),
        clientDataJSON: clientDataJSON.toString("utf8"),
        r: toHex(r),
        s: normalizeS(toHex(s)),
    };
}

function getContractAddresses() {
    const txs = require('../../broadcast/Deploy.s.sol/31337/deployAll-latest.json').transactions;
    return {
        eoaValidator: txs[1].contractAddress as Address,
        webauthnValidator: txs[5].contractAddress as Address,
        factory: txs[txs.length - 3].contractAddress as Address,
        account: txs[txs.length - 2].additionalContracts[0].address as Address
    }
}

const anvilPort = 8545;
const altoPort = require("../../alto.json").port;
const anvilRpc = `http://localhost:${anvilPort}`;
const altoRpc = `http://localhost:${altoPort}`;
const privateKey = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6";

(async () => {
    const contracts = getContractAddresses();

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

    const callAbi = [{
        components: [
            { name: 'to', type: 'address' },
            { name: 'value', type: 'uint256' },
            { name: 'data', type: 'bytes' },
        ],
        name: 'Call',
        type: 'tuple[]',
    }];

    let signHash = async function(userOpHash: Hex) {
        console.log("Signing with EOA");
        const signature = await privateKeyToAccount(privateKey).sign({ hash: userOpHash });
        return encodeAbiParameters(
            [{ type: "address" }, { type: "bytes" }, { type: "bytes" }],
            [contracts.eoaValidator, signature, "0x"]
        )
    };

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
            // bad signature, but correct format
            return await signHash(pad("0x", { size: 32 }));
        },
        async signUserOperation(userOperation) {
            const userOpHash = getUserOperationHash({
                userOperation: { ...userOperation, sender: contracts.account },
                entryPointAddress: entryPoint08Address,
                entryPointVersion: '0.8',
                chainId: 31337
            });
            return await signHash(userOpHash);
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

    // credentialId is just random bytes
    const credentialId = toHex(crypto.randomBytes(16));

    // add validation key
    const addValidationKey = await bundlerClient.sendUserOperation({
        account,
        calls: [{
            to: contracts.webauthnValidator,
            value: 0n,
            data: encodeFunctionData({
                abi: parseAbi(["function addValidationKey(bytes memory credentialId, bytes32[2] memory newKey, string memory originDomain) public"]),
                args: [credentialId, [publicKey.x, publicKey.y], "https://example.com"]
            })
        }],
    })
    let receipt = await bundlerClient.waitForUserOperationReceipt({ hash: addValidationKey });
    console.log(receipt.receipt.status);

    // hot-swap signing function
    signHash = async function(userOpHash: Hex) {
        console.log("Signing with Passkey");
        const signature = signWithPasskey(Buffer.from(userOpHash.slice(2), 'hex'), keyPair.privateKey);

        const fatSignature = encodeAbiParameters([
            { type: "bytes" }, // authenticatorData
            { type: "string"}, // clientDataJSON
            { type: "bytes32[2]" }, // r and s
            { type: "bytes" }  // credentialId
        ], [
            signature.authenticatorData, signature.clientDataJSON, [signature.r, signature.s], credentialId
        ]);

        return encodeAbiParameters(
            [{ type: "address" }, { type: "bytes" }, { type: "bytes" }],
            [contracts.webauthnValidator, fatSignature, "0x"]
        );
    }

    // zero transfer to a random address
    const hash = await bundlerClient.sendUserOperation({
        account,
        calls: [{ to: '0xcb98643b8786950F0461f3B0edf99D88F274574D' }],
    })
    receipt = await bundlerClient.waitForUserOperationReceipt({ hash });
    console.log(receipt.receipt.status);

    process.exit(0)
})()
