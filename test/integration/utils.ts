import {
    createPublicClient,
    encodeAbiParameters,
    pad,
    toHex,
    http,
    concat,
    type Hex,
    type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { createBundlerClient } from "viem/account-abstraction";
import { localhost } from "viem/chains";

import crypto from "crypto";

export function contractAddresses() {
    const txs = require('../../broadcast/Deploy.s.sol/31337/deployAll-latest.json').transactions;
    return {
        eoaValidator: txs[1].contractAddress as Address,
        sessionValidator: txs[3].contractAddress as Address,
        webauthnValidator: txs[5].contractAddress as Address,
        guardiansExecutor: txs[7].contractAddress as Address,
        factory: txs[11].contractAddress as Address,
        account: txs[12].additionalContracts[0].address as Address
    }
}

export function createClients(anvilPort: number, bundlerPort: number) {
    // smaller polling interval to speed up the test
    const pollingInterval = 100;

    const client = createPublicClient({
        chain: localhost,
        transport: http(`http://localhost:${anvilPort}`),
        pollingInterval,
    });

    const bundlerClient = createBundlerClient({
        client,
        transport: http(`http://localhost:${bundlerPort}`),
        pollingInterval,
    });

    return { client, bundlerClient }
}

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

export function toEOASigner(privateKey: Hex) {
    const { eoaValidator } = contractAddresses();
    return async function(userOpHash: Hex) {
        const signature = await privateKeyToAccount(privateKey).sign({ hash: userOpHash });
        return concat([eoaValidator, signature]);
    };
}

export function toPasskeySigner(privateKey: crypto.KeyObject, credentialId: Hex) {
    const { webauthnValidator } = contractAddresses();
    return async function(userOpHash: Hex) {
        const signature = signWithPasskey(Buffer.from(userOpHash.slice(2), 'hex'), privateKey);
        const fatSignature = encodeAbiParameters([
            { type: "bytes" }, // authenticatorData
            { type: "string" }, // clientDataJSON
            { type: "bytes32[2]" }, // r and s
            { type: "bytes" }  // credentialId
        ], [
            signature.authenticatorData,
            signature.clientDataJSON,
            [signature.r, signature.s],
            credentialId
        ]);
        return concat([webauthnValidator, fatSignature]);
    }
}
