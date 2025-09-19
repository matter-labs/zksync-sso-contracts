import { getUserOperationHash } from 'viem/account-abstraction'
import { privateKeyToAccount } from 'viem/accounts'
import { encodeAbiParameters } from 'viem'
import { readFileSync } from 'fs'
import path from 'path'

type UserOperation = {
    sender: `0x${string}`
    nonce: bigint
    initCode: `0x${string}`
    callData: `0x${string}`
    callGasLimit: bigint
    verificationGasLimit: bigint
    preVerificationGas: bigint
    maxFeePerGas: bigint
    maxPriorityFeePerGas: bigint
    paymasterAndData: `0x${string}`
    signature: `0x${string}`
}

function reviveBigints<T>(obj: T): T {
    if (obj === null || typeof obj !== 'object') return obj
    if (Array.isArray(obj)) return obj.map(reviveBigints) as unknown as T
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
        if (typeof v === 'string' && v.startsWith('0x') && v.length > 2) {
            try {
                // Only convert hex strings that look like numbers (not addresses or data)
                if (v.length <= 18) { // Max 64-bit hex string
                    out[k] = BigInt(v)
                    continue
                }
            } catch { }
        }
        out[k] = reviveBigints(v)
    }
    return out as T
}

const userOpPath = path.join(__dirname, 'erc4337-userop.json')
const raw = JSON.parse(readFileSync(userOpPath, 'utf8'))
const userOperation: UserOperation = reviveBigints(raw.userOperation)
const { entryPointAddress, entryPointVersion, chainId } = raw.metadata as {
    entryPointAddress: `0x${string}`
    entryPointVersion: '0.6' | '0.7' | '0.8'
    chainId: number
}

    ; (async () => {
        const userOperationHash = getUserOperationHash({
            userOperation,
            entryPointAddress,
            entryPointVersion,
            chainId,
        })

        console.log('userOperation (revived):', userOperation)
        console.log('userOperationHash:', userOperationHash)

        // Assert against the hash logged from basic.ts
        const expectedHash = '0x2df06416b0a74c9125b57736a863665a767570fa3a5958735ddf2cc325a23a3e'
        console.log('Expected hash from basic.ts:', expectedHash)
        console.log('Hashes match:', userOperationHash === expectedHash)

        if (userOperationHash !== expectedHash) {
            console.error('❌ Hash mismatch!')
            process.exit(1)
        } else {
            console.log('✅ Hash matches!')
        }

        // Test signature calculation
        console.log('\n=== Testing Signature Calculation ===')
        const privateKey = "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6"
        const account = privateKeyToAccount(privateKey)

        // Sign the user operation hash
        const signature = await account.sign({ hash: userOperationHash })
        console.log('Computed signature:', signature)

        // Expected signature from basic.ts
        const expectedSignature = '0xe78c2d68677789bdb8e636848e81c7143301c98828c0730f89e1e2ecbb11ddac483d48515fc52d1b9b98ad59c47a41dc160ee8235435c415f44a44c77a9ed7811b'
        console.log('Expected signature from basic.ts:', expectedSignature)
        console.log('Signatures match:', signature === expectedSignature)

        if (signature !== expectedSignature) {
            console.error('❌ Signature mismatch!')
            process.exit(1)
        } else {
            console.log('✅ Signature matches!')
        }

        // Test encoded signature payload
        console.log('\n=== Testing Encoded Signature Payload ===')
        const eoaValidator = '0x00427edf0c3c3bd42188ab4c907759942abebd93'
        const encodedSignaturePayload = encodeAbiParameters(
            [{ type: "address" }, { type: "bytes" }, { type: "bytes" }],
            [eoaValidator, signature, "0x"]
        )
        console.log('Computed encodedSignaturePayload:', encodedSignaturePayload)

        // Expected encoded signature payload from basic.ts
        const expectedEncodedSignaturePayload = '0x00000000000000000000000000427edf0c3c3bd42188ab4c907759942abebd93000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000041e78c2d68677789bdb8e636848e81c7143301c98828c0730f89e1e2ecbb11ddac483d48515fc52d1b9b98ad59c47a41dc160ee8235435c415f44a44c77a9ed7811b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        console.log('Expected encodedSignaturePayload from basic.ts:', expectedEncodedSignaturePayload)
        console.log('Encoded signature payloads match:', encodedSignaturePayload === expectedEncodedSignaturePayload)

        if (encodedSignaturePayload !== expectedEncodedSignaturePayload) {
            console.error('❌ Encoded signature payload mismatch!')
            process.exit(1)
        } else {
            console.log('✅ Encoded signature payload matches!')
        }
    })()


