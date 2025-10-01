import {
  encodeAbiParameters,
  Hex,
  pad,
  concat,
  type Address,
  type PublicClient,
} from "viem";

import {
  toSmartAccount,
  getUserOperationHash,
  entryPoint08Abi,
  entryPoint08Address,
  type SmartAccount
} from "viem/account-abstraction";

import { hashTypedData, wrapTypedDataSignature } from "viem/experimental/erc7739";

const callAbi = [{
    components: [
        { name: 'to', type: 'address' },
        { name: 'value', type: 'uint256' },
        { name: 'data', type: 'bytes' },
    ],
    name: 'Call',
    type: 'tuple[]',
}];

type Signer = (hash: Hex) => Promise<Hex>;

export class SsoAccount {
    public account: SmartAccount;
    public signer: Signer;

    private constructor() {}

    public static async create(client: PublicClient, address: Address, signer: Signer) {
        const sso = new SsoAccount();
        sso.signer = signer;

        const account = await toSmartAccount({
            client,
            entryPoint: {
                address: entryPoint08Address,
                version: '0.8',
                abi: entryPoint08Abi
            },
            async encodeCalls(calls) {
                const modeCode = pad('0x01', { dir: 'right' }); // simple batch execute
                const executionData = encodeAbiParameters(
                    callAbi,
                    [calls.map(call => ({ to: call.to, value: call.value ?? 0n, data: call.data ?? '0x' }))]
                );
                const selector = '0xe9ae5c53'; // execute(bytes32,bytes)
                return concat([
                    selector,
                    encodeAbiParameters([{ type: 'bytes32' }, { type: 'bytes' }], [modeCode, executionData])
                ]);
            },
            async getAddress() {
                return address;
            },
            async getNonce() {
                return await client.readContract({
                    abi: entryPoint08Abi,
                    address: entryPoint08Address,
                    functionName: 'getNonce',
                    args: [address, 0n]
                });
            },
            async getStubSignature() {
                // bad signature, but correct format
                return await sso.signer(pad("0x", { size: 32 }));
            },
            async signUserOperation(userOperation) {
                const userOpHash = getUserOperationHash({
                    userOperation: { ...userOperation, sender: address },
                    entryPointAddress: entryPoint08Address,
                    entryPointVersion: '0.8',
                    chainId: 1337
                });
                const signature = await sso.signer(userOpHash);
                console.log("Signature:", signature);
                return signature;
            },
            async decodeCalls(data) {
                // Not used tests
                return [];
            },
            async getFactoryArgs() {
                // Not used tests
                return {};
            },
            async signMessage(message) {
                // Not used in tests
                return "0x";
            },
            async signTypedData(typedData) {
                const verifierDomain = {
                    chainId: 1337,
                    name: "zksync-sso-1271",
                    version: "1.0.0",
                    verifyingContract: address,
                    salt: pad('0x', { size: 32 })
                };
                const erc7739Data: any = {
                    ...typedData,
                    verifierDomain
                }
                const hash = hashTypedData(erc7739Data);
                const signature = await sso.signer(hash);
                return wrapTypedDataSignature({
                    ...erc7739Data,
                    signature
                });
            },
        })

        sso.account = account;
        return sso;
    }
}
