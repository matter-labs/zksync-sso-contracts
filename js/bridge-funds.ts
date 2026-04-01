import { ETH_ADDRESS } from "@matterlabs/zksync-js/core";
import { createViemClient, createViemSdk } from "@matterlabs/zksync-js/viem";
import { createPublicClient, createWalletClient, formatEther, http, parseEther } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { anvil } from "viem/chains";

const PRIVATE_KEY = (process.env.PRIVATE_KEY ||
  "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6") as `0x${string}`;
const L1_RPC = process.env.L1_RPC_URL || "http://localhost:5010";
const L2_RPC = process.env.L2_RPC_URL || "http://localhost:3050";
const MIN_L2_BALANCE = parseEther(process.env.MIN_L2_BALANCE || "15");
const BRIDGE_AMOUNT = parseEther(process.env.BRIDGE_AMOUNT || "25");

async function main() {
  const account = privateKeyToAccount(PRIVATE_KEY);
  const l2 = createPublicClient({ transport: http(L2_RPC) });
  const balance = await l2.getBalance({ address: account.address });

  if (balance >= MIN_L2_BALANCE) {
    console.log(`L2 balance already sufficient for ${account.address}: ${formatEther(balance)} ETH`);
    return;
  }

  console.log(`Bridging ${formatEther(BRIDGE_AMOUNT)} ETH from L1 to L2 for ${account.address}...`);

  const l1 = createPublicClient({ chain: anvil, transport: http(L1_RPC) });
  const l1Wallet = createWalletClient({
    account,
    chain: anvil,
    transport: http(L1_RPC),
  });

  const client = createViemClient({ l1, l2, l1Wallet });
  const sdk = createViemSdk(client);

  const handle = await sdk.deposits.create({
    token: ETH_ADDRESS,
    amount: BRIDGE_AMOUNT,
    to: account.address,
  });

  await sdk.deposits.wait(handle, { for: "l2" });

  const updatedBalance = await l2.getBalance({ address: account.address });
  console.log(`Bridge complete, L2 balance is now ${formatEther(updatedBalance)} ETH`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
