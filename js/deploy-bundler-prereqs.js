#!/usr/bin/env node

// eslint-disable-next-line @typescript-eslint/no-require-imports
const fs = require("fs");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const path = require("path");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const {
  concat,
  createPublicClient,
  createWalletClient,
  defineChain,
  getContractAddress,
  http,
  keccak256,
  parseEther,
  recoverTransactionAddress,
} = require("viem");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { privateKeyToAccount } = require("viem/accounts");

const DETERMINISTIC_DEPLOYER_ADDRESS = "0x4e59b44847b379578588920cA78FbF26c0B4956C";
const DETERMINISTIC_DEPLOYER_TRANSACTION =
  "0xf8a58085174876e800830186a08080b853604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf31ba02222222222222222222222222222222222222222222222222222222222222222a02222222222222222222222222222222222222222222222222222222222222222";
const DETERMINISTIC_DEPLOYER_FUNDER_MIN_BALANCE = parseEther("0.02");
const ENTRYPOINT_DEPLOYMENT_SALT = "0x0a59dbff790c23c976a548690c27297883cc66b4c67024f9117b0238995e35e9";

const colors = {
  reset: "\x1b[0m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
};

function log(prefix, message, color = colors.reset) {
  console.log(`${color}[${prefix}]${colors.reset} ${message}`);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function loadAltoArtifact(relativePath) {
  const altoRoot = path.dirname(path.dirname(require.resolve("@pimlico/alto")));
  return readJson(path.join(altoRoot, "esm", "contracts", relativePath));
}

function loadEntrypointDeploymentArtifact() {
  return readJson(
    path.join(
      __dirname,
      "..",
      "dependencies",
      "eth-infinitism-account-abstraction-0.8.0",
      "deployments",
      "ethereum",
      "EntryPoint.json",
    ),
  );
}

async function getCode(publicClient, address) {
  const code = await publicClient.getCode({ address });
  return code && code !== "0x" ? code : null;
}

async function ensureDeterministicDeployer(publicClient, walletClient) {
  const existingCode = await getCode(publicClient, DETERMINISTIC_DEPLOYER_ADDRESS);
  if (existingCode) {
    log("PREP", `Deterministic deployer already available at ${DETERMINISTIC_DEPLOYER_ADDRESS}`, colors.green);
    return;
  }

  const deployerFunder = await recoverTransactionAddress({
    serializedTransaction: DETERMINISTIC_DEPLOYER_TRANSACTION,
  });
  const deployerFunderBalance = await publicClient.getBalance({ address: deployerFunder });
  if (deployerFunderBalance < DETERMINISTIC_DEPLOYER_FUNDER_MIN_BALANCE) {
    log(
      "PREP",
      `Funding deployer signer ${deployerFunder} with ${DETERMINISTIC_DEPLOYER_FUNDER_MIN_BALANCE} wei`,
      colors.cyan,
    );
    const fundHash = await walletClient.sendTransaction({
      to: deployerFunder,
      value: DETERMINISTIC_DEPLOYER_FUNDER_MIN_BALANCE,
    });
    await publicClient.waitForTransactionReceipt({ hash: fundHash });
    log("PREP", `Deployer signer funded with tx ${fundHash}`, colors.green);
  }

  log("PREP", `Deploying deterministic deployer to ${DETERMINISTIC_DEPLOYER_ADDRESS}`, colors.cyan);
  const hash = await publicClient.request({
    method: "eth_sendRawTransaction",
    params: [DETERMINISTIC_DEPLOYER_TRANSACTION],
  });
  await publicClient.waitForTransactionReceipt({ hash });

  const deployedCode = await getCode(publicClient, DETERMINISTIC_DEPLOYER_ADDRESS);
  if (!deployedCode) {
    throw new Error(`Deterministic deployer was not found at ${DETERMINISTIC_DEPLOYER_ADDRESS} after deployment`);
  }

  log("PREP", `Deterministic deployer deployed with tx ${hash}`, colors.green);
}

async function main() {
  const repoRoot = path.join(__dirname, "..");
  const configPath = path.join(repoRoot, "alto.json");
  const config = readJson(configPath);
  const rpcUrl = process.env.ALTO_RPC_URL || config["rpc-url"];
  const privateKey = process.env.ALTO_UTILITY_PRIVATE_KEY || config["utility-private-key"];

  if (!rpcUrl) {
    throw new Error(`Missing rpc-url in ${configPath}`);
  }

  if (!privateKey) {
    throw new Error(`Missing utility-private-key in ${configPath}`);
  }

  const account = privateKeyToAccount(privateKey);
  const transport = http(rpcUrl);
  const publicClient = createPublicClient({ transport });
  const chainId = await publicClient.getChainId();
  const chain = defineChain({
    id: chainId,
    name: "zksync-os-local",
    nativeCurrency: {
      name: "ETH",
      symbol: "ETH",
      decimals: 18,
    },
    rpcUrls: {
      default: { http: [rpcUrl] },
      public: { http: [rpcUrl] },
    },
  });
  const walletClient = createWalletClient({
    account,
    chain,
    transport,
  });

  const salt = keccak256(account.address);
  const contracts = [
    {
      label: "EntryPoint",
      bytecode: loadEntrypointDeploymentArtifact().bytecode,
      salt: ENTRYPOINT_DEPLOYMENT_SALT,
    },
    {
      label: "PimlicoSimulations",
      bytecode: loadAltoArtifact("PimlicoSimulations.sol/PimlicoSimulations.json").bytecode.object,
      salt,
    },
    {
      label: "EntryPointSimulations07",
      bytecode: loadAltoArtifact("EntryPointSimulations.sol/EntryPointSimulations07.json").bytecode.object,
      salt,
    },
    {
      label: "EntryPointSimulations08",
      bytecode: loadAltoArtifact("EntryPointSimulations.sol/EntryPointSimulations08.json").bytecode.object,
      salt,
    },
  ].map(({ label, bytecode, salt: deploymentSalt }) => ({
    label,
    bytecode,
    salt: deploymentSalt,
    address: getContractAddress({
      opcode: "CREATE2",
      bytecode,
      salt: deploymentSalt,
      from: DETERMINISTIC_DEPLOYER_ADDRESS,
    }),
  }));

  log("PREP", `Preparing bundler prerequisites on chain ${chainId} via ${rpcUrl}`, colors.cyan);
  log("PREP", `Using utility wallet ${account.address}`, colors.cyan);

  await ensureDeterministicDeployer(publicClient, walletClient);

  for (const contract of contracts) {
    const existingCode = await getCode(publicClient, contract.address);
    if (existingCode) {
      log("PREP", `${contract.label} already deployed at ${contract.address}`, colors.green);
      continue;
    }

    log("PREP", `Deploying ${contract.label} to ${contract.address}`, colors.cyan);
    const hash = await walletClient.sendTransaction({
      to: DETERMINISTIC_DEPLOYER_ADDRESS,
      data: concat([contract.salt, contract.bytecode]),
    });
    await publicClient.waitForTransactionReceipt({ hash });

    const deployedCode = await getCode(publicClient, contract.address);
    if (!deployedCode) {
      throw new Error(`${contract.label} was not found at ${contract.address} after deployment`);
    }

    log("PREP", `${contract.label} deployed with tx ${hash}`, colors.green);
  }

  console.log(
    JSON.stringify(
      {
        deterministicDeployer: DETERMINISTIC_DEPLOYER_ADDRESS,
        salt,
        contracts: Object.fromEntries(contracts.map((contract) => [contract.label, contract.address])),
      },
      null,
      2,
    ),
  );
}

main().catch((error) => {
  log("PREP", error instanceof Error ? error.message : String(error), colors.red);
  process.exit(1);
});
