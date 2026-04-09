# ZKsync SSO ERC-7579 Contracts

A user & developer friendly modular smart account implementation on ZKsync;
simplifying user authentication, session management, and transaction processing.

Aiming to be compliant with the [ERC-7579](https://erc7579.com/) standard.

Based on the
[ERC-7579 reference implementation](https://github.com/erc7579/erc7579-implementation).

Developer documentation: [here](./docs/README.md).

## Local Development

Requires the latest [`foundry`](https://getfoundry.sh).

1. Install workspace dependencies with `forge soldeer install`.
2. Build the project with `forge build`.
3. Run tests with `forge test`.

To run the integration tests:

1. Install dependencies with `pnpm install`
2. Start your local `zksync-os` node so the RPC is available at
   `http://127.0.0.1:3050`.
3. Predeploy the bundler prerequisites with `pnpm bundler:prepare`
4. In a separate terminal, run the bundler with `pnpm bundler`
5. Deploy the reusable SSO contract suite with `pnpm deploy-contracts`
6. If you specifically need a sample account deployment for testing, run
   `pnpm deploy-test-account`
7. Run integration tests with `pnpm test`
