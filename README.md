# ZKsync SSO ERC-7579 Contracts

A user & developer friendly modular smart account implementation on ZKsync;
simplifying user authentication, session management, and transaction processing.

Aiming to be compliant with the [ERC-7579](https://erc7579.com/) standard.

> [!CAUTION]
> The factory and module interfaces are not yet stable! Any contracts interfacing
> `ModularSmartAccount` will likely need to be updated in the
> final version. The code is currently under audit and the latest may contain
> security vulnerabilities.

## Local Development

1. Install workspace dependencies with `forge soldeer install`.
2. Build the project with `forge build`.
3. Run tests with `forge test`.
