# Developer Documentation

## Overview

ZKsync SSO is a modular smart account compliant with [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337) and [ERC-7579](https://eips.ethereum.org/EIPS/eip-7579) and based on the [ERC-7579 reference implementation](https://github.com/erc7579/erc7579-implementation).

Being familiar with these standards can prove useful while reading this documentation.

## Features

- **Modular & Extendable Architecture**: Pluggable validators and executors following the ERC-7579 standard; supports existing 3rd-party modules
- **Multiple Authentication Methods**: Support for EOA keys, WebAuthn passkeys, and session keys
- **Session Key Support**: Grant third parties limited, time-bound access with fine-grained permissions
- **Account Recovery**: Guardian-based recovery system for lost keys or passkeys
- **Upgradeable**: Factory and modules are behind transparent proxies; accounts use beacon proxies

## Documentation

- [Architecture](./architecture.md) - System design and component relationships
- [Deploying](./deploying.md) - Deployment instructions and scripts
- [Modules](./modules.md) - Available modules and their APIs
  - EOAKeyValidator - EOA owner validation
  - WebAuthnValidator - Passkey/WebAuthn support
  - SessionKeyValidator - Session key management with usage limits
  - GuardianExecutor - Guardian-based account recovery
- [Registry](./registry.md) - ERC-7484 module registry integration
- [Calldata Format](./calldata-format.md) - ERC-7579 execution calldata encoding
- [Signature Formats](./signature-formats.md) - Signature encoding for each validator
