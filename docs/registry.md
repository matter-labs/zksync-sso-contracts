# Registry

The default registry is not implemented but the account supports having a [ERC-7484](https://eips.ethereum.org/EIPS/eip-7484) registry to check all modules against. The modules are checked upon installation, and upon `executeFromExecutor` call.

By default, no registry is installed on the account so no modules are validated.
