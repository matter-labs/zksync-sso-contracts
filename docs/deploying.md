# Deploying

## Using forge

To deploy the contracts, use the `Deploy.s.sol` script.

To deploy the factory and 4 modules (`EOAKeyValidator`, `SessionKeyValidator`, `WebAuthnValidator` and `GuardianExecutor`):

```bash
forge script script/Deploy.s.sol \
    --rpc-url $RPC_URL \
    --private-key $DEPLOYER \
    --broadcast
```

This should be used for if a new clean setup is desired (e.g. on a new network).
This will not deploy any accounts yet.

---

To deploy an account from an existing factory with preinstalled modules:

```bash
forge script script/Deploy.s.sol --sig 'deployAccount(address,address[])' $FACTORY_ADDRESS $MODULES_ADDRESSES \
    --rpc-url $RPC_URL \
    --private-key $DEPLOYER \
    --broadcast
```

This should be used to deploy an account when a factory is already deployed on the network, and/or a custom set of preinstalled modules is desired.

---

To deploy everything at once (factory, all 4 default modules, and an account with all 4 default modules installed):

```bash
forge script script/Deploy.s.sol --sig 'deployAll()' \
    --rpc-url $RPC_URL \
    --private-key $DEPLOYER \
    --broadcast
```

This should primarily be used during testing.

---

In each case, admin of the factory and all modules will be the deployer.
For the account, the deployer's key will be registered as an EOA owner in the `EOAKeyValidator`.

Address of the new account can be found in the emitted event `AccountCreated(address indexed newAccount, address indexed deployer)`.

## Manually

To deploy an account from an existing factory, call `deployAccount(bytes32 salt, bytes calldata initData)` on the factory. `initData` must be encoded in the following format:

```solidity
address[] memory modules = ...  // modules to be installed on the new account
bytes[] memory data = ...       // initialization data for each module (empty if not needed)
initData = abi.encodeCall(IMSA.initializeAccount, (modules, data))
```

Modules installed this way have to be of single type and must not repeat in the array.
