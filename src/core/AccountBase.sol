// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title reference implementation of the minimal modular smart account with Hook Extension
/// @author zeroknots.eth | rhinestone.wtf
contract AccountBase {
    error AccountAccessUnauthorized();

    /// @dev The EntryPoint v0.8 standard address.
    address public constant ENTRY_POINT_V08 = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;

    function entryPoint() public pure virtual returns (address) {
        return ENTRY_POINT_V08;
    }

    modifier onlyEntryPointOrSelf() virtual {
        if (!(msg.sender == entryPoint() || msg.sender == address(this))) {
            revert AccountAccessUnauthorized();
        }
        _;
    }

    modifier onlyEntryPoint() virtual {
        if (msg.sender != entryPoint()) {
            revert AccountAccessUnauthorized();
        }
        _;
    }

    /// @dev Sends to the EntryPoint (i.e. `msg.sender`) the missing funds for this transaction.
    /// Subclass MAY override this modifier for better funds management.
    /// (e.g. send to the EntryPoint more than the minimum required, so that in future transactions
    /// it will not be required to send again)
    ///
    /// `missingAccountFunds` is the minimum value this modifier should send the EntryPoint,
    /// which MAY be zero, in case there is enough deposit, or the userOp has a paymaster.
    modifier payPrefund(uint256 missingAccountFunds) virtual {
        _;
        /// @solidity memory-safe-assembly
        assembly {
            if missingAccountFunds {
                // Ignore failure (it's EntryPoint's job to verify, not the account's).
                pop(call(gas(), caller(), missingAccountFunds, codesize(), 0x00, codesize(), 0x00))
            }
        }
    }
}
