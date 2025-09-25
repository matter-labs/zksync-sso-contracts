// SPDX-License-Identifier: MIT

pragma solidity ^0.8.26;

import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {IEntryPoint, IPaymaster, PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

contract MockPaymaster is IPaymaster {
    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint()));
        _;
    }

    function entryPoint() public view virtual returns (IEntryPoint) {
        return ERC4337Utils.ENTRYPOINT_V08;
    }

    function validatePaymasterUserOp(
        PackedUserOperation calldata, // userOp
        bytes32, // userOpHash
        uint256  // maxCost
    ) public virtual onlyEntryPoint returns (bytes memory context, uint256 validationData) {
        // Allow any userOp from anyone.
        return ("", 0);
    }

    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    ) public virtual onlyEntryPoint {
    }

    function deposit() public payable virtual {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    function addStake(uint32 unstakeDelaySec) public payable virtual {
        entryPoint().addStake{value: msg.value}(unstakeDelaySec);
    }
}
