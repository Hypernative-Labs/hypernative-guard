// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IGuardPolicyExtension} from "src/IGuardPolicyExtension.sol";
import {Enum} from "@safe/contracts/libraries/Enum.sol";

contract DelegateNotAllowedPolicy is IGuardPolicyExtension {
    function checkPolicy(
        address, /*to*/
        uint256, /*value*/
        bytes memory, /*data*/
        Enum.Operation operation,
        uint256, /*safeTxGas*/
        uint256, /*baseGas*/
        uint256, /*gasPrice*/
        address, /*gasToken*/
        address payable, /*refundReceiver*/
        bytes memory, /*signatures*/
        address /*executor*/
    ) external pure override {
        require(operation != Enum.Operation.DelegateCall, "Delegate call is not allowed");
    }
}
