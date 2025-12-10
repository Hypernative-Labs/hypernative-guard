// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IGuardPolicyExtension, Transaction, SignatureParams} from "src/IGuardPolicyExtension.sol";
import {Enum} from "@safe/contracts/libraries/Enum.sol";

contract DelegateNotAllowedPolicy is IGuardPolicyExtension {
    function checkPolicy(Transaction calldata txn, SignatureParams calldata signatureParams) external pure override {
        require(txn.operation != Enum.Operation.DelegateCall, "Delegate call is not allowed");
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IGuardPolicyExtension).interfaceId;
    }
}
