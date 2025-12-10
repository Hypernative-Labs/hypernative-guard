// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IGuardPolicyExtension, Transaction, SignatureParams} from "src/IGuardPolicyExtension.sol";

contract AddressZeroNotAllowedPolicy is IGuardPolicyExtension {
    function checkPolicy(Transaction calldata txn, SignatureParams calldata signatureParams) external pure override {
        require(txn.to != address(0), "Address 0 is not allowed");
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IGuardPolicyExtension).interfaceId;
    }
}
