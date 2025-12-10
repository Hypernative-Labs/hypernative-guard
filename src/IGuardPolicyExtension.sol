// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Enum} from "@safe/contracts/libraries/Enum.sol";

/// @notice Struct to bundle transaction parameters
struct Transaction {
    address to;
    uint256 value;
    bytes data;
    Enum.Operation operation;
    uint256 safeTxGas;
    uint256 baseGas;
    uint256 gasPrice;
    address gasToken;
    address refundReceiver;
    address executor;
}

struct SignatureParams {
    bytes keeperSignature;
    bytes context;
}

/**
 * @title IGuardPolicyExtension
 * @notice Interface for policy extensions that can be added to a HypernativeGuard for Safe transactions
 * @dev Implementations of this interface provide custom validation logic for Safe transactions using the HypernativeGuard
 */
interface IGuardPolicyExtension {
    /**
     * @notice Checks if a Safe transaction complies with the policy defined by this extension
     * @dev This function should revert if the transaction violates policy rules
     * @param txn The transaction parameters bundled in a struct
     */
    function checkPolicy(Transaction calldata txn, SignatureParams calldata signatureParams) external view;

    /**
     * @notice Checks if the contract supports a specific interface
     * @param interfaceId The interface identifier, as specified in ERC-165
     * @return True if the contract implements the interface defined by `interfaceId`, false otherwise
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
