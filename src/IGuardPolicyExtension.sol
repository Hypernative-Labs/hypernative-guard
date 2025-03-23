// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Enum} from "@safe/contracts/libraries/Enum.sol";

/**
 * @title IGuardPolicyExtension
 * @notice Interface for policy extensions that can be added to a HypernativeGuard for Safe transactions
 * @dev Implementations of this interface provide custom validation logic for Safe transactions using the HypernativeGuard
 */
interface IGuardPolicyExtension {
    /**
     * @notice Checks if a Safe transaction complies with the policy defined by this extension
     * @dev This function should revert if the transaction violates policy rules
     * @param to Destination address of the transaction
     * @param value Ether value of the transaction
     * @param data Transaction data payload
     * @param operation Operation type (Call or DelegateCall)
     * @param safeTxGas Gas that should be used for the safe transaction
     * @param baseGas Gas costs for data used to trigger the safe transaction
     * @param gasPrice Maximum gas price that should be used for this transaction
     * @param gasToken Token address (or 0 if ETH) that is used for the payment
     * @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin)
     * @param signatures Transaction signatures
     * @param executor Address of the executor of the transaction
     */
    function checkPolicy(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address executor
    ) external view;
}