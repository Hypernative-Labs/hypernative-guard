// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.28;

import {Enum} from "@safe/contracts/libraries/Enum.sol";

/**
 * @title Safe Smart Account Interface.
 * @dev This is the minimal interface required by Safenet contracts in order to interact with Safe accounts, and does
 *      not exhaustively cover all Safe contract methods.
 * @author @safe-global/safe-protocol
 */
interface ISafe {
    /** @notice Executes a `operation` {0: Call, 1: DelegateCall}} transaction to `to` with `value` (Native Currency)
     *          and pays `gasPrice` * `gasLimit` in `gasToken` token to `refundReceiver`.
     * @dev The fees are always transferred, even if the user transaction fails.
     *      This method doesn't perform any sanity check of the transaction, such as:
     *      - if the contract at `to` address has code or not
     *      - if the `gasToken` is a contract or not
     *      It is the responsibility of the caller to perform such checks.
     * @param to Destination address of Safe transaction.
     * @param value Ether value of Safe transaction.
     * @param data Data payload of Safe transaction.
     * @param operation Operation type of Safe transaction.
     * @param safeTxGas Gas that should be used for the Safe transaction.
     * @param baseGas Gas costs that are independent of the transaction execution
     *        (e.g. base transaction fee, signature check, payment of the refund)
     * @param gasPrice Gas price that should be used for the payment calculation.
     * @param gasToken Token address (or 0 if ETH) that is used for the payment.
     * @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin).
     * @param signatures Signature data that should be verified.
     *        Can be packed ECDSA signature ({bytes32 r}{bytes32 s}{uint8 v}), contract signature (EIP-1271)
     *        or approved hash.
     * @return success Boolean indicating transaction's success.
     */
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) external payable returns (bool success);

    /**
     * @notice Execute {operation} (0: Call, 1: DelegateCall) to {to} with {value} (Native Token).
     * @param to Destination address of module transaction.
     * @param value Ether value of module transaction.
     * @param data Data payload of module transaction.
     * @param operation Operation type of module transaction.
     * @return success Boolean flag indicating if the call succeeded.
     */
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) external returns (bool success);

    /**
     * @notice Execute `operation` (0: Call, 1: DelegateCall) to `to` with `value` (Native Token) and return data
     * @param to Destination address of module transaction.
     * @param value Ether value of module transaction.
     * @param data Data payload of module transaction.
     * @param operation Operation type of module transaction.
     * @return success Boolean flag indicating if the call succeeded.
     * @return returnData Data returned by the call.
     */
    function execTransactionFromModuleReturnData(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) external returns (bool success, bytes memory returnData);

    /**
     * @notice Checks whether the signature provided is valid for the provided data and hash. Reverts otherwise.
     * @param dataHash Hash of the data (could be either a message hash or transaction hash)
     * @param signatures Signature data that should be verified.
     *                   Can be packed ECDSA signature ({bytes32 r}{bytes32 s}{uint8 v}), contract signature (EIP-1271),
     *                   or approved hash.
     */
    function checkSignatures(bytes32 dataHash, bytes memory signatures) external view;

    /**
     * @notice Set a guard that checks transactions before execution. This can only be done via a Safe transaction to
     *         the account itself.
     * @dev ⚠️ IMPORTANT: Since a guard has full power to block Safe transaction execution, a broken guard can cause a
     *      denial of service for the Safe. Make sure to carefully audit the guard code and design recovery mechanisms.
     * @param guard The address of the guard to be used or the 0 address to disable the guard.
     */
    function setGuard(address guard) external;

    /**
     * @notice Enables the module `module` for the Safe.
     * @dev This can only be done via a Safe transaction.
     * @param module Module to be whitelisted.
     */
    function enableModule(address module) external;

    /**
     * @notice Checks if a module is enabled for the Safe.
     * @param module Module to check.
     * @return True if the module is enabled, false otherwise.
     */
    function isModuleEnabled(address module) external view returns (bool);

    /**
     * @notice Returns the value of the storage slot at the given index.
     * @param slot Storage slot to read.
     * @param index Index of the storage slot to read.
     * @return The value of the storage slot.
     */
    function getStorageAt(bytes32 slot, uint256 index) external view returns (bytes32);

    /**
     * @notice Returns transaction hash to be signed by owners.
     * @param to Destination address.
     * @param value Ether value.
     * @param data Data payload.
     * @param operation Operation type.
     * @param safeTxGas Gas that should be used for the safe transaction.
     * @param baseGas Gas costs for data used to trigger the safe transaction.
     * @param gasPrice Maximum gas price that should be used for this transaction.
     * @param gasToken Token address (or 0 if ETH) that is used for the payment.
     * @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin).
     * @param nonce Transaction nonce.
     * @return The transaction hash.
     */
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 nonce
    ) external view returns (bytes32);

    /**
     * @notice Gets the current nonce of the Safe contract.
     * @return The value of the current nonce.
     */
    function nonce() external view returns (uint256);
}