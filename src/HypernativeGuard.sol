// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Safe} from "@safe/contracts/Safe.sol";
import {Enum} from "@safe/contracts/libraries/Enum.sol";
import {BaseTransactionGuard, ITransactionGuard, GuardManager} from "@safe/contracts/base/GuardManager.sol";
import {IGuardPolicyExtension} from "./IGuardPolicyExtension.sol";

/**
 * @title HypernativeGuard
 * @author Hypernative
 * @notice A transaction guard for the Safe smart contract wallet that enforces transaction approval policies
 * @dev Extends BaseTransactionGuard and implements AccessControl for role-based management
 */
contract HypernativeGuard is BaseTransactionGuard, AccessControl {
    error UnapprovedHash();

    /// @notice Address of the Safe wallet this guard is attached to
    /// @dev Immutable and set during contract deployment
    address payable public immutable safeAddress;

    /// @notice Role identifier for keeper accounts that can approve transactions
    bytes32 public constant KEEPER_ROLE = keccak256("KEEPER_ROLE");

    /// @notice Hash used for revoking operations
    bytes32 public immutable revokingHash;

    /// @notice Hash for the timelock activation transaction
    bytes32 public immutable activateTimelockHash;

    /// @notice Hash for the timelock deactivation transaction
    bytes32 public immutable disableTimelockHash;

    /// @dev Timestamp when the timelock expires
    uint256 internal timelockBlock;

    /// @notice Whether the timelock sequence has been triggered
    bool public isTimelockTriggered;

    /// @notice Mapping of approved transaction hashes to their approval status
    mapping(bytes32 txHash => bool) public approvedTxHashes;

    /// @notice Mapping of approved nonce-free transaction hashes to their approval status
    mapping(bytes32 nonceFreeTxHash => bool) public approvedNonceFreeTxHashes;

    /// @notice Mapping of approved function call hashes to their approval status
    mapping(bytes32 functionCallTxHash => bool) public approvedFunctionCallHashes;

    /// @dev Array of policy extension contract addresses that provide additional validation logic
    address[] internal policyExtensions;

    /**
     * @notice Types of transaction hashes that can be approved
     * @dev Used in events to indicate which type of hash is being approved or revoked
     */
    enum HashType {
        Regular,
        NonceFree,
        FunctionCall
    }

    /**
     * @notice Emitted when the timelock is activated
     * @param timestamp The timestamp when the timelock was activated
     */
    event TimelockActivated(uint256 timestamp);

    /**
     * @notice Emitted when the timelock is disabled
     * @param timestamp The timestamp when the timelock was disabled
     */
    event TimelockDisabled(uint256 timestamp);

    /**
     * @notice Emitted when a hash is approved
     * @param hash The hash that was approved
     * @param hashType The type of the hash that was approved
     */
    event HashApproved(bytes32 hash, HashType hashType);

    /**
     * @notice Emitted when a hash is revoked
     * @param hash The hash that was revoked
     * @param hashType The type of the hash that was revoked
     */
    event HashRevoked(bytes32 hash, HashType hashType);

    /**
     * @notice Emitted when a policy extension is added
     * @param policyExtension The address of the added policy extension
     */
    event PolicyExtensionAdded(address policyExtension);

    /**
     * @notice Emitted when a policy extension is removed
     * @param policyExtension The address of the removed policy extension
     */
    event PolicyExtensionRemoved(address policyExtension);

    /**
     * @dev Restricts function access to accounts with the keeper role
     */
    modifier onlyKeeper() {
        require(hasRole(KEEPER_ROLE, msg.sender), "Caller is not a keeper");
        _;
    }

    /**
     * @dev Restricts function access to the guarded Safe contract
     */
    modifier onlyGuardedSafe() {
        require(msg.sender == safeAddress, "Only Safe is allowed to call.");
        _;
    }

    /**
     * @notice Creates a new HypernativeGuard instance
     * @dev Sets up initial configurations, approves timelock transactions, and assigns the deployer as keeper
     * @param _safeAddress The address of the Safe this guard will protect
     * @param _revokingHash The hash that identifies the HypernativeGuard revocation operations
     */
    constructor(address payable _safeAddress, bytes32 _revokingHash) {
        _grantRole(KEEPER_ROLE, msg.sender);
        safeAddress = _safeAddress;
        revokingHash = _revokingHash;
        activateTimelockHash = keccak256(
            abi.encode(
                address(this),
                0,
                keccak256(abi.encodeWithSelector(this.activateTimelock.selector)),
                Enum.Operation.Call,
                0,
                0,
                0,
                address(0),
                payable(0)
            )
        );
        disableTimelockHash = keccak256(
            abi.encode(
                address(this),
                0,
                keccak256(abi.encodeWithSelector(this.disableTimelock.selector)),
                Enum.Operation.Call,
                0,
                0,
                0,
                address(0),
                payable(0)
            )
        );
        // pre-approve timelock transaction hashes as nonce-free
        approveNonceFreeHash(disableTimelockHash);
        approveNonceFreeHash(activateTimelockHash);
    }

    /**
     * @notice Validates transactions before execution by the Safe
     * @dev Applies policy extensions and checks various hash approval methods
     * @param to Destination address of the transaction
     * @param value Ether value of the transaction
     * @param data Transaction data payload
     * @param operation Operation type (Call or DelegateCall)
     * @param safeTxGas Gas that should be used for the safe transaction
     * @param baseGas Gas costs for data used to trigger the safe transaction
     * @param gasPrice Maximum gas price that should be used for this transaction
     * @param gasToken Token address (or 0 if ETH) that is used for the payment
     * @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin)
     */
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        // solhint-disable-next-line no-unused-vars
        address payable refundReceiver,
        bytes memory, /*signatures*/
        address /*executor*/
    ) external view override onlyGuardedSafe {
        // process policy extensions
        for (uint256 i = 0; i < policyExtensions.length; ++i) {
            IGuardPolicyExtension(policyExtensions[i]).checkPolicy(
                to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, "", address(0)
            );
        }

        Safe safe = Safe(safeAddress);
        bytes32 txHash = safe.getTransactionHash(
            to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, safe.nonce() - 1
        );
        bytes32 nonceFreeTxHash = getNonceFreeTransactionHash(
            to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver
        );
        bytes32 functionCallTxHash =
            getFunctionCallHash(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver);

        // if the transaction is a Guard change or revoke operation, check timelock status
        // the revokingHash was set during contract deployment and is used to identify these operations 
        if (functionCallTxHash == revokingHash) {
            require(isTimelockTriggered, "Timelock sequence wasn't initiated");
            require(block.timestamp > timelockBlock, "Timelock wasn't completed yet");
            return;
        } else if (
            approvedTxHashes[txHash] || approvedNonceFreeTxHashes[nonceFreeTxHash]
                || approvedFunctionCallHashes[functionCallTxHash]
        ) {
            return;
        } else {
            // if the transaction hash is not approved, revert
            revert UnapprovedHash();
        }
    }

    /**
     * @notice Required by the ITransactionGuard interface, called after transaction execution
     * @dev This function is a no-op in the current implementation
     */
    function checkAfterExecution(bytes32, bool) external override {}

    /**
     * @notice Approves a transaction hash
     * @dev Sets the approval status to true for a transaction hash
     * @param txHash The hash of the transaction to approve
     */
    function approveHash(bytes32 txHash) public onlyKeeper {
        approvedTxHashes[txHash] = true;
        emit HashApproved(txHash, HashType.Regular);
    }

    /**
     * @notice Approves a nonce-free transaction hash
     * @dev Sets the approval status to true for a nonce-free transaction hash
     * @param nonceFreeTxHash The nonce-free hash of the transaction to approve
     */
    function approveNonceFreeHash(bytes32 nonceFreeTxHash) public onlyKeeper {
        approvedNonceFreeTxHashes[nonceFreeTxHash] = true;
        emit HashApproved(nonceFreeTxHash, HashType.NonceFree);
    }

    /**
     * @notice Approves a function call hash
     * @dev Sets the approval status to true for a function call hash
     * @param functionCallTxHash The function call hash to approve
     */
    function approveFunctionCallHash(bytes32 functionCallTxHash) public onlyKeeper {
        approvedFunctionCallHashes[functionCallTxHash] = true;
        emit HashApproved(functionCallTxHash, HashType.FunctionCall);
    }

    /**
     * @notice Revokes approval for a transaction hash
     * @dev Sets the approval status to false for a transaction hash
     * @param txHash The hash of the transaction to revoke approval for
     */
    function revokeHash(bytes32 txHash) public onlyKeeper {
        approvedTxHashes[txHash] = false;
        emit HashRevoked(txHash, HashType.Regular);
    }

    /**
     * @notice Revokes approval for a nonce-free transaction hash
     * @dev Sets the approval status to false for a nonce-free transaction hash
     * @param nonceFreeTxHash The nonce-free hash to revoke approval for
     */
    function revokeNonceFreeHash(bytes32 nonceFreeTxHash) public onlyKeeper {
        approvedNonceFreeTxHashes[nonceFreeTxHash] = false;
        emit HashRevoked(nonceFreeTxHash, HashType.NonceFree);
    }

    /**
     * @notice Revokes approval for a function call hash
     * @dev Sets the approval status to false for a function call hash
     * @param functionCallTxHash The function call hash to revoke approval for
     */
    function revokeFunctionCallHash(bytes32 functionCallTxHash) public onlyKeeper {
        approvedFunctionCallHashes[functionCallTxHash] = false;
        emit HashRevoked(functionCallTxHash, HashType.FunctionCall);
    }

    /**
     * @notice Adds a policy extension to the guard
     * @dev Can only be called by the Safe contract
     * @param _policyExtension Address of the policy extension to add
     */
    function addPolicyExtension(address _policyExtension) public onlyGuardedSafe {
        policyExtensions.push(_policyExtension);
        emit PolicyExtensionAdded(_policyExtension);
    }

    /**
     * @notice Removes a policy extension from the guard
     * @dev Uses swap-and-pop pattern for efficient removal, can only be called by the Safe
     * @param _policyExtension Address of the policy extension to remove
     */
    function removePolicyExtension(address _policyExtension) public onlyGuardedSafe {
        for (uint256 i = 0; i < policyExtensions.length; ++i) {
            if (policyExtensions[i] == _policyExtension) {
                policyExtensions[i] = policyExtensions[policyExtensions.length - 1];
                policyExtensions.pop();
                emit PolicyExtensionRemoved(_policyExtension);
                break;
            }
        }
    }


    /**
     * @notice Activates the timelock sequence
     * @dev Sets the timelock expiration time to 1 day from the current block timestamp 
     */
    function activateTimelock() public onlyGuardedSafe {
        isTimelockTriggered = true;
        timelockBlock = block.timestamp + 1 days;
        emit TimelockActivated(block.timestamp);
    }

    /**
     * @notice Disables the timelock sequence
     * @dev Can only be called by the Safe contract
     */
    function disableTimelock() public onlyGuardedSafe {
        isTimelockTriggered = false;
        emit TimelockDisabled(block.timestamp);
    }

    /**
     * @notice Grants the keeper role to an address
     * @dev Can only be called by the Safe contract
     * @param _keeper Address to grant the keeper role to
     */
    function grantKeeperRole(address _keeper) public onlyGuardedSafe {
        _grantRole(KEEPER_ROLE, _keeper);
    }

    /**
     * @notice Revokes the keeper role from an address
     * @dev Can only be called by the Safe contract
     * @param _keeper Address to revoke the keeper role from
     */
    function revokeKeeperRole(address _keeper) public onlyGuardedSafe {
        _revokeRole(KEEPER_ROLE, _keeper);
    }

    /**
     * @notice Returns the timestamp when the timelock expires
     * @dev Returns 0 if the timelock is not currently triggered
     * @return The timestamp of the timelock expiration, or 0 if inactive
     */
    function getTimelockBlock() public view returns (uint256) {
        return isTimelockTriggered ? timelockBlock : 0;
    }

    /**
     * @notice Gets all policy extensions
     * @return Array of policy extension addresses
     */
    function getPolicyExtensions() public view returns (address[] memory) {
        return policyExtensions;
    }

    /**
     * @notice Computes a nonce-free transaction hash
     * @dev Hash is based on transaction parameters without considering the nonce
     * @param to Destination address
     * @param value Ether value of the transaction
     * @param data Transaction data payload
     * @param operation Operation type (Call or DelegateCall)
     * @param safeTxGas Gas that should be used for the safe transaction
     * @param baseGas Gas costs for data used to trigger the safe transaction
     * @param gasPrice Maximum gas price that should be used for this transaction
     * @param gasToken Token address (or 0 if ETH) that is used for the payment
     * @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin)
     * @return Hash of the transaction parameters without nonce
     */
    function getNonceFreeTransactionHash(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encode(to, value, keccak256(data), operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver)
        );
    }

    /**
     * @notice Computes a function call hash based on the function selector
     * @dev Extracts the first 4 bytes of the data parameter (function selector)
     * @param to Destination address
     * @param value Ether value of the transaction
     * @param data Transaction data payload
     * @param operation Operation type (Call or DelegateCall)
     * @param safeTxGas Gas that should be used for the safe transaction
     * @param baseGas Gas costs for data used to trigger the safe transaction
     * @param gasPrice Maximum gas price that should be used for this transaction
     * @param gasToken Token address (or 0 if ETH) that is used for the payment
     * @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin)
     * @return Hash based on the function selector and transaction parameters
     */
    function getFunctionCallHash(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver
    ) public pure returns (bytes32) {
        bytes memory functionSelector = new bytes(4);
        assembly {
            let selectorData := mload(add(data, 0x20))
            mstore(add(functionSelector, 0x20), selectorData)
        }
        return keccak256(
            abi.encode(
                to,
                value,
                keccak256(functionSelector),
                operation,
                safeTxGas,
                baseGas,
                gasPrice,
                gasToken,
                refundReceiver
            )
        );
    }

    /**
     * @notice Checks if this contract supports a given interface
     * @dev Overrides implementation from both parent contracts
     * @param interfaceId Interface identifier (4 bytes)
     * @return True if the interface is supported
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(BaseTransactionGuard, AccessControl)
        returns (bool)
    {
        return interfaceId == type(ITransactionGuard).interfaceId // Safe Guard interface
            || AccessControl.supportsInterface(interfaceId);
    }
}
