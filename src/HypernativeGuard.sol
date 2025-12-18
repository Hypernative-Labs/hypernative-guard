// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ISafe, Enum} from "./interfaces/ISafe.sol";
import {IGuardPolicyExtension, Transaction, SignatureParams} from "./IGuardPolicyExtension.sol";
import {BaseTransactionGuard, ITransactionGuard, GuardManager} from "@safe/contracts/base/GuardManager.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title HypernativeGuard
 * @author Hypernative
 * @notice A transaction guard for the Safe smart contract wallet that enforces transaction approval policies
 * @dev Extends BaseTransactionGuard and implements AccessControl for role-based management
 */
contract HypernativeGuard is AccessControlEnumerable, BaseTransactionGuard {
    using EnumerableSet for EnumerableSet.AddressSet;

    error OnlySafe();
    error OnlyKeeper();
    error OnlyKeeperOrSafe();

    error InvalidKeeperSignature();
    error UnapprovedHash();

    error TimelockNotTriggered();
    error TimelockNotCompleted();
    error CannotRevokeTimelockHashes();

    error PolicyExtensionNotValid();
    error PolicyExtensionNotFound();
    error PolicyExtensionAlreadyExists();

    error ZeroAddress();
    error KeeperNotFound();
    error AtLeastOneKeeperRequired();

    /// @notice Address of the Safe wallet this guard is attached to
    /// @dev Immutable and set during contract deployment
    address public immutable safeAddress;

    /// @notice Safe contract instance
    ISafe internal safe;

    /// @notice Role identifier for keeper accounts that can approve transactions
    bytes32 public constant KEEPER_ROLE = keccak256("KEEPER_ROLE");

    /**
     * @dev The precomputed EIP-712 type hash for the Safe transaction type.
     *      Precomputed value of: `keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)")`.
     */
    bytes32 private constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

    /// @notice Cached domain separator for the Safe instance
    /// @dev Computed once during construction to save gas on subsequent calls
    bytes32 public immutable DOMAIN_SEPARATOR;

    /// @notice Hash used for revoking operations
    bytes32 public immutable revokingHash;

    /// @notice Hash for the timelock activation transaction
    bytes32 public immutable activateRevokeTimelockHash;

    /// @notice Hash for the timelock deactivation transaction
    bytes32 public immutable disableRevokeTimelockHash;

    /// @notice Hash for enabling pass-through mode (requires timelock)
    bytes32 public immutable enablePassThroughModeHash;

    /// @dev Timestamp when the timelock expires
    uint256 internal revokeTimelockBlock;

    /// @notice Whether the timelock sequence has been triggered
    bool public isRevokeTimelockTriggered;

    /// @dev Timestamp when the pass-through timelock expires
    uint256 internal passThroughTimelockBlock;

    /// @notice Whether the pass-through timelock sequence has been triggered
    bool public isPassThroughTimelockTriggered;

    /// @notice Whether the guard is in pass-through mode
    /// @dev If true, the guard will not enforce restriction on the transaction and will allow it to pass through
    bool public isPassThroughMode;

    /// @notice Mapping of approved transaction hashes to their approval status
    mapping(bytes32 txHash => bool) public approvedTxHashes;

    /// @notice Mapping of approved nonce-free transaction hashes to their approval status
    mapping(bytes32 nonceFreeTxHash => bool) public approvedNonceFreeTxHashes;

    /// @notice Mapping of approved function call hashes to their approval status
    mapping(bytes32 functionCallTxHash => bool) public approvedFunctionCallHashes;

    /// @dev Array of policy extension contract addresses that provide additional validation logic
    EnumerableSet.AddressSet internal policyExtensions;

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
    event RevokeTimelockActivated(uint256 timestamp);

    /**
     * @notice Emitted when the timelock is disabled
     * @param timestamp The timestamp when the timelock was disabled
     */
    event RevokeTimelockDisabled(uint256 timestamp);

    /**
     * @notice Emitted when the pass-through timelock is activated
     * @param timestamp The timestamp when the pass-through timelock was activated
     */
    event PassThroughTimelockActivated(uint256 timestamp);

    /**
     * @notice Emitted when the pass-through timelock is disabled
     * @param timestamp The timestamp when the pass-through timelock was disabled
     */
    event PassThroughTimelockDisabled(uint256 timestamp);

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
     * @notice Emitted when the pass-through mode is enabled
     */
    event PassThroughModeEnabled();

    /**
     * @notice Emitted when the pass-through mode is disabled
     */
    event PassThroughModeDisabled();

    /**
     * @dev Restricts function access to accounts with the keeper role
     */
    modifier onlyKeeper() {
        require(hasRole(KEEPER_ROLE, msg.sender), OnlyKeeper());
        _;
    }

    /**
     * @dev Restricts function access to the guarded Safe contract
     */
    modifier onlyGuardedSafe() {
        require(msg.sender == safeAddress, OnlySafe());
        _;
    }

    /**
     * @dev Restricts function access to the keeper or the protected Safe contract
     */
    modifier onlyKeeperOrSafe() {
        require(hasRole(KEEPER_ROLE, msg.sender) || msg.sender == safeAddress, OnlyKeeperOrSafe());
        _;
    }

    /**
     * @notice Creates a new HypernativeGuard instance
     * @dev Sets up initial configurations, approves timelock transactions, and assigns the deployer as keeper
     * @param _safeAddress The address of the Safe this guard will protect
     * @param _keeper The address of the keeper that will be granted the keeper role
     */
    constructor(address _safeAddress, address _keeper) {
        _grantRole(KEEPER_ROLE, _keeper);
        isPassThroughMode = true;
        require(_safeAddress != address(0), ZeroAddress());
        require(_keeper != address(0), ZeroAddress());
        safeAddress = _safeAddress;
        safe = ISafe(safeAddress);
        DOMAIN_SEPARATOR = safe.domainSeparator();
        
        revokingHash = getPrivilegedOperationHash(
            safeAddress,
            abi.encodeWithSelector(GuardManager.setGuard.selector),
            Enum.Operation.Call
        );

        enablePassThroughModeHash = getPrivilegedOperationHash(
            address(this),
            abi.encodeWithSelector(this.enablePassThroughMode.selector),
            Enum.Operation.Call
        );

        activateRevokeTimelockHash = getNonceFreeTransactionHash(
            address(this),
            0,
            abi.encodeWithSelector(this.activateRevokeTimelock.selector),
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(0)
        );

        disableRevokeTimelockHash = getNonceFreeTransactionHash(
            address(this),
            0,
            abi.encodeWithSelector(this.disableRevokeTimelock.selector),
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(0)
        );

        // pre-approve timelock transaction hashes as nonce-free
        approvedNonceFreeTxHashes[activateRevokeTimelockHash] = true;
        approvedNonceFreeTxHashes[disableRevokeTimelockHash] = true;
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
        address payable refundReceiver,
        bytes calldata signatures,
        address executor
    ) external view override  {
        if (isPassThroughMode || msg.sender != safeAddress) {
            return;
        }

        // context is being ignored for now, and reserved for potential future use
        (SignatureParams memory signatureParams) = _extractSignatureComponents(signatures);

        Transaction memory txn = Transaction({
            to: to,
            value: value,
            data: data,
            operation: operation,
            safeTxGas: safeTxGas,
            baseGas: baseGas,
            gasPrice: gasPrice,
            gasToken: gasToken,
            refundReceiver: refundReceiver,
            executor: executor
        });

        // process policy extensions
        for (uint256 i = 0; i < policyExtensions.length(); ++i) {
            IGuardPolicyExtension(policyExtensions.at(i)).checkPolicy(
                txn,
                signatureParams
            );
        }   
        _validateTransactionApproval(txn, signatureParams.keeperSignature);
    }

    /**
     * @dev Extracts keeper signature and context from signatures bytes
     * @dev that assumes the following format of the signatures field: [signatures][keeperSignature: 65 bytes][context: contextLength bytes][contextLength: bytes32]
     * @param signatures The full signatures bytes with appended keeper signature and context
     * @return signatureParams The signature parameters
     */
    function _extractSignatureComponents(bytes calldata signatures)
        internal
        pure
        returns (SignatureParams memory signatureParams) {
        
        uint256 signaturesLength = signatures.length;
        // Minimum length: 65 bytes (keeper sig) + 32 bytes (context length) = 97 bytes  
        if (signaturesLength < 97) {
            return (SignatureParams(new bytes(0), new bytes(0)));
        }
        
        // Read context length from the last 32 bytes
        uint256 contextLength = uint256(bytes32(signatures[signaturesLength - 32:]));
        
        // Validate: total length must be at least 65 (keeper) + contextLength + 32 (length field)
        // Which means: contextLength must be <= signatures.length - 97
        if (contextLength > signaturesLength - 97) {
            return (SignatureParams(new bytes(0), new bytes(0)));
        }
        
        // Now safe to calculate indices
        uint256 contextStartIndex = signaturesLength - 32 - contextLength;
        uint256 keeperSignatureStartIndex = contextStartIndex - 65;
        
        signatureParams.keeperSignature = signatures[keeperSignatureStartIndex : contextStartIndex];
        signatureParams.context = signatures[contextStartIndex : signaturesLength - 32];
    }

    /**
     * @dev Validates transaction approval via hash checks or timelock
     * @param txn The transaction to validate
     * @param keeperSignature The keeper signature
     */
    function _validateTransactionApproval(
        Transaction memory txn,
        bytes memory keeperSignature
    ) internal view {

        bytes32 txHash = getTransactionHash(txn.to, txn.value, txn.data, txn.operation, txn.safeTxGas, txn.baseGas, txn.gasPrice, txn.gasToken, txn.refundReceiver, safe.nonce() - 1);

        bytes32 nonceFreeTxHash = getNonceFreeTransactionHash(
            txn.to, txn.value, txn.data, txn.operation, txn.safeTxGas, txn.baseGas, txn.gasPrice, txn.gasToken, txn.refundReceiver
        );
        bytes32 functionCallTxHash =
            getFunctionCallHash(txn.to, txn.value, txn.data, txn.operation, txn.safeTxGas, txn.baseGas, txn.gasPrice, txn.gasToken, txn.refundReceiver);
        
        bytes32 privilegedOperationHash = getPrivilegedOperationHash(
            txn.to,
            txn.data,
            txn.operation
        );

        // skip ECDSA recovery for empty keeper signatures to save gas
        // forge-lint: disable-next-line(unsafe-typecast)
        bool isValidKeeperSignature = _checkKeeperSignature(txHash, keeperSignature);

        // Check timelock-protected operations
        if (privilegedOperationHash == revokingHash) {
            _checkTimelock(revokeTimelockBlock, isRevokeTimelockTriggered);
            return;
        }
        else if (privilegedOperationHash == enablePassThroughModeHash) {
            _checkTimelock(passThroughTimelockBlock, isPassThroughTimelockTriggered);
            return;
        }
        else if (isValidKeeperSignature) {
            return;
        }
        else if (
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
     * @dev Checks if the keeper signature is valid
     * @param txHash The hash of the transaction
     * @param keeperSignature The keeper signature
     */
    function _checkKeeperSignature(bytes32 txHash, bytes memory keeperSignature) internal view returns (bool isValidKeeperSignature) {
        // Skip ECDSA recovery for empty keeper signatures to save gas
        if (bytes32(keeperSignature) == bytes32(0)) {
            return false;
        }
        (address signer, ECDSA.RecoverError err, ) = ECDSA.tryRecover(txHash, keeperSignature);
        isValidKeeperSignature = hasRole(KEEPER_ROLE, signer) && err == ECDSA.RecoverError.NoError;
    }
    
    /**
     * @dev Checks if a timelock is properly triggered and expired
     * @param timelockExpiry The timestamp when the timelock expires
     * @param timelockTriggered Whether the timelock has been triggered
     */
    function _checkTimelock(uint256 timelockExpiry, bool timelockTriggered) internal view {
        require(timelockExpiry > 0 && timelockTriggered, TimelockNotTriggered());
        require(block.timestamp > timelockExpiry, TimelockNotCompleted());
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
     * @notice Approves a nonce-free transaction hash - allowing the transaction to be executed regardless of the current safe nonce
     * @dev Sets the approval status to true for a nonce-free transaction hash
     * @param nonceFreeTxHash The nonce-free hash of the transaction to approve
     */
    function approveNonceFreeHash(bytes32 nonceFreeTxHash) public onlyKeeper {
        approvedNonceFreeTxHashes[nonceFreeTxHash] = true;
        emit HashApproved(nonceFreeTxHash, HashType.NonceFree);
    }

    /**
     * @notice Approves a function call hash - allowing a call using 4byte selecor and target address to be executed
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
        if (nonceFreeTxHash == activateRevokeTimelockHash || nonceFreeTxHash == disableRevokeTimelockHash) {
            revert CannotRevokeTimelockHashes();
        }
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
        require(
            IGuardPolicyExtension(_policyExtension).supportsInterface(type(IGuardPolicyExtension).interfaceId),
            PolicyExtensionNotValid()
        );
        require(policyExtensions.add(_policyExtension), PolicyExtensionAlreadyExists());
        emit PolicyExtensionAdded(_policyExtension);
    }

    /**
     * @notice Removes a policy extension from the guard
     * @param _policyExtension Address of the policy extension to remove
     */
    function removePolicyExtension(address _policyExtension) public onlyKeeperOrSafe {
        require(policyExtensions.remove(_policyExtension), PolicyExtensionNotFound());
        emit PolicyExtensionRemoved(_policyExtension);
    }

    /**
     * @notice Disables the pass-through mode
     * @dev Can only be called by the keeper
     */
    function disablePassThroughMode() public onlyKeeperOrSafe {
        isPassThroughMode = false;
        emit PassThroughModeDisabled();
    }

    /**
     * @notice Enables the pass-through mode
     * @dev Can only be called by the keeper
     */
    function enablePassThroughMode() public onlyGuardedSafe {
        isPassThroughMode = true;
        emit PassThroughModeEnabled();
    }

    /**
     * @notice Activates the pass-through timelock sequence
     * @dev Sets the pass-through timelock expiration time to 1 day from the current block timestamp
     */
    function activatePassThroughTimelock() public onlyGuardedSafe {
        isPassThroughTimelockTriggered = true;
        passThroughTimelockBlock = block.timestamp + 1 days;
        emit PassThroughTimelockActivated(block.timestamp);
    }

    /**
     * @notice Disables the pass-through timelock sequence
     * @dev Can only be called by the Safe contract
     */
    function disablePassThroughTimelock() public onlyGuardedSafe {
        isPassThroughTimelockTriggered = false;
        passThroughTimelockBlock = 0;
        emit PassThroughTimelockDisabled(block.timestamp);
    }


    /**
     * @notice Activates the timelock sequence
     * @dev Sets the timelock expiration time to 1 day from the current block timestamp
     */
    function activateRevokeTimelock() public onlyGuardedSafe {
        isRevokeTimelockTriggered = true;
        revokeTimelockBlock = block.timestamp + 1 days;
        emit RevokeTimelockActivated(block.timestamp);
    }

    /**
     * @notice Disables the timelock sequence
     * @dev Can only be called by the Safe contract
     */
    function disableRevokeTimelock() public onlyGuardedSafe {
        isRevokeTimelockTriggered = false;
        revokeTimelockBlock = 0;
        emit RevokeTimelockDisabled(block.timestamp);
    }

    /**
     * @notice Grants the keeper role to an address
     * @dev Can only be called by the Safe contract
     * @param _keeper Address to grant the keeper role to
     */
    function grantKeeperRole(address _keeper) public onlyGuardedSafe {
        require(_keeper != address(0), ZeroAddress());
        _grantRole(KEEPER_ROLE, _keeper);
    }

    /**
     * @notice Revokes the keeper role from an address
     * @dev Can only be called by the Safe contract
     * @param _keeper Address to revoke the keeper role from
     */
    function revokeKeeperRole(address _keeper) public onlyGuardedSafe {
        require(hasRole(KEEPER_ROLE, _keeper), KeeperNotFound());
        require(getRoleMemberCount(KEEPER_ROLE) > 1, AtLeastOneKeeperRequired());
        _revokeRole(KEEPER_ROLE, _keeper);
    }

    /**
     * @notice Returns the timestamp when the timelock expires
     * @dev Returns 0 if the timelock is not currently triggered
     * @return The timestamp of the timelock expiration, or 0 if inactive
     */
    function getRevokeTimelockBlock() public view returns (uint256) {
        return revokeTimelockBlock;
    }

    /**
     * @notice Returns the timestamp when the pass-through timelock expires
     * @dev Returns 0 if the pass-through timelock is not currently triggered
     * @return The timestamp of the pass-through timelock expiration, or 0 if inactive
     */
    function getPassThroughTimelockBlock() public view returns (uint256) {
        return passThroughTimelockBlock;
    }

    /**
     * @notice Gets all policy extensions
     * @return Array of policy extension addresses
     */
    function getPolicyExtensions() public view returns (address[] memory) {
        return policyExtensions.values();
    }

    /**
     * @notice Computes the Safe transaction hash locally without an external call
     * @dev Uses EIP-712 structured hashing, matching Safe's getTransactionHash implementation
     * @param to Destination address
     * @param value Ether value
     * @param data Transaction data payload
     * @param operation Operation type
     * @param safeTxGas Gas that should be used for the safe transaction
     * @param baseGas Gas costs for data used to trigger the safe transaction
     * @param gasPrice Maximum gas price that should be used for this transaction
     * @param gasToken Token address (or 0 if ETH) that is used for the payment
     * @param refundReceiver Address of receiver of gas payment (or 0 if tx.origin)
     * @param _nonce Transaction nonce
     * @return Transaction hash computed using EIP-712
     */
    function getTransactionHash(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) internal view returns (bytes32) {
        bytes32 safeTxHash = keccak256(
            abi.encode(
                SAFE_TX_TYPEHASH,
                to,
                value,
                keccak256(data),
                operation,
                safeTxGas,
                baseGas,
                gasPrice,
                gasToken,
                refundReceiver,
                _nonce
            )
        );
        return keccak256(abi.encodePacked(bytes1(0x19), bytes1(0x01), DOMAIN_SEPARATOR, safeTxHash));
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
        bytes memory functionSelector = getFunctionSelector(data);
        return keccak256(
            abi.encode(
                to,
                value,
                functionSelector,
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
     * @notice Computes a privileged operation hash that only includes essential parameters
     * @dev This hash excludes Safe execution parameters (safeTxGas, baseGas, gasPrice, gasToken, refundReceiver)
     *      as well as value and operation to ensure privileged operations are detected regardless of how they're executed.
     *      Used for critical operations like setGuard, revokeKeeperRole, enablePassThroughMode, etc.
     * @param to Destination address
     * @param data Transaction data payload (includes function selector and parameters)
     * @return Hash based only on the target address and function call data
     */
    function getPrivilegedOperationHash(
        address to,
        bytes memory data,
        Enum.Operation operation
    ) public pure returns (bytes32) {
        bytes memory functionSelector = getFunctionSelector(data);
        return keccak256(
            abi.encode(
                to,
                functionSelector,
                operation
            )
        );
    }

    function getFunctionSelector(bytes memory data) internal pure returns (bytes memory) {
        bytes memory functionSelector = new bytes(4);
        assembly {
            let selectorData := mload(add(data, 0x20))
            mstore(add(functionSelector, 0x20), selectorData)
        }
        return functionSelector;
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
        override(AccessControlEnumerable, BaseTransactionGuard)
        returns (bool)
    {
        return super.supportsInterface(interfaceId)
            || AccessControlEnumerable.supportsInterface(interfaceId);
    }
}
