// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {BaseGuard} from  "@safe/contracts/base/GuardManager.sol";
import {Safe} from "@safe/contracts/Safe.sol";
import {Enum} from "@safe/contracts/common/Enum.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract HypernativeGuard is BaseGuard, Ownable {
    error UnapprovedHypernativeHash();

    address payable immutable public safeAddress;
    bytes32 immutable public revokingHash;
    bytes32 immutable public activateTimelockHash;
    bytes32 immutable public disableTimelockHash;
    uint256 internal timelockBlock;
    bool public isTimelockTriggered;
    mapping(bytes32 nonceFreeTxHash => bool) public hypernativeApprovedNonceFreeTxHashes;
    mapping(bytes32 txHash => bool) public hypernativeApprovedTxHashes;

    event TimelockActivated(uint256 timestamp);
    event TimelockDisabled(uint256 timestamp);
    event uintEvent(uint256);
    event addressEvent(address);

    modifier onlyGuardedSafe() {
        require(
            msg.sender == safeAddress,
            "Only seller can call this."
        );
        _;
    }

    constructor(address payable _safeAddress, bytes32 _revokingHash) {
        safeAddress = _safeAddress;
        revokingHash = _revokingHash;
        activateTimelockHash = keccak256(abi.encode(address(this), 0, keccak256(abi.encodeWithSelector(this.activateTimelock.selector)), Enum.Operation.Call, 0, 0, 0, address(0), payable(0)));
        disableTimelockHash = keccak256(abi.encode(address(this), 0, keccak256(abi.encodeWithSelector(this.disableTimelock.selector)), Enum.Operation.Call, 0, 0, 0, address(0), payable(0)));
    }

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
    ) external override onlyGuardedSafe {
        Safe safe = Safe(safeAddress);       
        bytes32 nonceFreeTxHash = getNonceFreeTransactionHash(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver);
        bytes32 txHash = safe.getTransactionHash(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, safe.nonce() - 1);

        if (nonceFreeTxHash == revokingHash) {
            require(isTimelockTriggered, "Timelock sequence wasn't initiated");
            require(block.timestamp > timelockBlock, "Timelock wasn't completed yet");
        }
        else if ((nonceFreeTxHash == disableTimelockHash) || (nonceFreeTxHash == activateTimelockHash)) {
            return;
        }
        else  {
            if (!hypernativeApprovedTxHashes[txHash] && !hypernativeApprovedNonceFreeTxHashes[nonceFreeTxHash]) revert UnapprovedHypernativeHash();
        }
    }

    function checkAfterExecution(bytes32, bool) external override {}

    function hypernativeApproveHash(bytes32 txHash) public onlyOwner {
        hypernativeApprovedTxHashes[txHash] = !hypernativeApprovedTxHashes[txHash];
    }


    function hypernativeApproveNonceFreeHash(bytes32 nonceFreeTxHash) public onlyOwner {
        hypernativeApprovedNonceFreeTxHashes[nonceFreeTxHash] = true;
    }

    function hypernativeRevokeHash(bytes32 txHash) public onlyOwner {
        hypernativeApprovedTxHashes[txHash] = false;
    }

    function hypernativeRevokeNonceFreeHash(bytes32 nonceFreeTxHash) public onlyOwner {
        hypernativeApprovedNonceFreeTxHashes[nonceFreeTxHash] = false;
    }

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
        return keccak256(abi.encode(to, value, keccak256(data), operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver));
    }

    function activateTimelock() public onlyGuardedSafe {
        isTimelockTriggered = true;
        timelockBlock = block.timestamp + 3 days;
        emit TimelockActivated(block.timestamp);
    }

    function disableTimelock() public onlyGuardedSafe {
        isTimelockTriggered = false;
        emit TimelockDisabled(block.timestamp);
    }
}
