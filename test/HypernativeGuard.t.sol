// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import {console} from "forge-std/Test.sol";
import "../src/HypernativeGuard.sol";
import {Safe} from "@safe/contracts/Safe.sol";
import {Enum} from "@safe/contracts/libraries/Enum.sol";
import {SigUtils} from "./SigUtils.sol";
import {GuardManager} from "@safe/contracts/base/GuardManager.sol";
import {MockPoolManager} from "./Mocks/MockPoolManager.sol";
import {AddressZeroNotAllowedPolicy} from "./Mocks/MockPolicies/AddressZeroNotAllowedPolicy.sol";

contract HypernativeGuardTest is Test {
    HypernativeGuard public hypernativeGuard;
    Safe public safe;
    SigUtils sigUtils;
    MockPoolManager public poolManager;
    AddressZeroNotAllowedPolicy public addressZeroNotAllowedPolicy;
    bytes32 private _changeGuardHash;

    address internal signer1;
    address internal signer2;
    uint256 private _owner1PrivateKey;
    uint256 private _owner2PrivateKey;
    uint256 private _owner3PrivateKey;
    uint256[] private ownerPKs;
    mapping(address => address) private ownerAddresses;

    bytes32 public constant TYPE_HASH = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");

    function setUp() public {
        string memory url = vm.rpcUrl("sepolia");
        vm.selectFork(vm.createFork(url));
        safe = Safe(payable(0xCFe98FC6d837cccbaF6bCa703652a664a8a59604));
        sigUtils = new SigUtils(safe.domainSeparator());
        // _owner1PrivateKey = vm.envUint("SIGNER1");
        // _owner2PrivateKey = vm.envUint("SIGNER2");
        _owner3PrivateKey = vm.envUint("SIGNER3");

        ownerPKs.push(_owner3PrivateKey);
        //ownerPKs.push(_owner2PrivateKey);
        signer1 = vm.addr(_owner3PrivateKey);
        //signer2 = vm.addr(_owner2PrivateKey);
        ownerAddresses[signer1] = signer1;
        //ownerAddresses[signer2] = signer2;
        // the hash to revoke the guard
        bytes memory setGuardData = abi.encodeWithSelector(GuardManager.setGuard.selector);
        _changeGuardHash = keccak256(
            abi.encode(
                address(safe),
                0,
                keccak256((getFunctionSelector(setGuardData))),
                Enum.Operation.Call,
                0,
                0,
                0,
                address(0),
                payable(0)
            )
        );
        hypernativeGuard = new HypernativeGuard(payable(safe), _changeGuardHash, address(this));
        poolManager = new MockPoolManager(address(safe));
        addressZeroNotAllowedPolicy = new AddressZeroNotAllowedPolicy();
        vm.startPrank(signer1);
        vm.deal(address(safe), 1 ether);
    }

    function test_SendFunds() public {
        (bool success,) = payable(safe).call{value: 0.1 ether}("");
        require(success);
    }

    function test_addHashNotKeeperReverts() public {
        vm.expectRevert();
        hypernativeGuard.approveNonceFreeHash(0x0);
    }

    function test_WithdrawEth() public {
        uint256 balanceBefore = address(safe).balance;
        withdrawEth();
        assertEq(balanceBefore - 0.005 ether, address(safe).balance);
    }

    function withdrawEth() internal {
        SigUtils.SafeTx memory safeTx = generateWithrawTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        bytes memory signatures = signTransaction(digest);
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );
    }

    function withdrawEthReverts() internal {
        SigUtils.SafeTx memory safeTx = generateWithrawTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        bytes memory signatures = signTransaction(digest);
        vm.expectRevert();
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );
    }

    function testConfigureHypernativeGuard() public {
        SigUtils.SafeTx memory safeTx = generateConfigureGuardTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        bytes memory signatures = signTransaction(digest);
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );
    }

    function test_ConfigureHypernativeGuardAndAbortUnapprovedTx() public {
        testConfigureHypernativeGuard();
        withdrawEthReverts();
    }

    function test_ConfigureHypernativeGuardAndExecuteWithrawTx() public {
        testConfigureHypernativeGuard();
        SigUtils.SafeTx memory safeTx = generateWithrawTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        bytes memory signatures = signTransaction(digest);
        vm.stopPrank();
        hypernativeGuard.approveHash(digest);
        vm.startPrank(signer1);
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );
    }

    function test_RevokeApprovedHashExpectRevert() public {
        testConfigureHypernativeGuard();
        SigUtils.SafeTx memory safeTx = generateWithrawTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        vm.stopPrank();
        hypernativeGuard.approveHash(digest);
        hypernativeGuard.revokeHash(digest);
        vm.startPrank(signer1);
        withdrawEthReverts();
    }

    function testRevokeHypernativeGuardRevertsOnTimelockInit() public {
        testConfigureHypernativeGuard();
        (SigUtils.SafeTx memory safeTx, bytes memory signatures) = generateAndApproveRevokeGuardTx();
        vm.startPrank(signer1);
        vm.expectRevert(HypernativeGuard.TimelockNotTriggered.selector);
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );
    }

    function testRevokeHypernativeGuardRevertsOnTimelockStillActive() public {
        testConfigureHypernativeGuard();
        activateTimelock();
        (SigUtils.SafeTx memory safeTx, bytes memory signatures) = generateAndApproveRevokeGuardTx();
        vm.warp(block.timestamp + 10 hours);
        vm.expectRevert();
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );
    }

    function test_TimelockCancelation() public {
        // setGuard
        testConfigureHypernativeGuard();
        // activate timelock
        activateTimelock();
        vm.warp(block.timestamp + 5 hours);
        disableTimelock();
        vm.warp(block.timestamp + 2 days);
        withdrawEthReverts();
    }

    function test_RevokeHypernativeGuardSuccessfuly() public {
        testConfigureHypernativeGuard();
        activateTimelock();
        (SigUtils.SafeTx memory safeTx, bytes memory signatures) = generateAndApproveRevokeGuardTx();
        vm.warp(block.timestamp + 4 days);
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );
        test_WithdrawEth();
    }

    function test_NonceFreeTx() public {
        testConfigureHypernativeGuard();
        SigUtils.SafeTx memory safeTx = generateWithrawTxToSign();
        bytes32 nonceFreeHash = hypernativeGuard.getNonceFreeTransactionHash(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver
        );
        vm.stopPrank();
        hypernativeGuard.approveNonceFreeHash(nonceFreeHash);
        vm.startPrank(signer1);
        // shouldn't revert because the nonceFreeHash is already approved
        test_WithdrawEth();
        test_WithdrawEth();
        test_WithdrawEth();
    }

    function test_ApproveAndRevokeNonceFree() public {
        testConfigureHypernativeGuard();
        SigUtils.SafeTx memory safeTx = generateWithrawTxToSign();
        bytes32 nonceFreeHash = hypernativeGuard.getNonceFreeTransactionHash(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver
        );
        vm.stopPrank();
        hypernativeGuard.approveNonceFreeHash(nonceFreeHash);
        vm.startPrank(signer1);
        // shouldn't revert because the nonceFreeHash is already approved
        test_WithdrawEth();
        vm.stopPrank();
        hypernativeGuard.revokeNonceFreeHash(nonceFreeHash);
        vm.startPrank(signer1);
        // // should revert because the nonceFreeHash is revoked
        withdrawEthReverts();
    }

    function test_FunctionCallHash() public {
        testConfigureHypernativeGuard();

        // Since we are using functionCallHash, only the selector is needed, so while we can specify a certain address as param, every address will be allowed
        // and only the one that was actually sent via the Safe Multisig will be counted
        bytes32 functionCallTxHash = hypernativeGuard.getFunctionCallHash(
            address(poolManager),
            0,
            abi.encodeWithSelector(MockPoolManager.pause.selector, address(3)),
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(0)
        );
        vm.stopPrank();
        hypernativeGuard.approveFunctionCallHash(functionCallTxHash);
        vm.startPrank(signer1);
        SigUtils.SafeTx memory safeTx = generatePoolManagerPauseTx(address(1));
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        bytes memory signatures = signTransaction(digest);
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );
        assertTrue(poolManager.poolsStatus(address(1)));

        // now we'll pause another pool using the Same functionCallHash
        safeTx = generatePoolManagerPauseTx(address(2));
        digest = sigUtils.getTypedDataHash(safeTx);
        signatures = signTransaction(digest);
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );
        assertTrue(poolManager.poolsStatus(address(2)));

        vm.stopPrank();
        hypernativeGuard.revokeFunctionCallHash(functionCallTxHash);
        vm.startPrank(signer1);
        safeTx = generatePoolManagerPauseTx(address(3));
        digest = sigUtils.getTypedDataHash(safeTx);
        signatures = signTransaction(digest);
        vm.expectRevert();
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );
    }

    function test_GrantAndRevokeKeeperRole() public {
        testConfigureHypernativeGuard();
        // grant the keeper role to address(1)
        SigUtils.SafeTx memory safeTx = generateGrantKeeperTxToSign(address(1));
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        bytes memory signatures = signTransaction(digest);

        vm.stopPrank();
        hypernativeGuard.approveHash(digest); // approve the add keeper role hash
        // grant the keeper role to address(1)
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );

        // now we can approve hashes using the Safe Multisig

        // should revert because hash wasn't approved yet
        withdrawEthReverts();

        // approve the withdraw hash through the Safe Multisig
        safeTx = generateWithrawTxToSign();
        digest = sigUtils.getTypedDataHash(safeTx);
        signatures = signTransaction(digest);

        // aprove the hash through address(1) which has the keeper role
        vm.prank(address(1));
        hypernativeGuard.approveHash(digest);
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );

        safeTx = generateRevokeKeeperTxToSign();
        digest = sigUtils.getTypedDataHash(safeTx);
        signatures = signTransaction(digest);
        vm.stopPrank();
        hypernativeGuard.approveHash(digest);
        // revoke the keeper role from address(1)
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );

        bytes32 payload = keccak256(abi.encodePacked(address(1), uint256(0)));

        vm.startPrank(address(1));
        vm.expectRevert();
        hypernativeGuard.approveHash(payload);
    }

    function test_PolicyExtension() public {
        testConfigureHypernativeGuard();

        SigUtils.SafeTx memory safeTx = generateAddressZeroTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        bytes32 addressZeroNonceFreeHash = hypernativeGuard.getNonceFreeTransactionHash(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver
        );
        vm.stopPrank();
        hypernativeGuard.approveNonceFreeHash(addressZeroNonceFreeHash);
        vm.startPrank(signer1);
        bytes memory signatures = signTransaction(digest);
        // Tx to address zero should work because the blocking Policy wasn't applied yet
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );

        safeTx = generateAddPolicyTransactionToSign();
        digest = sigUtils.getTypedDataHash(safeTx);
        signatures = signTransaction(digest);
        vm.stopPrank();
        hypernativeGuard.approveHash(digest);
        vm.startPrank(signer1);
        // Add policy

        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );

        // Tx to address zero should revert because the blocking Policy was applied
        // notice: no need to approve the hash because it's a nonce free hash, also the policies are checked before the hash approval
        safeTx = generateAddressZeroTxToSign();
        digest = sigUtils.getTypedDataHash(safeTx);
        signatures = signTransaction(digest);
        vm.expectRevert("Address 0 is not allowed");
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );

        // grant the keeper role to the Safe address
        safeTx = generateGrantKeeperTxToSign(address(safe));
        digest = sigUtils.getTypedDataHash(safeTx);
        vm.stopPrank();
        hypernativeGuard.approveHash(digest);
        signatures = signTransaction(digest);
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );

        // now we'll remove the policy and try again
        vm.startPrank(signer1);
        safeTx = generateRemovePolicyTransactionToSign();
        digest = sigUtils.getTypedDataHash(safeTx);
        signatures = signTransaction(digest);
        vm.stopPrank();
        hypernativeGuard.approveHash(digest);
        vm.startPrank(signer1);
        // policy removed
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );

        address[] memory policyExtensions = hypernativeGuard.getPolicyExtensions();
        assertEq(policyExtensions.length, 0);

        // Tx to address zero should work because the blocking Policy was removed
        safeTx = generateAddressZeroTxToSign();
        digest = sigUtils.getTypedDataHash(safeTx);
        signatures = signTransaction(digest);
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );
    }

    function activateTimelock() internal {
        SigUtils.SafeTx memory safeTx = generateGuardTimelockTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        bytes memory signatures = signTransaction(digest);
        vm.stopPrank();
        //hypernativeGuard.hypernativeApproveHash(digest);
        vm.startPrank(signer1);
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );
    }

    function disableTimelock() internal {
        SigUtils.SafeTx memory safeTx = generateGuardDisableTimelockTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        bytes memory signatures = signTransaction(digest);
        vm.stopPrank();
        vm.startPrank(signer1);
        safe.execTransaction(
            safeTx.to,
            safeTx.value,
            safeTx.data,
            safeTx.operation,
            safeTx.safeTxGas,
            safeTx.baseGas,
            safeTx.gasPrice,
            safeTx.gasToken,
            safeTx.refundReceiver,
            signatures
        );
    }

    function generateAndApproveRevokeGuardTx()
        internal
        returns (SigUtils.SafeTx memory safeTx, bytes memory signatures)
    {
        safeTx = generateRevokeGuardTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        signatures = signTransaction(digest);
        vm.stopPrank();
        hypernativeGuard.approveHash(digest);
        return (safeTx, signatures);
    }

    function generatePoolManagerPauseTx(address _pool) internal view returns (SigUtils.SafeTx memory safeTx) {
        safeTx = SigUtils.SafeTx({
            to: address(poolManager),
            value: 0,
            data: abi.encodeWithSelector(MockPoolManager.pause.selector, _pool),
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(0),
            nonce: safe.nonce()
        });
        return safeTx;
    }

    function generateRevokeGuardTxToSign() internal view returns (SigUtils.SafeTx memory safeTx) {
        safeTx = SigUtils.SafeTx({
            to: address(safe),
            value: 0,
            data: abi.encodeWithSelector(GuardManager.setGuard.selector, address(0)),
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(0),
            nonce: safe.nonce()
        });
        return safeTx;
    }

    function generateGuardTimelockTxToSign() internal view returns (SigUtils.SafeTx memory safeTx) {
        safeTx = SigUtils.SafeTx({
            to: address(hypernativeGuard),
            value: 0,
            data: abi.encodeWithSelector(HypernativeGuard.activateTimelock.selector),
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(0),
            nonce: safe.nonce()
        });
        return safeTx;
    }

    function generateWithrawTxToSign() internal view returns (SigUtils.SafeTx memory safeTx) {
        safeTx = SigUtils.SafeTx({
            to: address(this),
            value: 0.005 ether,
            data: "",
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(0),
            nonce: safe.nonce()
        });
        return safeTx;
    }

    function generateGuardDisableTimelockTxToSign() internal view returns (SigUtils.SafeTx memory safeTx) {
        safeTx = SigUtils.SafeTx({
            to: address(hypernativeGuard),
            value: 0,
            data: abi.encodeWithSelector(HypernativeGuard.disableTimelock.selector),
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(0),
            nonce: safe.nonce()
        });
        return safeTx;
    }

    function generateConfigureGuardTxToSign() internal view returns (SigUtils.SafeTx memory safeTx) {
        safeTx = SigUtils.SafeTx({
            to: address(safe),
            value: 0,
            data: abi.encodeWithSelector(GuardManager.setGuard.selector, address(hypernativeGuard)),
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(0),
            nonce: safe.nonce()
        });
        return safeTx;
    }

    function generateGrantKeeperTxToSign(address _keeper) internal view returns (SigUtils.SafeTx memory safeTx) {
        safeTx = SigUtils.SafeTx({
            to: address(hypernativeGuard),
            value: 0,
            data: abi.encodeWithSelector(HypernativeGuard.grantKeeperRole.selector, address(_keeper)),
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(0),
            nonce: safe.nonce()
        });
        return safeTx;
    }

    function generateRevokeKeeperTxToSign() internal view returns (SigUtils.SafeTx memory safeTx) {
        safeTx = SigUtils.SafeTx({
            to: address(hypernativeGuard),
            value: 0,
            data: abi.encodeWithSelector(HypernativeGuard.revokeKeeperRole.selector, address(1)),
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(0),
            nonce: safe.nonce()
        });
        return safeTx;
    }

    function generateApproveHashTxToSign(bytes32 hash) internal view returns (SigUtils.SafeTx memory safeTx) {
        safeTx = SigUtils.SafeTx({
            to: address(hypernativeGuard),
            value: 0,
            data: abi.encodeWithSelector(HypernativeGuard.approveHash.selector, hash),
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(0),
            nonce: safe.nonce()
        });
        return safeTx;
    }

    function generateAddressZeroTxToSign() internal view returns (SigUtils.SafeTx memory safeTx) {
        safeTx = SigUtils.SafeTx({
            to: address(0),
            value: 0.005 ether,
            data: "",
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(0),
            nonce: safe.nonce()
        });
        return safeTx;
    }

    function generateAddPolicyTransactionToSign() internal view returns (SigUtils.SafeTx memory safeTx) {
        safeTx = SigUtils.SafeTx({
            to: address(hypernativeGuard),
            value: 0,
            data: abi.encodeWithSelector(HypernativeGuard.addPolicyExtension.selector, address(addressZeroNotAllowedPolicy)),
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(0),
            nonce: safe.nonce()
        });
        return safeTx;
    }

    function generateRemovePolicyTransactionToSign() internal view returns (SigUtils.SafeTx memory safeTx) {
        safeTx = SigUtils.SafeTx({
            to: address(hypernativeGuard),
            value: 0,
            data: abi.encodeWithSelector(
                HypernativeGuard.removePolicyExtension.selector, address(addressZeroNotAllowedPolicy)
            ),
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(0),
            nonce: safe.nonce()
        });
        return safeTx;
    }

    function signTransaction(bytes32 digest) internal view returns (bytes memory signatures) {
        for (uint256 i; i < ownerPKs.length; ++i) {
            uint256 pk = ownerPKs[i];
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
            signatures = bytes.concat(signatures, abi.encodePacked(r, s, v));
        }
    }

    function getFunctionSelector(bytes memory data) internal pure returns (bytes memory) {
        bytes memory selector = new bytes(4);
        assembly {
            let value := mload(add(data, 0x20))
            mstore(add(selector, 0x20), value)
        }
        return selector;
    }

    receive() external payable {
        console.log("received payment");
    }
}
