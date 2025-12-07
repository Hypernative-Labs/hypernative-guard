// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import {GuardManager} from "@safe/contracts/base/GuardManager.sol";
import {ISafe} from "@safe/contracts/interfaces/ISafe.sol";
import {Enum} from "@safe/contracts/libraries/Enum.sol";
import {HypernativeGuard} from "../src/HypernativeGuard.sol";
import {SigUtils} from "./SigUtils.sol";
import {MockPoolManager} from "./Mocks/MockPoolManager.sol";
import {AddressZeroNotAllowedPolicy} from "./Mocks/MockPolicies/AddressZeroNotAllowedPolicy.sol";

contract HypernativeGuardTest is Test {
    HypernativeGuard public hypernativeGuard;
    ISafe public safe;
    SigUtils sigUtils;
    MockPoolManager public poolManager;
    AddressZeroNotAllowedPolicy public addressZeroNotAllowedPolicy;
    bytes32 private _changeGuardHash;
    bytes32 private constant OWNERS_SENTINEL_SLOT = 0xe90b7bceb6e7df5418fb78d8ee546e97c83a08bbccc01a0644d599ccd2a7c2e0;

    address internal keeperAddress;
    address internal signer1;
    address internal signer2;
    Vm.Wallet internal newWallet;

    uint256 private _keeperPrivateKey;
    uint256 private _owner1PrivateKey;
    uint256 private _owner2PrivateKey;
    uint256 private _owner3PrivateKey;
    uint256[] private ownerPKs;
    mapping(address => address) private ownerAddresses;

    bytes32 public constant TYPE_HASH = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");

    function setUp() public {
        string memory url = vm.rpcUrl("sepolia");
        vm.selectFork(vm.createFork(url));
        safe = ISafe(payable(0xCFe98FC6d837cccbaF6bCa703652a664a8a59604));
        sigUtils = new SigUtils(safe.domainSeparator());
        // _owner1PrivateKey = vm.envUint("SIGNER1");
        // _owner2PrivateKey = vm.envUint("SIGNER2");
        _owner3PrivateKey = vm.envUint("SIGNER3");
        newWallet = vm.createWallet("MOCK_SIGNER");
        signer1 = newWallet.addr;
        
        

        
        vm.store(address(safe), OWNERS_SENTINEL_SLOT, bytes32(uint256(uint160(signer1))));
        bytes32 newOwnerSlot = keccak256(abi.encode(signer1, 2)); // 2 is the owners sslot
        // new owner in the owners mapping need to point to SENTINEL (0x1) which is the sentinel owner
        vm.store(address(safe), newOwnerSlot, bytes32(uint256(uint160(address(0x1)))));   
        
        ownerPKs.push(newWallet.privateKey);
        
        (keeperAddress, _keeperPrivateKey) = makeAddrAndKey("keeper");
        
        
        // the hash to revoke the guard (using privileged operation hash format)
        vm.deal(keeperAddress, 10 ether);
        vm.startPrank(keeperAddress);
        bytes memory setGuardData = abi.encodeWithSelector(GuardManager.setGuard.selector);
        _changeGuardHash = keccak256(
            abi.encode(
                address(safe),
                0,
                keccak256((setGuardData)),
                Enum.Operation.Call,
                0,
                0,
                0,
                address(0),
                payable(0)
            )
        );

        hypernativeGuard = new HypernativeGuard(address(safe), keeperAddress);
        poolManager = new MockPoolManager(address(safe));
        addressZeroNotAllowedPolicy = new AddressZeroNotAllowedPolicy();
        vm.deal(address(safe), 1 ether);
        vm.startPrank(keeperAddress);
        hypernativeGuard.disablePassThroughMode();
    }

    function test_SendFunds() public {
        (bool success,) = address(safe).call{value: 0.1 ether}("");
        require(success);
    }

    function test_addHashNotKeeperReverts() public {
        vm.stopPrank();
        // now operating as address(this) which doesn't have the keeper role
        vm.expectRevert();
        hypernativeGuard.approveNonceFreeHash(0x0);
    }

    function test_WithdrawEth() public {
        uint256 balanceBefore = address(safe).balance;
        withdrawEth(false);
        assertEq(balanceBefore - 0.005 ether, address(safe).balance);
    }

    function test_WithdrawEthOfflineSigner() public {
        uint256 balanceBefore = address(safe).balance;
        withdrawEth(true);
        assertEq(balanceBefore - 0.005 ether, address(safe).balance);
    }

    function withdrawEth(bool isOfflineSigner) internal {
        SigUtils.SafeTx memory safeTx = generateWithdrawTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        bytes memory signatures;
        if (isOfflineSigner) {
            signatures = signTransactionWithKeeper(digest);
        } else {
            signatures = signTransaction(digest);
        }
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
        SigUtils.SafeTx memory safeTx = generateWithdrawTxToSign();
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

    function test_ConfigureHypernativeGuardAndExecuteWithdrawTx() public {
        testConfigureHypernativeGuard();
        SigUtils.SafeTx memory safeTx = generateWithdrawTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        bytes memory signatures = signTransaction(digest);
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
        SigUtils.SafeTx memory safeTx = generateWithdrawTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        hypernativeGuard.approveHash(digest);
        hypernativeGuard.revokeHash(digest);
        withdrawEthReverts();
    }

    function testRevokeHypernativeGuardRevertsOnTimelockInit() public {
        testConfigureHypernativeGuard();
        (SigUtils.SafeTx memory safeTx, bytes memory signatures) = generateAndApproveRevokeGuardTx();
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
        disableRevokeTimelock();
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
        SigUtils.SafeTx memory safeTx = generateWithdrawTxToSign();
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
        hypernativeGuard.approveNonceFreeHash(nonceFreeHash);
        vm.startPrank(signer1);
        // shouldn't revert because the nonceFreeHash is already approved
        test_WithdrawEth();
        test_WithdrawEth();
        test_WithdrawEth();
    }

    function test_ApproveAndRevokeNonceFree() public {
        testConfigureHypernativeGuard();
        SigUtils.SafeTx memory safeTx = generateWithdrawTxToSign();
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
        
        hypernativeGuard.approveNonceFreeHash(nonceFreeHash);
        
        // shouldn't revert because the nonceFreeHash is already approved
        test_WithdrawEth();
        
        hypernativeGuard.revokeNonceFreeHash(nonceFreeHash);
        
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
        
        hypernativeGuard.approveFunctionCallHash(functionCallTxHash);
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

        // sign the withdraw hash through the Safe Multisig
        safeTx = generateWithdrawTxToSign();
        digest = sigUtils.getTypedDataHash(safeTx);
        signatures = signTransaction(digest);

        // aprove the hash through address(1) which has the keeper role
        vm.stopPrank();
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

        // sign the revoke keeper role hash through the Safe Multisig
        safeTx = generateRevokeKeeperTxToSign();
        digest = sigUtils.getTypedDataHash(safeTx);
        signatures = signTransaction(digest);
        vm.prank(keeperAddress);
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
        hypernativeGuard.approveNonceFreeHash(addressZeroNonceFreeHash);
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
        hypernativeGuard.approveHash(digest);
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
        safeTx = generateRemovePolicyTransactionToSign();
        digest = sigUtils.getTypedDataHash(safeTx);
        signatures = signTransaction(digest);

        hypernativeGuard.approveHash(digest);
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
        SigUtils.SafeTx memory safeTx = generateGuardRevokeTimelockTxToSign();
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

    function disableRevokeTimelock() internal {
        SigUtils.SafeTx memory safeTx = generateGuardDisableRevokeTimelockTxToSign();
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

    function generateAndApproveEnablePassthroughTimelockTx() internal returns (SigUtils.SafeTx memory safeTx, bytes memory signatures) {
        safeTx = generateActivatePassThroughTimelockTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        signatures = signTransaction(digest);
        hypernativeGuard.approveHash(digest);
        return (safeTx, signatures);
    }

    function generateAndApproveRevokeGuardTx()
        internal
        returns (SigUtils.SafeTx memory safeTx, bytes memory signatures)
    {
        safeTx = generateRevokeGuardTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        signatures = signTransaction(digest);
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

    function generateGuardRevokeTimelockTxToSign() internal view returns (SigUtils.SafeTx memory safeTx) {
        safeTx = SigUtils.SafeTx({
            to: address(hypernativeGuard),
            value: 0,
            data: abi.encodeWithSelector(HypernativeGuard.activateRevokeTimelock.selector),
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

    function generateWithdrawTxToSign() internal view returns (SigUtils.SafeTx memory safeTx) {
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

    function generateGuardDisableRevokeTimelockTxToSign() internal view returns (SigUtils.SafeTx memory safeTx) {
        safeTx = SigUtils.SafeTx({
            to: address(hypernativeGuard),
            value: 0,
            data: abi.encodeWithSelector(HypernativeGuard.disableRevokeTimelock.selector),
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

    function generateActivatePassThroughTimelockTxToSign() internal view returns (SigUtils.SafeTx memory safeTx) {
        safeTx = SigUtils.SafeTx({
            to: address(hypernativeGuard),
            value: 0,
            data: abi.encodeWithSelector(HypernativeGuard.activatePassThroughTimelock.selector),
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

    function generateEnablePassThroughTxToSign() internal view returns (SigUtils.SafeTx memory safeTx) {
        safeTx = SigUtils.SafeTx({
            to: address(hypernativeGuard),
            value: 0,
            data: abi.encodeWithSelector(HypernativeGuard.enablePassThroughMode.selector),
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

    function enablePassthroughTimelock() internal {
        SigUtils.SafeTx memory safeTx = generateActivatePassThroughTimelockTxToSign();
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

    function test_EnablePassThroughMode() public {
        
        enablePassthroughTimelock();
        vm.warp(block.timestamp + 2 days);
        (SigUtils.SafeTx memory safeTx, bytes memory signatures) = generateAndApproveEnablePassthroughTimelockTx();
        
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

    function signTransaction(bytes32 digest) internal view returns (bytes memory signatures) {
        for (uint256 i; i < ownerPKs.length; ++i) {
            uint256 pk = ownerPKs[i];
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
            signatures = bytes.concat(signatures, abi.encodePacked(r, s, v));
        }
        bytes32 contextLength;
        bytes memory context;
        bytes memory keeperSignature = new bytes(65);
        signatures = bytes.concat(signatures, keeperSignature, context, contextLength);
    }

    function signTransactionWithKeeper(bytes32 digest) internal view returns (bytes memory signatures) {
        for (uint256 i; i < ownerPKs.length; ++i) {
            uint256 pk = ownerPKs[i];
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
            signatures = bytes.concat(signatures, abi.encodePacked(r, s, v));
        }
        // encoding the keeper signature with some mock context data and context length
        bytes32 contextLength = bytes32(uint256(4));
        bytes memory context = abi.encodeWithSelector(HypernativeGuard.enablePassThroughMode.selector);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_keeperPrivateKey, digest);
        bytes memory keeperSignature = abi.encodePacked(r, s, v);
        signatures = bytes.concat(signatures, keeperSignature, context, contextLength);
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
