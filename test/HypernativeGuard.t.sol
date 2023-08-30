// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import {console}  from "forge-std/Test.sol";
import  "../src/HypernativeGuard.sol";
import {Safe} from "@safe/contracts/Safe.sol";
import {Enum} from "@safe/contracts/common/Enum.sol";
import {SigUtils} from "./SigUtils.sol";
import {GuardManager} from "@safe/contracts/base/GuardManager.sol";

contract HypernativeGuardTest is Test {
    HypernativeGuard public hypernativeGuard;
    Safe public safe;
    SigUtils sigUtils;
    bytes32 private _revokingHash;

    address internal signer1;
    address internal signer2;
    uint256 private _owner1PrivateKey;
    uint256 private _owner2PrivateKey;
    uint256[] private ownerPKs;
    mapping(address => address) private ownerAddresses;


    bytes32 public constant TYPE_HASH =
        keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");


    function setUp() public {
        safe = Safe(payable(0xfE369f5fb7B4f39040e9C76321CfB2DA620A51d4));
        sigUtils = new SigUtils(safe.domainSeparator());
        _owner1PrivateKey = vm.envUint("SIGNER1");
        _owner2PrivateKey = vm.envUint("SIGNER2");
        ownerPKs.push(_owner1PrivateKey);
        ownerPKs.push(_owner2PrivateKey);
        signer1 = vm.addr(_owner1PrivateKey);
        signer2 = vm.addr(_owner2PrivateKey);
        ownerAddresses[signer1] = signer1 ;
        ownerAddresses[signer2] = signer2;
        // the hash to revoke the guard
        _revokingHash = keccak256(abi.encode(address(safe), 0, keccak256(abi.encodeWithSelector(GuardManager.setGuard.selector, address(0))), Enum.Operation.Call, 0, 0, 0, address(0), payable(0)));
        hypernativeGuard = new HypernativeGuard(payable(safe), _revokingHash);
        vm.startPrank(0x47a0bA6eAB7825a854049eDa62F56301Cf0a7056);
    }

    function testSendFunds() public {
        (bool success,) = payable(safe).call{value: 0.1 ether}("");
        require(success);
    }

    function testWithdrawEth() public {
        uint256 balanceBefore = address(safe).balance;
        withdrawEth();
        assertEq(balanceBefore - 0.005 ether, address(safe).balance);
    }

    function withdrawEth() internal {
        SigUtils.SafeTx memory safeTx = generateWithrawTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        bytes memory signatures = signTransaction(digest);
        safe.execTransaction(safeTx.to, safeTx.value, safeTx.data, safeTx.operation, safeTx.safeTxGas, safeTx.baseGas, safeTx.gasPrice, safeTx.gasToken, safeTx.refundReceiver, signatures);
    }

    function withdrawEthReverts() internal {
        SigUtils.SafeTx memory safeTx = generateWithrawTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        bytes memory signatures = signTransaction(digest);
        vm.expectRevert();
        safe.execTransaction(safeTx.to, safeTx.value, safeTx.data, safeTx.operation, safeTx.safeTxGas, safeTx.baseGas, safeTx.gasPrice, safeTx.gasToken, safeTx.refundReceiver, signatures);
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

    function testConfigureHypernativeGuard() public {
        SigUtils.SafeTx memory safeTx = generateConfigureGuardTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        bytes memory signatures = signTransaction(digest);
        safe.execTransaction(safeTx.to, safeTx.value, safeTx.data, safeTx.operation, safeTx.safeTxGas, safeTx.baseGas, safeTx.gasPrice, safeTx.gasToken, safeTx.refundReceiver, signatures);
    }

    function testConfigureHypernativeGuardAndAbortUnapprovedTx() public {
        testConfigureHypernativeGuard();
        withdrawEthReverts();
    }

    function testConfigureHypernativeGuardAndExecuteWithrawTx() public {
        testConfigureHypernativeGuard();
        SigUtils.SafeTx memory safeTx = generateWithrawTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        bytes memory signatures = signTransaction(digest);
        vm.stopPrank();
        hypernativeGuard.hypernativeApproveHash(digest);
        vm.startPrank(signer1);
        safe.execTransaction(safeTx.to, safeTx.value, safeTx.data, safeTx.operation, safeTx.safeTxGas, safeTx.baseGas, safeTx.gasPrice, safeTx.gasToken, safeTx.refundReceiver, signatures);
    }

    function generateConfigureGuardTxToSign() internal view returns (SigUtils.SafeTx memory safeTx)  {
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

    function testRevokeHypernativeGuardRevertsOnTimelock() public {
        testConfigureHypernativeGuard();
        (SigUtils.SafeTx memory safeTx, bytes memory signatures) = generateAndApproveRevokeGuardTx();
        vm.startPrank(signer1);
        vm.expectRevert("Timelock sequence wasn't initiated");
        safe.execTransaction(safeTx.to, safeTx.value, safeTx.data, safeTx.operation, safeTx.safeTxGas, safeTx.baseGas, safeTx.gasPrice, safeTx.gasToken, safeTx.refundReceiver, signatures);
    }

    function testRevokeHypernativeGuardRevertsOnTimelockStillActive() public {
        testConfigureHypernativeGuard();
        triggerTimelock();
        (SigUtils.SafeTx memory safeTx, bytes memory signatures) = generateAndApproveRevokeGuardTx();
        vm.warp(block.timestamp +  2 days);
        vm.expectRevert();
        safe.execTransaction(safeTx.to, safeTx.value, safeTx.data, safeTx.operation, safeTx.safeTxGas, safeTx.baseGas, safeTx.gasPrice, safeTx.gasToken, safeTx.refundReceiver, signatures);
    }
    
    function generateAndApproveRevokeGuardTx() internal returns (SigUtils.SafeTx memory safeTx, bytes memory signatures) {
        safeTx = generateRevokeGuardTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        signatures = signTransaction(digest);
        vm.stopPrank();
        hypernativeGuard.hypernativeApproveHash(digest); 
        return (safeTx, signatures);
    }



    function testRevokeHypernativeGuardSuccessfuly() public {
        testConfigureHypernativeGuard();
        triggerTimelock();
        (SigUtils.SafeTx memory safeTx, bytes memory signatures) = generateAndApproveRevokeGuardTx();
        vm.warp(block.timestamp +  4 days);
        safe.execTransaction(safeTx.to, safeTx.value, safeTx.data, safeTx.operation, safeTx.safeTxGas, safeTx.baseGas, safeTx.gasPrice, safeTx.gasToken, safeTx.refundReceiver, signatures);
        testWithdrawEth();
    }

    function triggerTimelock() public {
        SigUtils.SafeTx memory safeTx = generateGuardTimeLockTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        bytes memory signatures = signTransaction(digest);
        vm.stopPrank();
        //hypernativeGuard.hypernativeApproveHash(digest);
        vm.startPrank(signer1);
        safe.execTransaction(safeTx.to, safeTx.value, safeTx.data, safeTx.operation, safeTx.safeTxGas, safeTx.baseGas, safeTx.gasPrice, safeTx.gasToken, safeTx.refundReceiver, signatures);

    }

    function generateRevokeGuardTxToSign() internal view returns (SigUtils.SafeTx memory safeTx)  {
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

    function generateGuardTimeLockTxToSign() internal view returns (SigUtils.SafeTx memory safeTx) {
        safeTx = SigUtils.SafeTx({
            to: address(hypernativeGuard),
            value: 0,
            data: abi.encodeWithSelector(HypernativeGuard.triggerTimelock.selector),
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
            signatures = bytes.concat(signatures, abi.encodePacked(r,s,v));
        }
    }

    receive() external payable {
        console.log("received payment");
    }
}
