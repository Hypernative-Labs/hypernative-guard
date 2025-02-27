// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script}  from "forge-std/Script.sol";
import  "../src/HypernativeGuard.sol";
import {Safe} from "@safe/contracts/Safe.sol";
import {Enum} from "@safe/contracts/common/Enum.sol";
import {GuardManager} from "@safe/contracts/base/GuardManager.sol";
import {SigUtils} from "test/SigUtils.sol";



contract HypernativeGuardScript is Script {
    bytes32 private _revokingHash;
    Safe safe;
    HypernativeGuard hypernativeGuard;
    HypernativeGuard hypernativeOldGuard;
    SigUtils sigUtils;
    uint256 private _owner3PrivateKey;
    address private signer1;
    uint256[] private ownerPKs;
    mapping(address => address) private ownerAddresses;

    event logBytes32(bytes32);
    event logBytes(bytes);

    

    function setUp() public {
        string memory url = vm.rpcUrl("mainnet");
        vm.createSelectFork(url);
        safe = Safe(payable(0x57eCe8C3c65d125a29da90D8C9e5294Ba2D2e52c));
        _revokingHash = keccak256(abi.encode(address(safe), 0, keccak256(abi.encodeWithSelector(GuardManager.setGuard.selector, address(0))), Enum.Operation.Call, 0, 0, 0, address(0), payable(0)));
        //emit logBytes32(_revokingHash);
        sigUtils = new SigUtils(safe.domainSeparator());
        _owner3PrivateKey = vm.envUint("SIGNER3");
        ownerPKs.push(_owner3PrivateKey);
        //ownerPKs.push(_owner2PrivateKey);
        signer1 = vm.addr(_owner3PrivateKey);
        //signer2 = vm.addr(_owner2PrivateKey);
        ownerAddresses[signer1] = signer1;
    }

    function run() public {
        vm.startBroadcast();
        hypernativeGuard = new HypernativeGuard(payable(address(safe)), _revokingHash);
        SigUtils.SafeTx memory safeTx = generateConfigureGuardTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        //emit logBytes32(digest);
        bytes memory signatures = signTransaction(digest);
        //bytes memory callData = abi.encodeWithSelector(safe.execTransaction.selector, safeTx.to, safeTx.value, safeTx.data, safeTx.operation, safeTx.safeTxGas, safeTx.baseGas, safeTx.gasPrice, safeTx.gasToken, safeTx.refundReceiver, signatures);  
        //emit logBytes(callData);
        //bytes32 nonceFreeHash = hypernativeGuard.getNonceFreeTransactionHash(address(safe), 0, safeTx.data, safeTx.operation, safeTx.safeTxGas, safeTx.baseGas, safeTx.gasPrice, safeTx.gasToken, safeTx.refundReceiver);
        //emit logBytes32(nonceFreeHash);
        safe.execTransaction(safeTx.to, safeTx.value, safeTx.data, safeTx.operation, safeTx.safeTxGas, safeTx.baseGas, safeTx.gasPrice, safeTx.gasToken, safeTx.refundReceiver, signatures);
    }


    function signTransaction(bytes32 digest) internal view returns (bytes memory signatures) {
        for (uint256 i; i < ownerPKs.length; ++i) {
            uint256 pk = ownerPKs[i];
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
            signatures = bytes.concat(signatures, abi.encodePacked(r,s,v));
        }
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
}
