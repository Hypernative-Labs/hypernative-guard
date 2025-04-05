// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import "../src/HypernativeGuard.sol";
import {Safe} from "@safe/contracts/Safe.sol";
import {Enum} from "@safe/contracts/libraries/Enum.sol";
import {GuardManager} from "@safe/contracts/base/GuardManager.sol";
import {SigUtils} from "test/SigUtils.sol";
import "forge-std/Console.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract HypernativeGuardScript is Script {
    bytes32 private _revokingHash;
    Safe safe;
    HypernativeGuard hypernativeGuard;
    SigUtils sigUtils;
    uint256 private _owner3PrivateKey;
    address private signer1;
    uint256[] private ownerPKs;
    mapping(address => address) private ownerAddresses;
    address constant weth = 0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    event logBytes(bytes);

    function setUp() public {
        string memory url = vm.rpcUrl("mainnet");
        vm.createSelectFork(url);
        safe = Safe(payable(0x57eCe8C3c65d125a29da90D8C9e5294Ba2D2e52c));
        sigUtils = new SigUtils(safe.domainSeparator());
        _owner3PrivateKey = vm.envUint("SIGNER3");
        ownerPKs.push(_owner3PrivateKey);
        signer1 = vm.addr(_owner3PrivateKey);
        ownerAddresses[signer1] = signer1;
        //SigUtils.SafeTx memory safeTx = generateWithrawTxToSign();
    }

    function run() public {
        vm.startBroadcast();
        SigUtils.SafeTx memory safeTx = generateTransferTxToSign();
        bytes32 digest = sigUtils.getTypedDataHash(safeTx);
        console.logBytes32(digest);
        bytes memory signatures = signTransaction(digest);
        //safe.execTransaction(safeTx.to, safeTx.value, safeTx.data, safeTx.operation, safeTx.safeTxGas, safeTx.baseGas, safeTx.gasPrice, safeTx.gasToken, safeTx.refundReceiver, signatures);
    }

    function signTransaction(bytes32 digest) internal view returns (bytes memory signatures) {
        for (uint256 i; i < ownerPKs.length; ++i) {
            uint256 pk = ownerPKs[i];
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
            signatures = bytes.concat(signatures, abi.encodePacked(r, s, v));
        }
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

    function generateTransferTxToSign() internal view returns (SigUtils.SafeTx memory safeTx) {
        address benign = address(0x2a98B8E580Dc7FeF13b7A0cE470893831B1EBA69);
        //address malicious = 0x3946c93c3394eA23E438C714092cFC6aB310c7BB;
        bytes memory transferData = abi.encodeWithSelector(ERC20.transfer.selector, benign, 1e6);
        console.logBytes(transferData);
        safeTx = SigUtils.SafeTx({
            to: address(USDC),
            value: 0,
            data: transferData,
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
