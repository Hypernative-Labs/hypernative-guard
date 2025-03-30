// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import "../src/HypernativeGuard.sol";
import {Safe} from "@safe/contracts/Safe.sol";
import {Enum} from "@safe/contracts/libraries/Enum.sol";
import {GuardManager} from "@safe/contracts/base/GuardManager.sol";
import {SigUtils} from "test/SigUtils.sol";

contract HypernativeGuardDeploymentScript is Script {
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
        string memory url = vm.rpcUrl("sepolia");
        string memory safeAddress = vm.env("SAFE_ADDRESS");
        vm.createSelectFork(url);
        safe = Safe(payable());
        _revokingHash = keccak256(
            abi.encode(
                address(safe),
                0,
                keccak256(abi.encodeWithSelector(GuardManager.setGuard.selector, address(0))),
                Enum.Operation.Call,
                0,
                0,
                0,
                address(0),
                payable(0)
            )
        );
        //emit logBytes32(_revokingHash);
    }

    function run() public {
        vm.startBroadcast();
        hypernativeGuard = new HypernativeGuard(payable(address(safe)), _revokingHash);
    }
}
