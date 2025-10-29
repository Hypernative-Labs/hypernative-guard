// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import "../src/HypernativeGuard.sol";
import {Safe} from "@safe/contracts/Safe.sol";
import {Enum} from "@safe/contracts/libraries/Enum.sol";
import {GuardManager} from "@safe/contracts/base/GuardManager.sol";
import {SigUtils} from "test/SigUtils.sol";

contract HypernativeGuardDeploymentScript is Script {
    bytes32 private _changeGuardHash;
    Safe safe;
    HypernativeGuard hypernativeGuard;
    HypernativeGuard hypernativeOldGuard;
    SigUtils sigUtils;
    address private signer1;
    uint256[] private ownerPKs;
    mapping(address => address) private ownerAddresses;
    address private keeper;
    address private safeAddress;
    event logBytes32(bytes32);
    event logBytes(bytes);

    function setUp() public {
        string memory url = vm.rpcUrl("mainnet");
        // the Safe we want to protect using the HypernativeGuard
        //safeAddress = 


        // the keeper we want to use to approve the Safe transactions (usually SystemAsset)
        //keeper = 

        vm.createSelectFork(url);
        safe = Safe(payable(safeAddress));

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
        //emit logBytes32(_revokingHash);
    }

    function run() public {
        vm.startBroadcast();
        hypernativeGuard = new HypernativeGuard(payable(address(safe)), _changeGuardHash, keeper);
    }

    function getFunctionSelector(bytes memory data) internal pure returns (bytes memory) {
        bytes memory selector = new bytes(4);
        assembly {
            let value := mload(add(data, 0x20))
            mstore(add(selector, 0x20), value)
        }
        return selector;
    }
}
