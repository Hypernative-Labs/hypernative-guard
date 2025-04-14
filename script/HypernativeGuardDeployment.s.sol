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
    uint256 private _owner3PrivateKey;
    address private signer1;
    uint256[] private ownerPKs;
    mapping(address => address) private ownerAddresses;

    event logBytes32(bytes32);
    event logBytes(bytes);

    function setUp() public {
        string memory url = vm.rpcUrl("sepolia");
        address safeAddress = vm.envAddress("SAFE_ADDRESS");
        
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
        hypernativeGuard = new HypernativeGuard(payable(address(safe)), _changeGuardHash, tx.origin);
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
