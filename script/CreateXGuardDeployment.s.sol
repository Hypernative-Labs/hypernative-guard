// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import "../src/HypernativeGuard.sol";
import {Safe} from "@safe/contracts/Safe.sol";
import {Enum} from "@safe/contracts/libraries/Enum.sol";
import {GuardManager} from "@safe/contracts/base/GuardManager.sol";
import {SigUtils} from "test/SigUtils.sol";
import {ICreateX} from "./ICreateX.sol";
import {console2} from "forge-std/console2.sol";

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
    address constant createX = 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;
    ICreateX createXContract = ICreateX(createX);

    function setUp() public {
        string memory url = vm.rpcUrl("sepolia");
        // the Safe we want to protect using the HypernativeGuard
        //safeAddress = 


        // the keeper we want to use to approve the Safe transactions (usually SystemAsset)
        keeper = msg.sender;

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

        
        

        bytes memory initCode = abi.encodePacked(
            type(HypernativeGuard).creationCode,
            abi.encode(address(safe), keeper)
        );

        bytes memory initCode2 = type(HypernativeGuard).creationCode;
        console2.log("initCode2");
        console2.logBytes(initCode2);

        // Create a salt for CREATE2 deployment with CreateX _guard protection
        // Salt format for CreateX:
        // - bytes 0-19: msg.sender (deployer address) - permissioned deployment
        // - byte 20: RedeployProtectionFlag (0x01 = true, DIFFERENT address per chain - replay protection)
        // - bytes 21-31: custom salt data
        uint256 nonce = vm.getNonce(createX);

        bytes32 customSalt = keccak256(abi.encodePacked(safeAddress, keeper, nonce));

        // Build the full salt with msg.sender in first 20 bytes and flag in byte 20
        bytes32 salt = bytes32(abi.encodePacked(
            bytes20(keeper),           // bytes 0-19: msg.sender (permissioned)
            bytes1(0x01),                  // byte 20: RedeployProtectionFlag.True (cross-chain replay protection)
            bytes11(customSalt)            // bytes 21-31: custom salt
        ));

        // CreateX _guard function will process this as:
        // guardedSalt = keccak256(abi.encode(msg.sender, block.chainid, salt))
        bytes32 guardedSalt = keccak256(abi.encode(keeper, block.chainid, salt));

        console2.log("salt");
        console2.logBytes32(salt);

        // Pre-compute the deployment address
        address predictedAddress = createXContract.computeCreate2Address(guardedSalt, keccak256(initCode));
        

        console2.log("Predicted address:", predictedAddress);
        //salt 0xb1dc8de4182acb81122c033b5be3b7ec6d9d0e5b01ae5d8523a8f60b419f9665
        // Deploy the contract
        address deployedAddress = createXContract.deployCreate2(salt, initCode);
        bytes memory callData = abi.encodeWithSelector(createXContract.deployCreate2.selector, guardedSalt, initCode);

        console2.log("callData");
        console2.logBytes(callData);
        console2.log("Deployed address:", deployedAddress);

        // Verify deployment
        require(deployedAddress == predictedAddress, "Address mismatch - deployment failed");
        require(HypernativeGuard(deployedAddress).safeAddress() == safeAddress, "Safe address mismatch");
        //require(HypernativeGuard(deployedAddress).hasRole(HypernativeGuard.KEEPER_ROLE, keeper), "Keeper mismatch");

        vm.stopBroadcast();
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
