// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {HypernativeGuard} from "./HypernativeGuard.sol";

contract HyperNativeGuardFactory is Ownable {
    mapping(address safe => address guard) public getGuard;
    address[] public allGuards;

    event GuardCreated(address indexed safeAddress, address indexed guardAddress);

    function allGuardsLength() external view returns (uint256) {
        return allGuards.length;
    }

    function createGuard(address safe) external onlyOwner returns (address guard) {
        //address guardAddress = address(new HypernativeGuard(safeAddress));
        bytes memory bytecode = type(HypernativeGuard).creationCode;
        bytes32 salt = keccak256(abi.encodePacked(safe));  // need to add randomness
        assembly {
            guard := create2(0, add(bytecode, 32), mload(bytecode), salt)
        }
        getGuard[safe] = guard;
        allGuards.push(guard);
        emit GuardCreated(safe, guard);
    }
}