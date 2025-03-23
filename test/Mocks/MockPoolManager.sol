// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract MockPoolManager is Ownable {
    mapping(address pool => bool isPaused) public poolsStatus;

    constructor(address _owner) Ownable(_owner) {}

    function deposit(uint256 amount) public {
        // do nothing
    }

    function withdraw(uint256 amount) public {
        // do nothing
    }

    function pause(address _pool) public onlyOwner {
        poolsStatus[_pool] = true;
    }

    function unpause(address _pool) public onlyOwner {
        poolsStatus[_pool] = false;
    }
}
