// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {Enum, Safe}  from "@safe/contracts/Safe.sol";
import {Test} from "forge-std/Test.sol";


contract SigUtils is Test {
    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    // keccak256(
    //     "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
    // );
    bytes32 private constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

     bytes32 internal DOMAIN_SEPARATOR;


    struct SafeTx {
        address to;
        uint256 value;
        bytes data;
        Enum.Operation operation;
        uint256 safeTxGas;
        uint256 baseGas;
        uint256 gasPrice;
        address gasToken;
        address payable refundReceiver;
        uint256 nonce;
    }
    
   
    constructor(bytes32 _DOMAIN_SEPARATOR) {
        DOMAIN_SEPARATOR = _DOMAIN_SEPARATOR;
    }
    // computes the hash of a Safe TX
    function getStructHash(SafeTx memory _safeTx) internal pure returns (bytes32 safeTxHash) {
        safeTxHash = keccak256(
            abi.encode(
                SAFE_TX_TYPEHASH,
                _safeTx.to,
                _safeTx.value,
                keccak256(_safeTx.data),
                _safeTx.operation,
                _safeTx.safeTxGas,
                _safeTx.baseGas,
                _safeTx.gasPrice,
                _safeTx.gasToken,
                _safeTx.refundReceiver,
                _safeTx.nonce
            )
        );
    }

    // computes the hash of the fully encoded EIP-712 message for the domain, which can be used to recover the signer
    function getTypedDataHash(SafeTx memory safeTxToSign) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, getStructHash(safeTxToSign)));
    }
}
