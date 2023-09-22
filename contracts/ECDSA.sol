//SPDX-License-Identifier: LGPLv3
pragma solidity ^0.8.0;

contract ECDSA {
    function recover(bytes32 messageHash, uint8 v, bytes32 r, bytes32 s)
    public
    view
    returns (address)
    {
        return ecrecover(messageHash, v, r, s);
    }
}
