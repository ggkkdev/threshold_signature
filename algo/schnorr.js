const {expect} = require("chai");
const {ethers} = require("hardhat");

const {randomBytes} = require('crypto')
const secp256k1 = require('secp256k1')

const arrayify = ethers.utils.arrayify;

class Schnorr {

    sign(m, x) {
        // R = G * k
        const k = randomBytes(32);
        const R = secp256k1.publicKeyCreate(k);

        // e = h(address(R) || compressed pubkey || m)
        const e = this.challenge(R, m);

        // xe = x * e
        const xe = secp256k1.privateKeyTweakMul(x, e);

        // s = k + xe
        const s = secp256k1.privateKeyTweakAdd(k, xe);
        return {R, s, e};
    }

    challenge(R, m) {
        // convert R to address
        // see https://github.com/ethereum/go-ethereum/blob/eb948962704397bb861fd4c0591b5056456edd4d/crypto/crypto.go#L275
        const R_uncomp = secp256k1.publicKeyConvert(R, false);
        const R_addr = arrayify(ethers.utils.keccak256(R_uncomp.slice(1, 65))).slice(12, 32);

        // e = keccak256(address(R) || compressed publicKey || m)
        const e = arrayify(ethers.utils.solidityKeccak256(
            ["address", "bytes32"],
            [R_addr, m]));

        return e;
    }
}
module.exports ={Schnorr}