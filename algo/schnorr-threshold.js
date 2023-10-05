const {ethers} = require("hardhat");

const {randomBytes, randomInt} = require('crypto')
const secp256k1 = require('secp256k1')
const {red, BN} = require("./index");
const {arrayify} = require("ethers/lib/utils");
const {Lagrange} = require("./components/lagrange");
const {SSS} = require("./components/nfeldman-keygen");


class ThresholdSchnorr {
    constructor(numParticipants, threshold) {
        const xs = [...Array(numParticipants).keys()].map(i => i + 1)
        const {pk, skis, pkis, shares, polynomialSkis} = SSS.keygen(xs, threshold)
        this.polynomialSkis = polynomialSkis
        this.shares = shares
        this.pk = pk
        this.numParticipants = numParticipants
        this.threshold = threshold
    }

    deal(signers, polynomialSkis) {
        const xs = signers.map(i => i + 1)
        const dataForKis = SSS.keygen(xs, this.threshold)
        const k = dataForKis.skis.reduce((acc,e)=>acc.redAdd(e))
        const R=dataForKis.pk
        const kis=dataForKis.shares
        return {k, R, kis}
    }


    thresholdSign(m, signers) {
        const {R, k, kis} = this.deal(signers, this.polynomialSkis);
        const e = this.challenge(R, m);
        const sis = signers.map((el, i) => {
            const signature = this.sign(this.shares[el], kis[i], e)
            return new BN(signature.s).toRed(red)
        })
        const lagrange = new Lagrange(signers.map(i => new BN(i + 1).toRed(red)), sis)
        const sig = lagrange.evaluate(new BN(0).toRed(red))
        return {e: e, s: arrayify(sig.toBuffer())};
    }

    sign(x, k, e) {
        // xe = x * e
        const xe = secp256k1.privateKeyTweakMul(x.toBuffer(), e);
        // s = k + xe
        const s = secp256k1.privateKeyTweakAdd(k.toBuffer(), xe);
        return {s, e};
    }

    challenge(R, m) {
        // convert R to address
        // see https://github.com/ethereum/go-ethereum/blob/eb948962704397bb861fd4c0591b5056456edd4d/crypto/crypto.go#L275
        const R_uncomp = secp256k1.publicKeyConvert(R, false);
        const R_addr = arrayify(ethers.utils.keccak256(R_uncomp.slice(1, 65))).slice(12, 32);

        // e = keccak256(address(R) || m)
        const e = arrayify(ethers.utils.solidityKeccak256(
            ["address", "bytes32"],
            [R_addr, m]));
        return e;
    }
}

module.exports = {ThresholdSchnorr}
