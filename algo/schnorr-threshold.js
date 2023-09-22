const {ethers} = require("hardhat");

const {randomBytes, randomInt} = require('crypto')
const secp256k1 = require('secp256k1')
const {Polynomial} = require("./components/polynomial");
const {red, BN} = require("./index");
const {arrayify} = require("ethers/lib/utils");
const {Lagrange} = require("./components/lagrange");

class SSS {
    constructor(numParticipants, threshold) {
        this.numParticipants = numParticipants
        this.polynomialSkis = [...Array(numParticipants).keys()].map(e => Polynomial.random(threshold));
        this.pkis = []
        this.kis = []
        this.R = []
        this.k = []
        const xs=[...Array(numParticipants).keys()].map(i=>i+1)
        this.shares = this.generateHxs(xs, this.polynomialSkis)
        this.pkis = this.polynomialSkis.map(pol => secp256k1.publicKeyCreate(pol.evaluate(0).toBuffer()))
        this.pk = secp256k1.publicKeyCombine(this.pkis)
    }

    hx(x, polynomials) {
        let hx = new BN(0).toRed(red)
        polynomials.forEach(poli => {
            hx.redIAdd(poli.evaluate(x))
        })
        return hx;
    }

    generateHxs(xs, polynomials) {
        return  xs.map(e => this.hx(e, polynomials))
    }
    deal(signers) {
        const xs=signers.map(_=>randomBytes(32))
        const kis=  this.generateHxs(xs, signers.map(i=>this.polynomialSkis[i]))
        const lagrange=new Lagrange(signers.map(i=>new BN(i+1).toRed(red)), kis)
        this.k=lagrange.evaluate(new BN(0).toRed(red))
        this.R = secp256k1.publicKeyCreate(this.k.toBuffer())
        this.kis=kis
    }
}

class ThresholdSchnorr {
    constructor(numParticipants, threshold) {
        this.sss = new SSS(numParticipants, threshold)
    }

    thresholdSign(m, signers) {
        this.sss.deal(signers);
        const e = this.challenge(this.sss.R, m);
        const sis = signers.map((el,i) => {
            const signature = this.sign(this.sss.shares[el], this.sss.kis[i], e)
            return new BN(signature.s).toRed(red)
        })
        const lagrange=new Lagrange(signers.map(i=>new BN(i+1).toRed(red)), sis)
        const sig=lagrange.evaluate(new BN(0).toRed(red))
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

module.exports ={ThresholdSchnorr}