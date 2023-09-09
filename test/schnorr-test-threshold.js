const {expect} = require("chai");
const {ethers} = require("hardhat");

const BigInteger = require('bigi')
const {randomBytes, randomInt} = require('crypto')
const secp256k1 = require('secp256k1')

const EC = require('elliptic').ec

const ec = new EC('secp256k1')
const ecparams = ec.curve


// Hack, we can not use bn.js@5, while elliptic uses bn.js@4
// See https://github.com/indutny/elliptic/issues/191#issuecomment-569888758
const BN = ecparams.n.constructor
const red = BN.red(ec.n);

const arrayify = ethers.utils.arrayify;

class Polynomial {
    constructor(_coeffs = []) {
        this.coeffs = _coeffs;
    }

    static random(_order) {
        return new Polynomial([...Array(_order).keys()].map(e => randomBytes(32)))
    }

    evaluate(x) {
        const redx = new BN(x).toRed(red);
        const _eval = new BN(0).toRed(red);
        this.coeffs.forEach((i, e) => _eval.redIAdd(redx.redPow(new BN(e)).redMul(new BN(i).toRed(red))));
        return _eval;
    }
}

class SSS {
    constructor(numParticipants, threshold) {
        this.numParticipants = numParticipants
        this.polynomialSkis = [...Array(numParticipants).keys()].map(e => Polynomial.random(threshold));
        this.pkis = []
        this.kis = []
        this.R = []
        this.k = []
        //this.skis = this.polynomialSkis.map(pol => pol.evaluate(0).toBuffer())
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

class ThresholdSignature {
    constructor(numParticipants, threshold) {
        this.sss = new SSS(numParticipants, threshold)
        this.numParticipants = numParticipants
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


/**
 * @class Lagrange polynomial interpolation.
 * The computed interpolation polynomial will be referred to as L(x).
 * @example
 * const points = [{x:0, Y:0}, {x:0.5, y:0.8}, {x:1, y:1}];
 * const polynomial = new Lagrange(points);
 * console.log(polynomial.evaluate(0.1));
 */
class Lagrange {
    constructor(xs, ys) {
        this.xs=xs
        this.ys=ys
    }

    li(x, xi) {
        const _li = new BN(1).toRed(red);
        this.xs.filter(e => e != xi).forEach(e => _li.redIMul(x.redSub(e).redMul(xi.redSub(e).redInvm())))
        return _li;
    }

    /**
     * Calculate L(x)
     */
    evaluate(x) {
        const {xs, ys} = this;
        const L = new BN(0).toRed(red)
        xs.forEach((e, i) => L.redIAdd(ys[i].redMul(this.li(x, e))));
        return L;
    }

}


describe("Schnorr", function () {
    it("Should verify a signature", async function () {
        const Schnorr = await ethers.getContractFactory("Schnorr");
        const schnorr = await Schnorr.deploy();
        await schnorr.deployed();
        const participantsNb = 5;
        const threshold = 2;
        const thresholdSignature = new ThresholdSignature(participantsNb, threshold)
        const m = randomBytes(32);
        const signers = [2, 4]
        const sig = thresholdSignature.thresholdSign(m, signers)
        const publicKey = thresholdSignature.sss.pk

        let gas = await schnorr.estimateGas.verify(
            publicKey[0] - 2 + 27,
            publicKey.slice(1, 33),
            arrayify(m),
            sig.e,
            sig.s,
        )
        console.log("verify gas cost:", gas);

        expect(await schnorr.verify(
            publicKey[0] - 2 + 27,
            publicKey.slice(1, 33),
            arrayify(m),
            sig.e,
            sig.s,
        )).to.equal(true);
    });
});
