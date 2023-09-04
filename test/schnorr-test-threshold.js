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
        this.polynomialSkis = Polynomial.random(threshold);
        this.interpolation = null
        this.skis = []
        this.pkis = []
        this.pres = []
        this.kis = []
        this.Ris = []
        this.R = []
        this.k = []

        const _ = [...Array(numParticipants).keys()].forEach(e => {
            const {x, y, pre} = this.generatePolynomialKey(this.polynomialSkis);
            this.skis.push(x);
            this.pkis.push(y)
            this.pres.push(pre)
        })
        const points = this.skis.map((e, i) => {
            return {x: this.pres[i], y: e}
        })
        this.interpolation = new Lagrange(points);
        this.sk = this.interpolation.evaluate(new BN(0).toRed(red));
        this.pk = secp256k1.publicKeyCreate(this.sk.toBuffer())
    }

    generatePolynomialKey(polynomial) {
        let privKey
        let x
        do {
            x = randomBytes(32)
            privKey = polynomial.evaluate(x).toBuffer();
        } while (!secp256k1.privateKeyVerify(privKey))
        const publicKey = secp256k1.publicKeyCreate(privKey);
        return {x: new BN(privKey).toRed(red), y: new BN(publicKey).toRed(red), pre: new BN(x).toRed(red)}
    }

    getInterpolatedPublicKey(ys) {
        const _eval = this.interpolation.evaluateYs(new BN(0).toRed(red), ys);
        return {sk: _eval, pk: secp256k1.publicKeyCreate(_eval.toBuffer())}
    }

    deal() {
        const _ = [...Array(this.numParticipants).keys()].forEach(e => {
            const {x, y, pre} = this.generatePolynomialKey(this.polynomialSkis);
            this.kis.push(x);
            this.Ris.push(y)
        })
        const interpolatedPublicKey = this.getInterpolatedPublicKey(this.kis)
        this.k = interpolatedPublicKey.sk
        this.R = interpolatedPublicKey.pk
    }
}

class ThresholdSignature {
    constructor(numParticipants, threshold) {
        this.sss = new SSS(numParticipants, threshold)
        this.numParticipants = numParticipants
        this.sss.deal();
    }

    thresholdSign(m) {
        const e = challenge(this.sss.R, m);
        const sis = [...Array(this.numParticipants).keys()].map(i => {
            const signature = this.sign(this.sss.skis[i], this.sss.kis[i], e)
            return new BN(signature.s).toRed(red)
        })
        const sig=this.sss.getInterpolatedPublicKey(sis)
        return {e: e, s: arrayify(sig.sk.toBuffer())};
    }

    sign(x, k, e) {
        // xe = x * e
        const xe = secp256k1.privateKeyTweakMul(x.toBuffer(), e);
        // s = k + xe
        const s = secp256k1.privateKeyTweakAdd(k.toBuffer(), xe);
        return {s, e};
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
    constructor(points) {
        const xs = (this.xs = []);
        const ys = (this.ys = []);
        if (points && points.length) {
            this.k = points.length;
            points.forEach(({x, y}) => {
                xs.push(x);
                ys.push(y);
            });
        }
    }

    li(x, xi) {
        const _li = new BN(1).toRed(red);
        this.xs.filter(e => e != xi).forEach(xm => _li.redIMul(x.redSub(xm).redMul(xi.redSub(xm).redInvm())));
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

    evaluateYs(x, ys) {
        const {xs} = this;
        const L = new BN(0).toRed(red)
        xs.forEach((e, i) => L.redIAdd(ys[i].redMul(this.li(x, e))));
        return L;
    }
}

function challenge(R, m) {
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


describe("Schnorr", function () {
    it("Should verify a signature", async function () {
        const Schnorr = await ethers.getContractFactory("Schnorr");
        const schnorr = await Schnorr.deploy();
        await schnorr.deployed();
        const participantsNb = 5;
        const threshold = 2;
        const thresholdSignature = new ThresholdSignature(participantsNb, threshold)
        const m = randomBytes(32);
        const sig = thresholdSignature.thresholdSign(m)
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
