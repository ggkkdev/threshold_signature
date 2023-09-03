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
        this.polynomialKis = Polynomial.random(threshold);
        //this.polynomialSkis = new Polynomial([new BN(112).toBuffer(), new BN(2).toBuffer()])
        this.skis = []
        this.pkis = []
        this.pres = []
        this.kis = []
        this.Ris = []
        this.R = []
        this.preRis = []

        const _ = [...Array(numParticipants).keys()].forEach(e => {
            const {x, y, pre} = this.generatePolynomialKey(this.polynomialSkis);
            this.skis.push(x);
            this.pkis.push(y)
            this.pres.push(pre)
        })
        const interpolatedPublicKey = this.getInterpolatedPublicKey(this.pres, this.skis)
        this.pk = interpolatedPublicKey.pk
        this.sk = interpolatedPublicKey.sk
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

    getInterpolatedPublicKey(xs, ys) {
        const points = ys.map((e, i) => {
            return {x: xs[i], y: e}
        })
        const lagrange = new Lagrange(points);
        const sharedPrivKey = lagrange.evaluate(new BN(0).toRed(red));
        return {sk: sharedPrivKey, pk: secp256k1.publicKeyCreate(sharedPrivKey.toBuffer())}
    }

    deal() {
        const _ = [...Array(this.numParticipants).keys()].forEach(e => {
            const {x, y, pre} = this.generatePolynomialKey(this.polynomialKis);
            this.kis.push(x);
            this.Ris.push(y)
            this.preRis.push(pre)
        })
        const interpolatedPublicKey = this.getInterpolatedPublicKey(this.preRis, this.kis)
        this.R = interpolatedPublicKey.pk
        //assert(this.R==secp256k1.publicKeyCreate(this.polynomialKis))
    }

    thresholdSign(m) {
        const k=this.polynomialKis.coeffs[0]
        const R=secp256k1.publicKeyCreate(k)
        const e = challenge(R, m);
        const sis = [...Array(this.numParticipants).keys()].map(i => this.sign2(this.skis[i],this.kis[i], e))

        //const sis = [...Array(this.numParticipants).keys()].map((i, e) => this.sign(m, this.skis[i].toBuffer(), this.kis[i].toBuffer(), this.R))
        const points = this.kis.map((e, i) => {
            return {x: this.preRis[i], y: e}
        })
        const lagrangeKis = new Lagrange(points);
        const L = new BN(0).toRed(red)
        this.preRis.forEach((e, i) => L.redIAdd((new BN(sis[i].s)).toRed(red).redMul(lagrangeKis.li(new BN(0).toRed(red), e))));

        return {e: e, s: arrayify(L.toBuffer())};
    }

    thresholdSignTest(m) {
        // e = h(address(R) || m)
        const k=this.polynomialKis.coeffs[0]
        const R=secp256k1.publicKeyCreate(k)
        const e = challenge(R, m);

        // xe = x * e
        const xe = secp256k1.privateKeyTweakMul(this.polynomialSkis.coeffs[0], e);

        // s = k + xe
        const s = secp256k1.privateKeyTweakAdd(k, xe);

        return {e: e, s: s};
    }
    sign2(x, k, e) {
        // xe = x * e
        const xe = secp256k1.privateKeyTweakMul(x.toBuffer(), e);

        // s = k + xe
        const s = secp256k1.privateKeyTweakAdd(k.toBuffer(), xe);
        return {s, e};
    }
    sign(m, x, k, R) {

        // e = h(address(R) || m)
        const e = challenge(R, m);

        // xe = x * e
        const xe = secp256k1.privateKeyTweakMul(x, e);

        // s = k + xe
        const s = secp256k1.privateKeyTweakAdd(k, xe);
        return {R, s, e};
    }

    testInterpolation() {
        const skisPoints = this.skis.map((e, i) => {
            return {x: this.pres[i], y: e}
        })
        const lagrange = new Lagrange(skisPoints);
        const _eval = lagrange.evaluate(new BN(0).toRed(red));
        return _eval;
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
}




function challenge(R, m) {
    // convert R to address
    // see https://github.com/ethereum/go-ethereum/blob/eb948962704397bb861fd4c0591b5056456edd4d/crypto/crypto.go#L275
    var R_uncomp = secp256k1.publicKeyConvert(R, false);
    var R_addr = arrayify(ethers.utils.keccak256(R_uncomp.slice(1, 65))).slice(12, 32);

    // e = keccak256(address(R) || m)
    var e = arrayify(ethers.utils.solidityKeccak256(
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
        //const testPo=new Polynomial([new BN(0).toBuffer(), new BN(2).toBuffer()])
        //testPo.evaluate(0)

        const sss = new SSS(participantsNb, threshold)

        sss.deal();
        const m = randomBytes(32);
        const sig = sss.thresholdSignTest(m)


        //const {coeffs, kis, kisBytes, Ris, R} = deal(participantsNb, threshold);


        // message
        //const e = challenge(R, m);
        //const sis = [...Array(threshold).keys()].map((i, e) => sign(m, keys[i][0], kis[i], R))

        //const polynomialS = new Lagrange(sis);
        //const sig = polynomialS.evaluate(0);

        const publicKey = secp256k1.publicKeyCreate(sss.polynomialSkis.coeffs[0])
        let gas = await schnorr.estimateGas.verify2(
            publicKey[0] - 2 + 27,
            publicKey.slice(1, 33),
            arrayify(m),
            sig.e,
            sig.s,
        )
        console.log("verify gas cost:", gas);

        expect(await schnorr.verify2(
            publicKey[0] - 2 + 27,
            publicKey.slice(1, 33),
            arrayify(m),
            sig.e,
            sig.s,
        )).to.equal(true);
    });
});
