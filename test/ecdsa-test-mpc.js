const {expect} = require("chai");
const {ethers} = require("hardhat");
const paillierBigint = require('paillier-bigint')

const {randomBytes, randomInt} = require('crypto')
const secp256k1 = require('secp256k1')
const {bufToBigint, bigintToBuf} = require("bigint-conversion");

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

class Lagrange {
    constructor(xs, ys) {
        this.xs = xs
        this.ys = ys
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

class SSS {
    constructor(numParticipants, threshold, pailliers) {
        this.polynomialSkis = [...Array(numParticipants).keys()].map(e => Polynomial.random(threshold));
        this.pkis = []
        this.kis = []
        this.R = []
        this.k = []
        const xs = [...Array(numParticipants).keys()].map(i => i + 1)
        this.shares = this.generateHxs(xs, this.polynomialSkis)
        this.pkis = this.polynomialSkis.map(pol => secp256k1.publicKeyCreate(pol.evaluate(0).toBuffer()))
        this.pk = secp256k1.publicKeyCombine(this.pkis)
        this.pailliers = pailliers
    }

    static async build(numParticipants, threshold) {
        const pailliers = await Promise.all([...Array(numParticipants).keys()].map(async e => {
            const {publicKey, privateKey} = await paillierBigint.generateRandomKeys(3072)
            return {publicKey, privateKey};
        }));
        return new SSS(numParticipants, threshold, pailliers);
    }

    hx(x, polynomials) {
        let hx = new BN(0).toRed(red)
        polynomials.forEach(poli => {
            hx.redIAdd(poli.evaluate(x))
        })
        return hx;
    }

    generateHxs(xs, polynomials) {
        return xs.map(e => this.hx(e, polynomials))
    }

    shareConversion(val1, val2, key1) {
        const c1 = key1.publicKey.encrypt(bufToBigint(val1.toBuffer()));

        const betaPrime = bufToBigint(randomBytes(32))
        const c2 = key1.publicKey.addition(key1.publicKey.multiply(c1, bufToBigint(val2.toBuffer())), key1.publicKey.encrypt(betaPrime));
        // TODO mod q
        return {additiveShare1: new BN(key1.privateKey.decrypt(c2)), additiveShare2: new BN(bufToBigint(red.m.toBuffer())-betaPrime)}
    }

    deal(signers, keys) {
        this.kis = signers.map(_ => new BN(randomBytes(32)).toRed(red))
        const gammais = signers.map(_ => new BN(randomBytes(32)).toRed(red))
        const lagrange = new Lagrange(signers.map(i => new BN(i + 1).toRed(red)), signers.map(i => this.shares[i]))
        const wis = signers.map(e => this.shares[e].redMul(lagrange.li(new BN(0).toRed(red), new BN(e + 1).toRed(red))))
        const pailliers = signers.map(e => this.pailliers[e])
        let conversionsDeltais = new Array(signers.length).fill(new Array(signers.length-1).fill(0))
        let conversionsSigmais = new Array(signers.length).fill(new Array(signers.length-1).fill(0))
        signers.forEach((i, indi) => {
            signers.filter(j => j != i).forEach((j, indj) => {
                    conversionsDeltais[indi][indj] = this.shareConversion(this.kis[indi], gammais[indj], pailliers[indi])
                    conversionsSigmais[indi][indj] = this.shareConversion(this.kis[indi], wis[indj], pailliers[indi])
                }
            )
        })

        const deltais = this.multiplicativeToAdditiveProtocol(signers, this.kis, gammais, conversionsDeltais)

        this.sigmais = this.multiplicativeToAdditiveProtocol(signers, this.kis, wis, conversionsSigmais)

        const delta = new BN(0).toRed(red);
        deltais.forEach(e => delta.redIAdd(e))
        const Gammais = signers.map((i, indi) => secp256k1.publicKeyCreate(gammais[indi].toBuffer()))
        const Gamma = secp256k1.publicKeyCombine(Gammais)
        const DeltaMin = secp256k1.publicKeyCreate(delta.redInvm().toBuffer())
        this.R = secp256k1.publicKeyCombine([DeltaMin, Gamma])
        this.r = this.R.slice(1, 33)

    }

    multiplicativeToAdditiveProtocol(signers, firstTerms, secondTerms, conversions) {
        return signers.map((i, indi) => {
            let filterSum = new BN(0).toRed(red);
            signers.filter(j => j != i).forEach((j, indj) => {
                const share1 = conversions[indi][indj].additiveShare1.toRed(red)
                const share2 = conversions[indi][indj].additiveShare2.toRed(red)
                filterSum.redIAdd(share1.redAdd(share2))
            })
            return filterSum.redAdd(firstTerms[indi].redMul(secondTerms[indi]))
        })
    }
}

class ThresholdSignature {
    constructor(sss) {
        this.sss = sss;
    }

    static async build(numParticipants, threshold) {
        const sss = await SSS.build(numParticipants, threshold)
        return new ThresholdSignature(sss);
    }

    thresholdSign(m, signers) {
        this.sss.deal(signers);
        const s = new BN(0).toRed(red)
        signers.forEach((el, i) => {
            const si = this.sign(m, this.sss.shares[el], this.sss.kis[i], this.sss.r, this.sss.sigmais[i])
            return s.redIAdd(si);
        })
        return {r:"0x"+Buffer.from(this.sss.r).toString("hex"),v:this.sss.R[0] - 2 + 27, s: "0x"+s.toBuffer().toString("hex"),recoveryParam: this.sss.R[0]-2};
    }

    sign(m, sharei, ki, r, sigmai) {
        return (new BN(m).toRed(red)).redMul(ki).redAdd(new BN(r).toRed(red).redMul(sigmai))
    }
}


describe("ECDSA", function () {
    it("Should verify a signature", async function () {
        const Schnorr = await ethers.getContractFactory("Schnorr");
        const schnorr = await Schnorr.deploy();
        await schnorr.deployed();
        const participantsNb = 5;
        const threshold = 2;
        const thresholdSignature = await ThresholdSignature.build(participantsNb, threshold)
        const m = randomBytes(32);
        const signers = [2, 4]
        const sig = thresholdSignature.thresholdSign(m, signers)
        const publicKey = thresholdSignature.sss.pk
        console.log("signature: " +sig.s.toString())
        const [owner, addr1] = await ethers.getSigners();
        const sign=await owner.signMessage(m)
        const recoveredAddress=await ethers.utils.verifyMessage(m, sign);
        console.log(recoveredAddress==owner.address)
        const signature= ethers.utils.joinSignature(sig)
        let verified = await ethers.utils.verifyMessage(m, signature);
        expect(verified).to.equal("0x"+Buffer.from(publicKey).toString("hex"))


    });
});
