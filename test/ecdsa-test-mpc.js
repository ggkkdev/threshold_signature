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
        this.xs.filter(e => e.toString() != xi.toString()).forEach(e => _li.redIMul(x.redSub(e).redMul(xi.redSub(e).redInvm())))
        return _li;
    }
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
        const xs = [...Array(numParticipants).keys()].map(i => i + 1)
        this.shares = this.generateHxs(xs, this.polynomialSkis)
        this.pkis = this.polynomialSkis.map(pol => secp256k1.publicKeyCreate(pol.evaluate(0).toBuffer()))
        this.skis = this.polynomialSkis.map(pol => pol.evaluate(0))
        this.pk = secp256k1.publicKeyCombine(this.pkis)
        this.pailliers = pailliers
    }

    static async build(numParticipants, threshold) {
        const pailliers = await Promise.all([...Array(numParticipants).keys()].map(async e => {
            const {publicKey, privateKey} = await paillierBigint.generateRandomKeys(1024)
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

    shareConversion(_val1, _val2, key1) {
        let val1 = _val1.clone();
        let val2 = _val2.clone()
        const c1 = key1.publicKey.encrypt(bufToBigint(val1.toBuffer()));
        const betaPrime = bufToBigint(randomBytes(32))
        const c2 = key1.publicKey.addition(key1.publicKey.multiply(c1, bufToBigint(val2.toBuffer())), key1.publicKey.encrypt(betaPrime));
        const alpha = new BN(key1.privateKey.decrypt(c2)).toRed(red)
        const beta = new BN(ec.n).add(new BN(betaPrime).toRed(red).neg()).toRed(red)
        //console.log("Verif share conversion: " + (val1.redMul(val2).toString() == alpha.redAdd(beta).toString()))
        return {
            additiveShare1: alpha, additiveShare2: beta
        }
    }

    deal(signers) {
        const kis = signers.map(_ => new BN(randomBytes(32)).toRed(red))
        const gammais = signers.map(_ => new BN(randomBytes(32)).toRed(red))
        const lagrange = new Lagrange(signers.map(i => new BN(i + 1).toRed(red)), signers.map(i => this.shares[i]))
        const wis = signers.map(e => this.shares[e].redMul(lagrange.li(new BN(0).toRed(red), new BN(e + 1).toRed(red))))
        const pailliers = signers.map(e => this.pailliers[e])
        let conversionsDeltais = [...Array(signers.length)].map(_ => Array(signers.length).fill(0))
        let conversionsSigmais = [...Array(signers.length)].map(_ => Array(signers.length).fill(0))
        signers.forEach((i, indi) => {
            signers.forEach((j, indj) => {
                conversionsDeltais[indi][indj] = this.shareConversion(kis[indi], gammais[indj], pailliers[indi])
                conversionsSigmais[indi][indj] = this.shareConversion(kis[indi], wis[indj], pailliers[indi])
            })
        })
        const deltais = this.multiplicativeToAdditiveProtocol(signers, kis, gammais, conversionsDeltais)
        const sigmais = this.multiplicativeToAdditiveProtocol(signers, kis, wis, conversionsSigmais)
        const delta = deltais.reduce((acc, e) => acc.redAdd(e))
        const Gammais = gammais.map(e => secp256k1.publicKeyCreate(e.toBuffer()))
        const Gamma = secp256k1.publicKeyCombine(Gammais)
        const DeltaMin = secp256k1.publicKeyCreate(delta.redInvm().toBuffer())
        const R = secp256k1.publicKeyTweakMul(Gamma, delta.redInvm().toBuffer())
        const r = R.slice(1, 33)
        return {r, R, kis, gammais, sigmais, delta, Gamma, wis}
    }

    multiplicativeToAdditiveProtocol(signers, firstTerms, secondTerms, conversions) {
        return signers.map(i => {
            let filterSum = new BN(0).toRed(red);
            signers.filter(j => j != i).forEach(j => {
                const share1 = conversions[signers.indexOf(i)][signers.indexOf(j)].additiveShare1.clone()
                const share2 = conversions[signers.indexOf(j)][signers.indexOf(i)].additiveShare2.clone()
                filterSum.redIAdd(share1.redAdd(share2))
            })
            const d = firstTerms[signers.indexOf(i)].redMul(secondTerms[signers.indexOf(i)])
            return filterSum.redAdd(d)
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

    sign(m, signers) {
        const {kis, r, sigmais, R} = this.sss.deal(signers);
        const sis = signers.map((el, i) => this.individualSign(m, kis[i], r, sigmais[i]))
        const s = sis.reduce((acc, e) => acc.redAdd(e));
        return {
            r: "0x" + Buffer.from(r).toString("hex"),
            v: R[0] - 2 + 27,
            s: "0x" + s.toString("hex"),
            recoveryParam: R[0] - 2
        };
    }

    individualSign(m, ki, r, sigmai) {
        return (new BN(m).toRed(red)).redMul(ki).redAdd(new BN(r).toRed(red).redMul(sigmai))
    }
}


describe("ECDSA", function () {
    const participantsNb = 5;
    const threshold = 2;
    const signers = [2, 4]
    const m = randomBytes(32);
    let thresholdSignature, sss, x, owner;
    beforeEach(async function () {
        thresholdSignature= await ThresholdSignature.build(participantsNb, threshold)
        sss = thresholdSignature.sss
        x = sss.skis.reduce((acc, e) => acc.redAdd(e))
        owner = new ethers.Wallet(x.toBuffer(), ethers.getDefaultProvider());
    });

    it("Verify SSS: key interpolation ", async function () {
        const lagrange = new Lagrange(sss.skis.map((_, i) => new BN(i + 1).toRed(red)), sss.skis.map((_, i) => sss.hx(i + 1, sss.polynomialSkis)))
        const evalx = lagrange.evaluate(new BN(0).toRed(red))
        const h0=sss.hx(0, sss.polynomialSkis)
        expect(x.toString()).to.equal(evalx.toString())
        expect(h0.toString() == x.toString())
        expect(new BN(sss.pk).toRed(red).toString(), new BN(secp256k1.publicKeyCreate(x.toBuffer())).toRed(red).toString())
    })

    describe("verify deal", function(){
        const participantsNb = 5;
        const threshold = 2;
        const signers = [2, 4]
        const m = randomBytes(32);
        let thresholdSignature, sss, x, owner, delta, kis, r, sigmais, R, gammais, Gamma, wis, k, gamma, checkkgamma, checksigma, sigma;
        before(async function () {
            thresholdSignature= await ThresholdSignature.build(participantsNb, threshold)
            sss = thresholdSignature.sss
            x = sss.skis.reduce((acc, e) => acc.redAdd(e))
            owner = new ethers.Wallet(x.toBuffer(), ethers.getDefaultProvider());
            const deal = sss.deal(signers);
            [delta, kis, r, sigmais, R, gammais, Gamma, wis]=[deal.delta, deal.kis, deal.r, deal.sigmais, deal.R, deal.gammais, deal.Gamma, deal.wis]
            k = kis.reduce((acc, e) => acc.redAdd(e))
            gamma = gammais.reduce((acc, e) => acc.redAdd(e))
            checkkgamma = signers.reduce((accK, _, i) => accK.redAdd(signers.reduce((accG, _, j) => accG.redAdd(kis[i].redMul(gammais[j])), new BN(0).toRed(red))), new BN(0).toRed(red))
            //const checkkgamma2 = kis.reduce((accK, ki) => accK.redAdd(gammais.reduce((accG, gj) => accG.redAdd(ki.redMul(gj)))))
            checksigma = signers.reduce((accK, _, i) => accK.redAdd(signers.reduce((accG, _, j) => accG.redAdd(kis[i].redMul(wis[j])), new BN(0).toRed(red))), new BN(0).toRed(red))
            sigma = sigmais.reduce((acc, e) => acc.redAdd(e))
        });


        it("Check k*gamma", async function() {
            expect(checkkgamma.toString()).to.equal(delta.toString())
        })
        it("Check k*x", async function() {
            expect(sigma.toString()).to.equal(checksigma.toString())
        })
        it("Check Gamma is Prod Gamma", async function() {
            expect(new BN(secp256k1.publicKeyCreate(gamma.toBuffer())).toString()).to.equal(new BN(Gamma).toString())
        })
        it("Check gamma*deltaMin==kMin", async function() {
            expect(gamma.redMul(delta.redInvm()).toString()).to.equal(k.redInvm().toString())
        })
        it("Check kmin*gammamin=deltamin", async function() {
            expect(delta.redInvm().toString()).to.equal(k.redInvm().redMul(gamma.redInvm()).toString())
        })
        it("Check R=G*kmin", async function() {
            expect(R.toString()).to.equal(secp256k1.publicKeyCreate(k.redInvm().toBuffer()).toString())
        })
        it("Check same but G", async function() {
            expect(new BN(secp256k1.publicKeyCreate(k.redInvm().toBuffer())).toString()).to.equal(new BN(R).toString())
        })
        it("Check R is Kmin", async function() {
            expect(new BN(R).toString()).to.equal(new BN(secp256k1.publicKeyCreate(k.redInvm().toBuffer())).toString())
        })
        //console.log("Check s=k(m+rx) "+(new BN(m).toRed(red).redAdd(new BN(r).toRed(red).redMul(x)).redMul(k).toString()==s.toString()))
    })
    it("Should verify traditional signature with mpc private key", async function(){
        const sign = await owner.signMessage(m)
        const recoveredAddress = ethers.utils.verifyMessage(m, sign);
        expect(recoveredAddress).to.equal(owner.address)
    })

    it("Should verify MPC signature", async function () {
        const sig = thresholdSignature.sign(m, signers)
        const signature = ethers.utils.joinSignature(sig)
        let verified = ethers.utils.recoverAddress(m, signature);
        expect(verified).to.equal(owner.address)
    });
});
