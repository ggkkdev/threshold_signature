const {expect} = require("chai");
const {ethers} = require("hardhat");
const paillierBigint = require('paillier-bigint')

const {randomBytes, randomInt} = require('crypto')
const secp256k1 = require('secp256k1')
const {bufToBigint, bigintToBuf} = require("bigint-conversion");
const {recoverPublicKey, arrayify, hashMessage} = require("ethers/lib/utils");

const EC = require('elliptic').ec

const ec = new EC('secp256k1')
const ecparams = ec.curve


// Hack, we can not use bn.js@5, while elliptic uses bn.js@4
// See https://github.com/indutny/elliptic/issues/191#issuecomment-569888758
const BN = ecparams.n.constructor
const red = BN.red(ec.n);
let dd = {}
let cc = {}

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
        this.skis = this.polynomialSkis.map(pol => pol.evaluate(0))
        const lagrange = new Lagrange(this.skis.map((_, i) => new BN(i + 1).toRed(red)), this.skis.map((_, i) => this.hx(i + 1, this.polynomialSkis)))
        const evalx = lagrange.evaluate(new BN(0).toRed(red))
        this.x = this.skis.reduce((acc, e) => acc.redAdd(e))
        console.log(this.x.toString() == evalx.toString())
        console.log(this.hx(0, this.polynomialSkis).toString() == this.x.toString())
        this.pk = secp256k1.publicKeyCombine(this.pkis)
        console.log(new BN(this.pk).toRed(red).toString() == new BN(secp256k1.publicKeyCreate(this.x.toBuffer())).toRed(red).toString())
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

    shareConversion(_val1, _val2, key1) {
        let val1=_val1.clone();
        let val2=_val2.clone()
        const c1 = key1.publicKey.encrypt(bufToBigint(val1.toBuffer()));
        const betaPrime = bufToBigint(randomBytes(32))
        const c2 = key1.publicKey.addition(key1.publicKey.multiply(c1, bufToBigint(val2.toBuffer())), key1.publicKey.encrypt(betaPrime));
        const alpha = new BN(key1.privateKey.decrypt(c2)).toRed(red)
        const beta = new BN(ec.n).add(new BN(betaPrime).toRed(red).neg()).toRed(red)
        console.log("verifShare")
        console.log(val1.redMul(val2).toString() == alpha.redAdd(beta).toString())
        return {
            additiveShare1: alpha, additiveShare2: beta
        }
    }

    deal(signers, keys) {
        this.kis = signers.map(_ => new BN(randomBytes(32)).toRed(red))
        this.k = this.kis.reduce((acc, e) => acc.redAdd(e))
        const gammais = signers.map(_ => new BN(randomBytes(32)).toRed(red))
        this.gamma = gammais.reduce((acc, e) => acc.redAdd(e))
        const lagrange = new Lagrange(signers.map(i => new BN(i + 1).toRed(red)), signers.map(i => this.shares[i]))
        //console.log(lagrange.evaluate(new BN(0).toRed(red)).toString() == this.x.toString())
        const wis = signers.map(e => this.shares[e].redMul(lagrange.li(new BN(0).toRed(red), new BN(e + 1).toRed(red))))
        //console.log(wis.reduce((acc, e) => acc.redAdd(e)).toString() == this.x.toString())
        const pailliers = signers.map(e => this.pailliers[e])
        let conversionsDeltais = [...Array(signers.length)].map(_=>Array(signers.length).fill(0))
        let conversionsSigmais = [...Array(signers.length)].map(_=>Array(signers.length).fill(0))
        const checkkgamma2 = new BN(0).toRed(red)
        const checksigma = new BN(0).toRed(red)
        signers.forEach((i, indi) => {
            console.log("player " + i)
            signers.forEach((j, indj) => {
                conversionsDeltais[indi][indj] = this.shareConversion(this.kis[indi], gammais[indj], pailliers[indi])
                conversionsSigmais[indi][indj] = this.shareConversion(this.kis[indi], wis[indj], pailliers[indi])
                checkkgamma2.redIAdd(this.kis[indi].redMul(gammais[indj]))
                checksigma.redIAdd(this.kis[indi].redMul(wis[indj]))
            })
        })
        const deltais = this.multiplicativeToAdditiveProtocol(signers, this.kis, gammais, conversionsDeltais)
        this.sigmais = this.multiplicativeToAdditiveProtocol(signers, this.kis, wis, conversionsSigmais)

        const delta = deltais.reduce((acc, e) => acc.redAdd(e))
        const sigma = this.sigmais.reduce((acc, e) => acc.redAdd(e))

        console.log("Check k*gamma "+(delta.toString() == checkkgamma2.toString()))
        console.log("Check k*x "+(sigma.toString() == checksigma.toString()))

        //console.log(this.sigmais.reduce((acc, e) => acc.redAdd(e)).toString()==this.gamma.redMul(this.k))
        const Gammais = gammais.map(e => secp256k1.publicKeyCreate(e.toBuffer()))
        const Gamma = secp256k1.publicKeyCombine(Gammais)
        console.log("Check Gamma is Prod Gamma "+(new BN(secp256k1.publicKeyCreate(this.gamma.toBuffer())).toString()==new BN(Gamma).toString()))
        console.log("Check gamma*deltaMin==kMin "+(this.gamma.redMul(delta.redInvm()).toString()==this.k.redInvm().toString()))
        const DeltaMin = secp256k1.publicKeyCreate(delta.redInvm().toBuffer())
        console.log("Check kmin*gammamin=deltamin "+(delta.redInvm().toString()==this.k.redInvm().redMul(this.gamma.redInvm()).toString()))
        const R = secp256k1.publicKeyCombine([DeltaMin, Gamma])
        this.R=secp256k1.publicKeyCreate(this.k.redInvm().toBuffer())
        //TODO check why combine here dont work
        console.log("Check same but G "+(new BN(secp256k1.publicKeyCreate(this.k.redInvm().toBuffer())).toString()==new BN(this.R).toString()))
        console.log("Check R is Kmin "+(new BN(this.R).toString()==new BN(secp256k1.publicKeyCreate(this.k.redInvm().toBuffer())).toString()))
        this.r = this.R.slice(1, 33)
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

    thresholdSign(m, signers) {
        this.sss.deal(signers);
        const sis=signers.map((el, i) => this.sign(m, this.sss.kis[i], this.sss.r, this.sss.sigmais[i]))
        const s =sis.reduce((acc,e)=> acc.redAdd(e));
        console.log("Check s=k(m+rx) "+(new BN(m).toRed(red).redAdd(new BN(this.sss.r).toRed(red).redMul(this.sss.x)).redMul(this.sss.k).toString()==s.toString()))
        return {
            r: "0x" + Buffer.from(this.sss.r).toString("hex"),
            v: this.sss.R[0] - 2 + 27,
            s: "0x" + s.toString("hex"),
            recoveryParam: this.sss.R[0] - 2
        };
    }

    sign(m, ki, r, sigmai) {
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
        console.log("signature: " + sig.s.toString())
        //const [owner, addr1] = await ethers.getSigners();
        const owner=new ethers.Wallet(thresholdSignature.sss.x.toBuffer(), ethers.getDefaultProvider());
        const sign = await owner.signMessage(m)
        const recoveredAddress = await ethers.utils.verifyMessage(m, sign);
        console.log(recoveredAddress == owner.address)
        const signature = ethers.utils.joinSignature(sig)
        let verified = await ethers.utils.recoverAddress(m, signature);
        //let pubKey = recoverPublicKey(arrayify(hashMessage(arrayify(m))), sign);
        const pk = "0x" + Buffer.from(publicKey).toString("hex")
        expect(verified).to.equal(owner.address)


    });
});
