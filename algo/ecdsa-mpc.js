const paillierBigint = require('paillier-bigint')

const {randomBytes, randomInt} = require('crypto')
const secp256k1 = require('secp256k1')
const {bufToBigint} = require("bigint-conversion");
const {BN, ec, randomBytesVerified, red} = require("./index");
const {Lagrange} = require("./components/lagrange");
const {SSS} = require("./components/nfeldman-keygen");

class ThresholdECDSA {
    constructor(numParticipants, threshold, pailliers) {
        this.pailliers = pailliers
        const {pk, skis, pkis, shares, polynomialSkis}=SSS.keygen(numParticipants, threshold)
        this.pk=pk
        this.skis=skis
        this.pkis=pkis
        this.shares=shares
        this.polynomialSkis=polynomialSkis
    }

    static async build(numParticipants, threshold ) {
        const pailliers = await Promise.all([...Array(numParticipants).keys()].map(async e => {
            const {publicKey, privateKey} = await paillierBigint.generateRandomKeys(1024)
            return {publicKey, privateKey};
        }));
        return new ThresholdECDSA(numParticipants, threshold,pailliers);
    }

    sign(m, signers) {
        const {kis, r, sigmais, R} = this.deal(signers);
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
        const kis = signers.map(_ => new BN(randomBytesVerified(32)).toRed(red))
        const gammais = signers.map(_ => new BN(randomBytesVerified(32)).toRed(red))
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

module.exports ={ThresholdECDSA}