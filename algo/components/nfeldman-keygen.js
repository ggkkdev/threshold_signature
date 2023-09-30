const secp256k1 = require('secp256k1')
const {Polynomial} = require("./polynomial");
const {BN, red} = require("../index");

class SSS {

    /**
     * Key generation with n parallel feldman protocols
     * TODO: add verifiable property
     * @param numParticipants number of participants in the protocol
     * @param threshold number of required participants for a valid signature
     * @returns {{shares, pkis: Uint8Array[], skis: *[], pk: Uint8Array, polynomialSkis: Polynomial[]}} shares
     */
    static keygen(numParticipants, threshold) {
        let polynomialSkis, xs, condition;
        do {
            polynomialSkis = [...Array(numParticipants).keys()].map(e => Polynomial.random(threshold));
            xs = [...Array(numParticipants).keys()].map(i => i + 1)
            let privVerify = polynomialSkis.map(pol => secp256k1.privateKeyVerify(pol.evaluate(0).toBuffer()))
            condition = privVerify.every(v => v === true);
        } while (!condition)
        //const xs = [...Array(numParticipants).keys()].map(i => i + 1)
        const shares = this.generateHxs(xs, polynomialSkis)
        let privVerify = shares.map(e => secp256k1.privateKeyVerify(e.toBuffer()))
        console.log("privverify s"+privVerify)
        const pkis = polynomialSkis.map(pol => secp256k1.publicKeyCreate(pol.evaluate(0).toBuffer()))
        const skis = polynomialSkis.map(pol => pol.evaluate(0))
        const pk = secp256k1.publicKeyCombine(pkis)
        return {pk, skis, pkis, shares, polynomialSkis}
    }

    static hx(x, polynomials) {
        let hx = new BN(0).toRed(red)
        polynomials.forEach(poli => {
            hx.redIAdd(poli.evaluate(x))
        })
        return hx;
    }
    static generateHxs(xs, polynomials) {
        return xs.map(e => this.hx(e, polynomials))
    }

}

module.exports ={SSS}