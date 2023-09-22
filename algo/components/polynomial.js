const {randomBytes} = require("ethers/lib/utils");
const {BN, red} = require("../index");

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

module.exports ={Polynomial}