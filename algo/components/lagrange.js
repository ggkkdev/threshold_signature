const {BN} = require("../index");

/**
 * Generic lagrange interpolation
 */
class Lagrange {
    constructor(xs, ys) {
        this.xs = xs
        this.ys = ys
    }

    li(x, xi) {
        const _li = new BN(1).toRed(x.red);
        this.xs.filter(e => e.toString() != xi.toString()).forEach(e => _li.redIMul(x.redSub(e).redMul(xi.redSub(e).redInvm())))
        return _li;
    }
    evaluate(x) {
        const {xs, ys} = this;
        const L = new BN(0).toRed(x.red)
        xs.forEach((e, i) => L.redIAdd(ys[i].redMul(this.li(x, e))));
        return L;
    }
}
module.exports ={Lagrange}