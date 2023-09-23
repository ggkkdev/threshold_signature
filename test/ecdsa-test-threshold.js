const {expect} = require("chai");
const {ethers} = require("hardhat");

const {randomBytes, randomInt} = require('crypto')
const secp256k1 = require('secp256k1')
const {ThresholdECDSA} = require("../algo/ecdsa-threshold");
const {red, BN} = require("../algo");
const {Lagrange} = require("../algo/components/lagrange");
const {SSS} = require("../algo/components/nfeldman-keygen");


describe("ECDSA", function () {
    const participantsNb = 5;
    const threshold = 2;
    const signers = [2, 4]
    const m = randomBytes(32);
    let sig;
    let thresholdSignature, x, owner, ecdsa;
    before(async function () {
        thresholdSignature = await ThresholdECDSA.build(participantsNb, threshold)
        sig = thresholdSignature.sign(m, signers)
        x = thresholdSignature.skis.reduce((acc, e) => acc.redAdd(e))
        owner = new ethers.Wallet(x.toBuffer(), ethers.getDefaultProvider());
        const ECDSA = await ethers.getContractFactory("ECDSA");
        ecdsa = await ECDSA.deploy();
        await ecdsa.deployed();
    });

    it("Verify SSS: key interpolation ", async function () {
        const lagrange = new Lagrange(thresholdSignature.skis.map((_, i) => new BN(i + 1).toRed(red)), thresholdSignature.skis.map((_, i) => SSS.hx(i + 1, thresholdSignature.polynomialSkis)))
        const evalx = lagrange.evaluate(new BN(0).toRed(red))
        const h0 = SSS.hx(0, thresholdSignature.polynomialSkis)
        expect(x.toString()).to.equal(evalx.toString())
        expect(h0.toString() == x.toString())
        expect(new BN(thresholdSignature.pk).toRed(red).toString(), new BN(secp256k1.publicKeyCreate(x.toBuffer())).toRed(red).toString())
    })

    it("Should verify traditional signature with mpc private key", async function () {
        const sign = await owner.signMessage(m)
        const recoveredAddress = ethers.utils.verifyMessage(m, sign);
        expect(recoveredAddress).to.equal(owner.address)
    })
    it("Should verify traditional signature  with solidity", async function () {
        const bytes = ethers.utils.arrayify(m);
        const signature = await owner.signMessage(bytes)
        const sig = ethers.utils.splitSignature(signature)
        const messageHash = ethers.utils.hashMessage(bytes);
        expect(await ecdsa.recover(messageHash, sig.v, sig.r, sig.s)).to.equal(owner.address);
    })

    it("Should verify MPC signature", async function () {
        const signature = ethers.utils.joinSignature(sig)
        let verified = ethers.utils.recoverAddress(m, signature);
        expect(verified).to.equal(owner.address)
    });
    it("Should verify MPC signature with solidity", async function () {
        const bytes = ethers.utils.arrayify(m);
        let recovered = await ecdsa.recover(bytes, sig.v, sig.r, sig.s)
        let gas = await ecdsa.estimateGas.recover(bytes, sig.v, sig.r, sig.s)
        console.log("verify gas cost:", gas);
        expect(recovered).to.equal(owner.address);
    });

    describe("verify deal", function () {
        const participantsNb = 5;
        const threshold = 2;
        const signers = [2, 4]
        let thresholdSignature, x, owner, delta, kis, r, sigmais, R, gammais, Gamma, wis, k, gamma, checkkgamma,
            checksigma, sigma;
        before(async function () {
            thresholdSignature = await ThresholdECDSA.build(participantsNb, threshold)
            x = thresholdSignature.skis.reduce((acc, e) => acc.redAdd(e))
            owner = new ethers.Wallet(x.toBuffer(), ethers.getDefaultProvider());
            const deal = thresholdSignature.deal(signers);
            [delta, kis, r, sigmais, R, gammais, Gamma, wis] = [deal.delta, deal.kis, deal.r, deal.sigmais, deal.R, deal.gammais, deal.Gamma, deal.wis]
            k = kis.reduce((acc, e) => acc.redAdd(e))
            gamma = gammais.reduce((acc, e) => acc.redAdd(e))
            checkkgamma = signers.reduce((accK, _, i) => accK.redAdd(signers.reduce((accG, _, j) => accG.redAdd(kis[i].redMul(gammais[j])), new BN(0).toRed(red))), new BN(0).toRed(red))
            checksigma = signers.reduce((accK, _, i) => accK.redAdd(signers.reduce((accG, _, j) => accG.redAdd(kis[i].redMul(wis[j])), new BN(0).toRed(red))), new BN(0).toRed(red))
            sigma = sigmais.reduce((acc, e) => acc.redAdd(e))
        });


        it("Check k*gamma", async function () {
            expect(checkkgamma.toString()).to.equal(delta.toString())
        })
        it("Check k*x", async function () {
            expect(sigma.toString()).to.equal(checksigma.toString())
        })
        it("Check Gamma is Prod Gamma", async function () {
            expect(new BN(secp256k1.publicKeyCreate(gamma.toBuffer())).toString()).to.equal(new BN(Gamma).toString())
        })
        it("Check gamma*deltaMin==kMin", async function () {
            expect(gamma.redMul(delta.redInvm()).toString()).to.equal(k.redInvm().toString())
        })
        it("Check kmin*gammamin=deltamin", async function () {
            expect(delta.redInvm().toString()).to.equal(k.redInvm().redMul(gamma.redInvm()).toString())
        })
        it("Check R=G*kmin", async function () {
            expect(R.toString()).to.equal(secp256k1.publicKeyCreate(k.redInvm().toBuffer()).toString())
        })
        it("Check same but G", async function () {
            expect(new BN(secp256k1.publicKeyCreate(k.redInvm().toBuffer())).toString()).to.equal(new BN(R).toString())
        })
        it("Check R is Kmin", async function () {
            expect(new BN(R).toString()).to.equal(new BN(secp256k1.publicKeyCreate(k.redInvm().toBuffer())).toString())
        })
    })

});
