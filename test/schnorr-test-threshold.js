const {expect} = require("chai");
const {ethers} = require("hardhat");

const {randomBytes, randomInt} = require('crypto')
const {arrayify} = require("ethers/lib/utils");
const {ThresholdSchnorr} = require("../algo/schnorr-threshold");

describe("Schnorr Threshold", function () {
    it("Should verify a signature", async function () {
        const Schnorr = await ethers.getContractFactory("Schnorr");
        const schnorr = await Schnorr.deploy();
        await schnorr.deployed();
        const participantsNb = 5;
        const threshold = 2;
        const thresholdSignature = new ThresholdSchnorr(participantsNb, threshold)
        const m = randomBytes(32);
        const signers = [2, 4]
        const sig = thresholdSignature.thresholdSign(m, signers)
        const publicKey = thresholdSignature.pk

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
