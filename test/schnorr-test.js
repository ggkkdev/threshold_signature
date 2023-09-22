const { expect } = require("chai");
const { ethers } = require("hardhat");

const { randomBytes } = require('crypto')
const secp256k1 = require('secp256k1')
const {Schnorr} = require("../algo/schnorr");
const {arrayify} = require("ethers/lib/utils");

describe("Schnorr", function () {
  it("Should verify a signature", async function () {
    const SchnorrContract = await ethers.getContractFactory("Schnorr");
    const schnorrContract = await SchnorrContract.deploy();
    await schnorrContract.deployed();

    // generate privKey
    let privKey
    do {
      privKey = randomBytes(32)
    } while (!secp256k1.privateKeyVerify(privKey))

    const publicKey = secp256k1.publicKeyCreate(privKey);

    // message
    const m = randomBytes(32);
    const schnorr=new Schnorr()

    var sig = schnorr.sign(m, privKey);

    let gas = await schnorrContract.estimateGas.verify(
      publicKey[0] - 2 + 27,
      publicKey.slice(1, 33),
      arrayify(m),
      sig.e,
      sig.s,
    )
    console.log("verify gas cost:", gas);

    expect(await schnorrContract.verify(
      publicKey[0] - 2 + 27,
      publicKey.slice(1, 33),
      arrayify(m),
      sig.e,
      sig.s,
    )).to.equal(true);
  });
  });
