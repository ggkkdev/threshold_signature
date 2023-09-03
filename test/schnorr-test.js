const { expect } = require("chai");
const { ethers } = require("hardhat");

const BigInteger = require('bigi')
const { randomBytes } = require('crypto')
const secp256k1 = require('secp256k1')

const arrayify = ethers.utils.arrayify;

function sign(m, x) {
  var publicKey = secp256k1.publicKeyCreate(x);

  // R = G * k
  var k = randomBytes(32);
  var R = secp256k1.publicKeyCreate(k);

  // e = h(address(R) || compressed pubkey || m)
  var e = challenge(R, m);

  // xe = x * e
  var xe = secp256k1.privateKeyTweakMul(x, e);

  // s = k + xe
  var s = secp256k1.privateKeyTweakAdd(k, xe);
  return {R, s, e};
}

function challenge(R, m) {
  // convert R to address
  // see https://github.com/ethereum/go-ethereum/blob/eb948962704397bb861fd4c0591b5056456edd4d/crypto/crypto.go#L275
  var R_uncomp = secp256k1.publicKeyConvert(R, false);
  var R_addr = arrayify(ethers.utils.keccak256(R_uncomp.slice(1, 65))).slice(12, 32);

  // e = keccak256(address(R) || compressed publicKey || m)
  var e = arrayify(ethers.utils.solidityKeccak256(
      ["address", "bytes32"],
      [R_addr,  m]));

  return e;
}

describe("Schnorr", function () {
  it("Should verify a signature", async function () {
    const Schnorr = await ethers.getContractFactory("Schnorr");
    const schnorr = await Schnorr.deploy();
    await schnorr.deployed();

    // generate privKey
    let privKey
    do {
      privKey = randomBytes(32)
    } while (!secp256k1.privateKeyVerify(privKey))

    var publicKey = secp256k1.publicKeyCreate(privKey);

    // message
    var m = randomBytes(32);

    var sig = sign(m, privKey);

    let gas = await schnorr.estimateGas.verify2(
      publicKey[0] - 2 + 27,
      publicKey.slice(1, 33),
      arrayify(m),
      sig.e,
      sig.s,
    )
    console.log("verify gas cost:", gas);

    expect(await schnorr.verify2(
      publicKey[0] - 2 + 27,
      publicKey.slice(1, 33),
      arrayify(m),
      sig.e,
      sig.s,
    )).to.equal(true);
  });

  it("compare with addition", async function () {
    const Schnorr = await ethers.getContractFactory("Schnorr");
    const schnorr = await Schnorr.deploy();
    const gas=await schnorr.estimateGas.add(4,5);
    console.log("verify gas cost:", gas);
    expect(await schnorr.add(4,5)).to.equal(9)
  })
  it("compare with mul", async function () {
    const Schnorr = await ethers.getContractFactory("Schnorr");
    const schnorr = await Schnorr.deploy();
    const gas=await schnorr.estimateGas.mult(4,5);
    console.log("verify gas cost:", gas);
    expect(await schnorr.mult(4,5)).to.equal(20)
  })

  });
