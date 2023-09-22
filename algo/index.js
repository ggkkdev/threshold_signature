const {randomBytes} = require("crypto");
const secp256k1 = require("secp256k1");
const EC = require('elliptic').ec
const ec = new EC('secp256k1')
const ecparams = ec.curve
// Hack, we can not use bn.js@5, while elliptic uses bn.js@4
// See https://github.com/indutny/elliptic/issues/191#issuecomment-569888758
const BN = ecparams.n.constructor
const red = BN.red(ec.n);


randomBytesVerified = (numberBytes) => {
    let bytes;
    do {
        bytes = randomBytes(numberBytes)
    } while (!secp256k1.privateKeyVerify(bytes))
    return bytes;
}

module.exports ={BN, ecparams, ec, EC, red,  randomBytesVerified}