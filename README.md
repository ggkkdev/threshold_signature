# Threshold signatures
This repo try to reproduce threshold signatures. 

The first one is a threshold schnorr signature. 
See the hack used to verify the schnorr signature with ecrecover in See https://hackmd.io/@nZ-twauPRISEa6G9zg3XRw/SyjJzSLt9

The second one is a MPC threshold signature based on https://eprint.iacr.org/2019/114.pdf (verif to do)

### Try it out

Compile:
```
npx hardhat compile
```

Test:
```
npx hardhat test
```

run mocha test with --timeout 100000
