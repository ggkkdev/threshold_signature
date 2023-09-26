require("@nomiclabs/hardhat-waffle");

// This is a sample Hardhat task. To learn how to create your own go to
// https://hardhat.org/guides/create-task.html


import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
    solidity: {
        compilers: [
            {
                version: "0.5.15",
            },
            {
                version: "0.6.10",
            },
            {
                version: "0.8.4",
            }],
    }
};

export default config;

