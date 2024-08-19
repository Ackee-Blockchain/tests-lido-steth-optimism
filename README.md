# Tests for Lido StETH on Optimism
This repository serves as an example of tests written in a development and testing framework called [Wake](https://github.com/Ackee-Blockchain/wake).

![horizontal splitter](https://github.com/Ackee-Blockchain/wake-detect-action/assets/56036748/ec488c85-2f7f-4433-ae58-3d50698a47de)

## Setup

1. Clone this repository
2. `git submodule update --init --recursive` if not cloned with `--recursive`
3. `cd source && npm install && cd ..` to install dependencies
4. `wake up pytypes` to generate pytypes
5. `wake test tests` to run tests

Tested with `wake` version `4.11.0` and `anvil` version `anvil 0.2.0 (f2518c9 2024-08-06T00:19:05.446984000Z)`. Fuzz tests expect a local Ethereum mainnet node running at http://localhost:8545.