# Demo Wallet
Bitcoin and Ethereum minimalist wallet CLI app on top of Gotham City Client.

## Requirement
Gotham server is required to interact with the client, for instruction on how to run it see [here](../gotham-server/README.md).

## Installation
```bash
git clone https://github.com/ZenGo-X/gotham-city.git
cargo run --bin demo-wallet
```

## Usage
```
Commands:
  evm      EVM-compatible blockchain
  bitcoin  Bitcoin blockchain
  help     Print this message or the help of the given subcommand(s)

Options:
  -s, --settings <SETTINGS>  Settings file [default: settings.toml]
  -h, --help                 Print help
```

## Ethereum Wallet
Configuration variables in settings file:
* __rpc_url__ - endpoint to communicate with the Ethereum network.
* __wallet_file__ - file-path to wallet JSON file `[default: wallet.json]`.
* __gotham_server_url__ - URL to Gotham Server`[default: http://127.0.0.1:8000]`.

### New wallet
Create new MPC EVM wallet

```
Usage: demo-wallet evm new [OPTIONS] --chain-id <CHAIN_ID>

Options:
      --chain-id <CHAIN_ID>  Network Chain ID
  -o, --output <OUTPUT>      Output filepath [default: wallet-ethereum.json]
      --hd-path <HD_PATH>    Hierarchical Deterministic path
  -h, --help                 Print help
```

### Send transaction
Broadcast a transaction to the network

```
Usage: demo-wallet evm send [OPTIONS] --to <TO> --amount <AMOUNT>

Options:
      --to <TO>                Recipient address
      --amount <AMOUNT>        Amount of Wei to transfer (10^18 Wei = 1 ETH)
      --gas-limit <GAS_LIMIT>  Maximum amount of gas units this transaction can consume
      --gas-price <GAS_PRICE>  Amount of Giga-Wei to pay for gas (10^9 Giga-Wei = 1 ETH)
      --nonce <NONCE>          Sequentially incrementing counter to indicates transaction number
  -h, --help                   Print help
```

### Transfer ERC20
Broadcast an ERC20 transfer command to the network

```
Usage: demo-wallet evm transfer [OPTIONS] --token <TOKEN> --to <TO> --amount <AMOUNT>

Options:
      --token <TOKEN>          ERC20 token address
      --to <TO>                Recipient address
      --amount <AMOUNT>        Amount of tokens to transfer
      --decimals <DECIMALS>    Custom number of decimals to use
      --gas-limit <GAS_LIMIT>  Maximum amount of gas units this transaction can consume
      --gas-price <GAS_PRICE>  Amount of Giga-Wei to pay for gas (10^9 Giga-Wei = 1 ETH)
      --nonce <NONCE>          Sequentially incrementing counter to indicates transaction number
  -h, --help                   Print help
```

### See balance
Retrieve wallet balance

```
Usage: demo-wallet evm balance [OPTIONS]

Options:
      --tokens <TOKENS>  ERC20 token addresses seperated by commas
  -h, --help             Print help
```

## Bitcoin Wallet