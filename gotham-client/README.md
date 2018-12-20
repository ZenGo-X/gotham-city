# Gotham Client
## Introduction
Gotham client is a bitcoin minimalist decentralized wallet CLI app.

## Requirement
Gotham server is required to interact with the client, for instruction on how to run it see [here](../gotham-server/README.md).

## Installation
```bash
git clone https://github.com/KZen-networks/gotham-city.git
cd gotham-city/gotham-client
cargo build --release
```

## Using the CLI
```bash
./target/release/cli --help            
```

```text
Command Line Interface for a minimalist decentralized crypto-currency wallet

USAGE:
    cli [FLAGS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v               Sets the level of verbosity

SUBCOMMANDS:
    create-wallet    Create an MPC wallet
    help             Prints this message or the help of the given subcommand(s)
    wallet           Operation on wallet
```

## Wallet creation (required)
```bash
./target/release/cli create-wallet
```

* Output: 
```text
(id: f1025e8f-36c3-4220-8749-ac29d5f17974) Generating master key...
(id: f1025e8f-36c3-4220-8749-ac29d5f17974) Master key gen completed
(id: f1025e8f-36c3-4220-8749-ac29d5f17974) Took: PT1.559251309S
```
## Wallet operations
```bash
./target/release/cli wallet --help
```

```text
Operation on wallet

USAGE:
    cli wallet [FLAGS] [SUBCOMMAND]

FLAGS:
    -e               Wallet private shares backup
    -b               Total balance
    -h, --help       Prints help information
    -u               List unspent transactions (tx hash)
    -a               Generate a new address
    -V, --version    Prints version information

SUBCOMMANDS:
    help    Prints this message or the help of the given subcommand(s)
    send    Send a transaction
```

### Get a derived/new address (HD)
```bash
./target/release/cli wallet -a
```

* Output: 
```text
Network: [testnet], Address: [tb1quxl4c4cyl3586s7tuql7tqqsv233sumxz0588a]
```

### Get total balance
```bash
./target/release/cli wallet -b
```

* Output: 
```text
Network: [testnet], Balance: [balance: 1100000, pending: 0]
```

### Get list unspent
```bash
./target/release/cli wallet -u
```

* Output: 
```text
Network: [testnet], Unspent tx hashes: [
bc32ff53c1b9f71d7a6a5e3f5ec7bc8d20afe50214110a0718c9004be33d57d6
53bc8eca351446f0ec2c13a978243b726a132792305a6758bfc75c67209f9d6b
]
```

### Send a transaction
```bash
./target/release/cli wallet send -t [ADDRESS] -a [BTC_AMOUNT]
```

* Example: 
```bash
./target/debug/cli wallet send -t tb1quxl4c4cyl3586s7tuql7tqqsv233sumxz0588a -a 0.0001
```

* Output: 
```text
TBD
```