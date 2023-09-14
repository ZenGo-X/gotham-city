use crate::bitcoin::cli::*;
use crate::ethereum::cli::*;
use clap::builder::Str;
use clap::{arg, Args, Parser, Subcommand};

use client_lib as GothamClient;
use std::error::Error;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use GothamClient::Converter;

use crate::ethereum::{
    create_new_wallet, get_balance, send_transaction, transfer_erc20, ERC20Contract, GothamSigner,
    GothamWallet, TransactionDetails, TransferDetails,
};

use ethers::prelude::*;
use ethers::providers::{Http, Provider};
use ethers::signers::Signer;

use config::{Config, File};
use serde::Deserialize;

use crate::bitcoin::escrow::Escrow;
use crate::bitcoin::BitcoinWallet;
use electrumx_client::electrumx_client::ElectrumxClient;
use std::time::Instant;

pub mod bitcoin;
pub mod ethereum;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub commands: TopLevelSubCommands,
}

#[derive(Subcommand)]
pub enum TopLevelSubCommands {
    ///{n} EVM-compatible blockchains {n}
    /// -------------------------- {n}
    /// Mandatory variables in settings.toml file: {n}
    /// 1. For MPC Gotham wallet: 'rpc_url', 'gotham_wallet_file', 'gotham_server_url' {n}
    /// 2. For locally stored private key: 'rpc_url', 'private_key', 'chain_id' {n}
    Evm(EvmArgs),

    ///{n} Bitcoin blockchain {n}
    /// ------------------ {n}
    Bitcoin(BitcoinArgs),
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub gotham_wallet_file: Option<String>,
    pub rpc_url: Option<String>,
    pub gotham_server_url: Option<String>,

    pub private_key: Option<String>,
    pub chain_id: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::builder()
        .add_source(File::with_name("settings.toml").required(false))
        .add_source(config::Environment::with_prefix("GOTHAM"))
        .build()?;
    let settings = config.try_deserialize::<Settings>().unwrap();

    let cli = Cli::parse();

    match &cli.commands {
        TopLevelSubCommands::Evm(top_args) => match &top_args.commands {
            EvmSubCommands::New(args) => {
                create_new_wallet(
                    settings.gotham_wallet_file.unwrap(),
                    settings.gotham_server_url.unwrap(),
                    args.hd_path.clone(),
                    args.chain_id,
                );
                return Ok(());
            }
            EvmSubCommands::Send(args) => {
                let details = TransactionDetails {
                    to_address: args.to.clone(),
                    amount: args.amount.clone(),
                    gas_limit: args.gas_limit.clone(),
                    gas_price: args.gas_price.clone(),
                    nonce: args.nonce.clone(),
                };

                if top_args.no_mpc {
                    let wallet = settings.private_key.unwrap().parse::<LocalWallet>()?;

                    send_transaction(
                        settings.rpc_url.unwrap(),
                        settings.chain_id.unwrap(),
                        wallet,
                        details,
                    )
                    .await?;
                } else {
                    let signer = GothamSigner {
                        gotham_client_shim: GothamClient::ClientShim::new(
                            settings.gotham_server_url.unwrap(),
                            None,
                        ),
                        wallet: GothamWallet::load(settings.gotham_wallet_file.unwrap()),
                    };

                    send_transaction(
                        settings.rpc_url.unwrap(),
                        signer.chain_id(),
                        signer,
                        details,
                    )
                    .await?;
                }
            }
            EvmSubCommands::Transfer(args) => {
                let details = TransferDetails {
                    contract_address: args.token.clone(),
                    to_address: args.to.clone(),
                    amount: args.amount.clone(),
                    decimals: args.decimals.clone(),
                    gas_limit: args.gas_limit.clone(),
                    gas_price: args.gas_price.clone(),
                    nonce: args.nonce.clone(),
                };

                if top_args.no_mpc == true {
                    let wallet = settings.private_key.unwrap().parse::<LocalWallet>()?;

                    transfer_erc20(
                        settings.rpc_url.unwrap(),
                        settings.chain_id.unwrap(),
                        wallet,
                        details,
                    )
                    .await?;
                } else {
                    let signer = GothamSigner {
                        gotham_client_shim: GothamClient::ClientShim::new(
                            settings.gotham_server_url.unwrap(),
                            None,
                        ),
                        wallet: GothamWallet::load(settings.gotham_wallet_file.unwrap()),
                    };

                    transfer_erc20(
                        settings.rpc_url.unwrap(),
                        signer.chain_id(),
                        signer,
                        details,
                    )
                    .await?;
                }
            }
            EvmSubCommands::Balance(args) => {
                let mut address = Address::zero();
                if top_args.no_mpc == true {
                    address = settings
                        .private_key
                        .clone()
                        .unwrap()
                        .parse::<LocalWallet>()?
                        .address();
                } else {
                    address = GothamWallet::load(settings.gotham_wallet_file.unwrap()).address;
                }

                get_balance(settings.rpc_url.unwrap(), address, args.tokens.clone()).await?;
            }
        },
        TopLevelSubCommands::Bitcoin(top_args) => match &top_args.commands {
            BitcoinSubCommands::CreateWallet(create_wallet) => {
                let client_shim = client_lib::ClientShim::new(create_wallet.gotham.clone(), None);

                println!("Network: [{}], Creating wallet", &create_wallet.network);

                let wallet = BitcoinWallet::new(&client_shim, &create_wallet.network.to_string());
                wallet.save_to(&create_wallet.path);
                println!(
                    "Network: [{}], Wallet saved to disk",
                    &create_wallet.network
                );

                let _escrow = Escrow::new(&create_wallet.escrow_path);
                println!("Network: [{}], Escrow initiated", &create_wallet.network);
            }
            BitcoinSubCommands::Wallet(wallet_command) => {
                println!("Loading wallet from [{}]", wallet_command.path);

                let mut wallet: BitcoinWallet = BitcoinWallet::load_from(&wallet_command.path);

                match &wallet_command.command {
                    WalletCommands::NewAddress(new_address_struct) => {
                        let address = wallet.get_new_bitcoin_address();
                        println!(
                            "Network: [{}], Address: [{}]",
                            &new_address_struct.network,
                            address.to_string()
                        );
                        wallet.save_to(&wallet_command.path);
                    }
                    WalletCommands::GetBalance(get_balance_struct) => {
                        let mut electrum =
                            ElectrumxClient::new(&get_balance_struct.electrum).unwrap();

                        let balance = wallet.get_balance(&mut electrum);
                        println!(
                            "Network: [{}], Balance (in satoshi): [balance: {}, pending: {}] ",
                            &get_balance_struct.network, balance.confirmed, balance.unconfirmed
                        );
                    }
                    WalletCommands::ListUnspent(list_unspent_struct) => {
                        let mut electrum =
                            ElectrumxClient::new(&list_unspent_struct.electrum).unwrap();

                        let unspent = wallet.list_unspent(&mut electrum);
                        let hashes: Vec<String> = unspent.into_iter().map(|u| u.tx_hash).collect();

                        println!(
                            "Network: [{}], Unspent tx hashes: [\n{}\n]",
                            &list_unspent_struct.network,
                            hashes.join("\n")
                        );
                    }
                    WalletCommands::Backup(backup_struct) => {
                        let escrow = Escrow::load(&backup_struct.escrow_path);

                        println!("Backup private share pending (it can take some time)...");

                        let now = Instant::now();
                        wallet.backup(escrow, &backup_struct.backup_path);
                        let elapsed = now.elapsed();

                        println!("Backup key saved in escrow (Took: {:?})", elapsed);
                    }
                    WalletCommands::Verify(verify_struct) => {
                        let escrow = Escrow::load(&verify_struct.escrow_path);

                        println!("verify encrypted backup (it can take some time)...");

                        let now = Instant::now();
                        wallet.verify_backup(escrow, &verify_struct.backup_path);
                        let elapsed = now.elapsed();

                        println!(" (Took: {:?})", elapsed);
                    }
                    /*
                    // recover_master_key was removed from MasterKey2 in version 2.0
                    WalletCommands::Restore => {
                        let escrow = escrow::Escrow::load();

                        println!("backup recovery in process 📲 (it can take some time)...");

                        let now = Instant::now();
                        Wallet::recover_and_save_share(escrow, &network, &client_shim);
                        let elapsed = now.elapsed();

                        println!(" Backup recovered 💾(Took: {:?})", elapsed);
                    },

                     */

                    /* Rotation is not up to date
                    WalletCommands::Rotate => {
                        println!("Rotating secret shares");

                        let now = Instant::now();
                        let wallet = wallet.rotate(&client_shim);
                        wallet.save();
                        let elapsed = now.elapsed();

                        println!("key rotation complete, (Took: {:?})", elapsed);
                    },
                     */
                    WalletCommands::Send(send_struct) => {
                        let client_shim =
                            client_lib::ClientShim::new(send_struct.gotham.clone(), None);

                        let mut electrum = ElectrumxClient::new(&send_struct.electrum).unwrap();

                        let txid = wallet.send(
                            &send_struct.to,
                            send_struct.amount,
                            &client_shim,
                            &mut electrum,
                        );
                        wallet.save_to(&wallet_command.path);
                        println!(
                            "Network: [{}], Sent {} BTC to address {}. Transaction ID: {}",
                            send_struct.network, send_struct.amount, send_struct.to, txid
                        );
                    }
                }
            }
        },
    }

    Ok(())
}

/*

// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use bitcoin::Network;
use clap::{Args, Parser, Subcommand};
use client_lib::escrow;
use client_lib::wallet::Wallet;
use electrumx_client::electrumx_client::ElectrumxClient;
use std::time::Instant;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create an MPC wallet
    CreateWallet(CreateWalletStruct),

    /// Operation on wallet
    #[command(arg_required_else_help = true)]
    Wallet(WalletStruct),
}

const GOTHAM_ARG_HELP: &str = "Gotham server (url:port)";
const GOTHAM_ARG_DEFAULT: &str = "http://127.0.0.1:8000";

const NETWORK_ARG_HELP: &str = "Bitcoin network [bitcoin|testnet|signet|regtest]";
const NETWORK_ARG_DEFAULT: &str = "testnet";

const ELECTRUM_ARG_HELP: &str = "Electrum server (url:port)";

const WALLET_ARG_HELP: &str = "Wallet filepath";
const WALLET_ARG_DEFAULT: &str = "wallet.json";

const BACKUP_ARG_HELP: &str = "Backup filepath";
const BACKUP_ARG_DEFAULT: &str = "backup.json";

const ESCROW_ARG_HELP: &str = "Escrow filepath";
const ESCROW_ARG_DEFAULT: &str = "escrow.json";

#[derive(Args)]
struct CreateWalletStruct {
    #[arg(short, long, help = GOTHAM_ARG_HELP, default_value= GOTHAM_ARG_DEFAULT)]
    gotham: String,

    #[arg(short, long, help = NETWORK_ARG_HELP, default_value= NETWORK_ARG_DEFAULT)]
    network: Network,

    #[arg(short, long, help = WALLET_ARG_HELP, default_value= WALLET_ARG_DEFAULT)]
    path: String,

    #[arg(short, long, help = ESCROW_ARG_HELP, default_value= ESCROW_ARG_DEFAULT)]
    escrow_path: String,
}

#[derive(Args)]
struct WalletStruct {
    #[arg(short, long, help = WALLET_ARG_HELP, default_value= WALLET_ARG_DEFAULT)]
    path: String,

    #[command(subcommand)]
    command: WalletCommands,
}

#[derive(Subcommand)]
enum WalletCommands {
    /// Generate a new address
    NewAddress(NewAddressStruct),

    /// Total balance
    GetBalance(GetBalanceStruct),

    /// List unspent transactions (tx hash)
    ListUnspent(ListUnspentStruct),

    /// Private share backup
    Backup(BackupStruct),

    /// Backup verification
    Verify(VerifyStruct),

    // /// Private share recovery
    // Restore,

    // /// Private shares rotation
    // Rotate,
    /// Send a transaction
    Send(SendStruct),
}

#[derive(Args)]
struct NewAddressStruct {
    #[arg(short, long, help = NETWORK_ARG_HELP, default_value= NETWORK_ARG_DEFAULT)]
    network: Network,
}

#[derive(Args)]
struct ListUnspentStruct {
    #[arg(short, long, help = NETWORK_ARG_HELP, default_value= NETWORK_ARG_DEFAULT)]
    network: Network,

    #[arg(short, long, help = ELECTRUM_ARG_HELP)]
    electrum: String,
}

#[derive(Args)]
struct BackupStruct {
    #[arg(short, long, help = BACKUP_ARG_HELP, default_value= BACKUP_ARG_DEFAULT)]
    backup_path: String,

    #[arg(short, long, help = ESCROW_ARG_HELP, default_value= ESCROW_ARG_DEFAULT)]
    escrow_path: String,
}

#[derive(Args)]
struct VerifyStruct {
    #[arg(short, long, help = BACKUP_ARG_HELP, default_value= BACKUP_ARG_DEFAULT)]
    backup_path: String,

    #[arg(short, long, help = ESCROW_ARG_HELP, default_value= ESCROW_ARG_DEFAULT)]
    escrow_path: String,
}

#[derive(Args)]
struct GetBalanceStruct {
    #[arg(short, long, help = NETWORK_ARG_HELP, default_value= NETWORK_ARG_DEFAULT)]
    network: Network,

    #[arg(short, long, help = ELECTRUM_ARG_HELP)]
    electrum: String,
}

#[derive(Args)]
struct SendStruct {
    #[arg(short, long, help = GOTHAM_ARG_HELP, default_value= GOTHAM_ARG_DEFAULT)]
    gotham: String,

    #[arg(short, long, help = ELECTRUM_ARG_HELP)]
    electrum: String,

    // #[arg(short, long, help = WALLET_ARG_HELP, default_value= WALLET_ARG_DEFAULT)]
    // wallet: String,
    #[arg(short, long, help = NETWORK_ARG_HELP, default_value= NETWORK_ARG_DEFAULT)]
    network: Network,

    #[arg(short, long, help = "Recipient")]
    to: String,

    #[arg(short, long, help = "Amount in BTC")]
    amount: f32,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::CreateWallet(create_wallet) => {
            let client_shim = client_lib::ClientShim::new(create_wallet.gotham.clone(), None);

            println!("Network: [{}], Creating wallet", &create_wallet.network);

            let wallet = Wallet::new(&client_shim, &create_wallet.network.to_string());
            wallet.save_to(&create_wallet.path);
            println!(
                "Network: [{}], Wallet saved to disk",
                &create_wallet.network
            );

            let _escrow = escrow::Escrow::new(&create_wallet.escrow_path);
            println!("Network: [{}], Escrow initiated", &create_wallet.network);
        }
        Commands::Wallet(wallet_command) => {
            println!("Loading wallet from [{}]", wallet_command.path);

            let mut wallet: Wallet = Wallet::load_from(&wallet_command.path);

            match &wallet_command.command {
                WalletCommands::NewAddress(new_address_struct) => {
                    let address = wallet.get_new_bitcoin_address();
                    println!(
                        "Network: [{}], Address: [{}]",
                        &new_address_struct.network,
                        address.to_string()
                    );
                    wallet.save_to(&wallet_command.path);
                }
                WalletCommands::GetBalance(get_balance_struct) => {
                    let mut electrum = ElectrumxClient::new(&get_balance_struct.electrum).unwrap();

                    let balance = wallet.get_balance(&mut electrum);
                    println!(
                        "Network: [{}], Balance (in satoshi): [balance: {}, pending: {}] ",
                        &get_balance_struct.network, balance.confirmed, balance.unconfirmed
                    );
                }
                WalletCommands::ListUnspent(list_unspent_struct) => {
                    let mut electrum = ElectrumxClient::new(&list_unspent_struct.electrum).unwrap();

                    let unspent = wallet.list_unspent(&mut electrum);
                    let hashes: Vec<String> = unspent.into_iter().map(|u| u.tx_hash).collect();

                    println!(
                        "Network: [{}], Unspent tx hashes: [\n{}\n]",
                        &list_unspent_struct.network,
                        hashes.join("\n")
                    );
                }
                WalletCommands::Backup(backup_struct) => {
                    let escrow = escrow::Escrow::load(&backup_struct.escrow_path);

                    println!("Backup private share pending (it can take some time)...");

                    let now = Instant::now();
                    wallet.backup(escrow, &backup_struct.backup_path);
                    let elapsed = now.elapsed();

                    println!("Backup key saved in escrow (Took: {:?})", elapsed);
                }
                WalletCommands::Verify(verify_struct) => {
                    let escrow = escrow::Escrow::load(&verify_struct.escrow_path);

                    println!("verify encrypted backup (it can take some time)...");

                    let now = Instant::now();
                    wallet.verify_backup(escrow, &verify_struct.backup_path);
                    let elapsed = now.elapsed();

                    println!(" (Took: {:?})", elapsed);
                }
                /*
                // recover_master_key was removed from MasterKey2 in version 2.0
                WalletCommands::Restore => {
                    let escrow = escrow::Escrow::load();

                    println!("backup recovery in process 📲 (it can take some time)...");

                    let now = Instant::now();
                    Wallet::recover_and_save_share(escrow, &network, &client_shim);
                    let elapsed = now.elapsed();

                    println!(" Backup recovered 💾(Took: {:?})", elapsed);
                },

                 */

                /* Rotation is not up to date
                WalletCommands::Rotate => {
                    println!("Rotating secret shares");

                    let now = Instant::now();
                    let wallet = wallet.rotate(&client_shim);
                    wallet.save();
                    let elapsed = now.elapsed();

                    println!("key rotation complete, (Took: {:?})", elapsed);
                },
                 */
                WalletCommands::Send(send_struct) => {
                    let client_shim = client_lib::ClientShim::new(send_struct.gotham.clone(), None);

                    let mut electrum = ElectrumxClient::new(&send_struct.electrum).unwrap();

                    let txid = wallet.send(
                        &send_struct.to,
                        send_struct.amount,
                        &client_shim,
                        &mut electrum,
                    );
                    wallet.save_to(&wallet_command.path);
                    println!(
                        "Network: [{}], Sent {} BTC to address {}. Transaction ID: {}",
                        send_struct.network, send_struct.amount, send_struct.to, txid
                    );
                }
            }
        }
    }
}

 */
