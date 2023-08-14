// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use clap::{Args, Parser, Subcommand, ValueEnum};
use config::Config;
use client_lib::escrow;
use client_lib::wallet::{ElectrumxBalanceFetcher, Wallet};
use std::collections::HashMap;
use std::time::Instant;

const SETTINGS_FILENAME: &str = "../Settings.toml";

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    // #[arg(short, long, help= "Sets the level of verbosity")]
    // verbose: bool,

    #[arg(short, long, help= "Address for electrum address to use. \
    In the format of a socket address (url:port)")]
    network: String,

    #[arg(short, long, help= "Gotham server API endpoint")]
    server: String,

    #[command(subcommand)]
    command: Commands,

}

#[derive(Subcommand)]
enum Commands {
    /// Create an MPC wallet
    CreateWallet(CreateWalletStruct),

    /// Operation on wallet
    #[command(arg_required_else_help = true)]
    Wallet(WalletStruct)
}

#[derive(Args)]
struct CreateWalletStruct {
}

#[derive(Args)]
struct WalletStruct {
    #[command(subcommand)]
    command: WalletCommands,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum WalletMode {
    /// Generate a new address
    NewAddress,

    /// "Total balance"
    GetBalance,

    /// List unspent transactions (tx hash)
    ListUnspent,

    /// Private share backup
    Backup,

    /// Backup verification
    Verify,

    /// Private share recovery
    Restore,

    /// Private shares rotation
    Rotate,
}

#[derive(Subcommand)]
enum WalletCommands {
    /// Generate a new address
    NewAddress,

    /// "Total balance"
    GetBalance,

    /// List unspent transactions (tx hash)
    ListUnspent,

    /// Private share backup
    Backup,

    /// Backup verification
    Verify,

    // /// Private share recovery
    // Restore,

    // /// Private shares rotation
    // Rotate,

    /// Send a transaction
    Send(SendStruct),
}

#[derive(Args)]
struct SendStruct {
    #[arg(short, long, help= "Recipient")]
    to: String,

    #[arg(short, long, help= "Amount in BTC")]
    amount: f32
}

fn main() {
    let cli = Cli::parse();

    // let settings = Config::builder()
    //     .add_source(config::File::with_name(SETTINGS_FILENAME))
    //     .build()
    //     .unwrap();
    //
    // let mut settings = settings
    //     .try_deserialize::<HashMap<String, String>>().unwrap();


    // let endpoint = match_settings_and_cli(
    //     settings.get("server").cloned(), cli.server, "server");
    //
    // let network = match_settings_and_cli(
    //     settings.get("network").cloned(), cli.network,"network");

    let client_shim = client_lib::ClientShim::new(cli.server, None);


    match &cli.command {
        Commands::CreateWallet(create_wallet) => {
            println!("Network: [{}], Creating wallet", &cli.network);

            let wallet = Wallet::new(&client_shim, &cli.network);
            wallet.save();
            println!("Network: [{}], Wallet saved to disk", &cli.network);

            let _escrow = escrow::Escrow::new();
            println!("Network: [{}], Escrow initiated", &cli.network);
        },
        Commands::Wallet(wallet_command) => {
            let mut wallet: Wallet = Wallet::load();

            match &wallet_command.command {
                WalletCommands::NewAddress => {
                    let address = wallet.get_new_bitcoin_address();
                    println!("Network: [{}], Address: [{}]", cli.network, address.to_string());
                    wallet.save();
                },
                WalletCommands::GetBalance => {
                    let mut fetcher = ElectrumxBalanceFetcher::new("ec2-34-219-15-143.us-west-2.compute.amazonaws.com:60001");

                    let balance = wallet.get_balance(&mut fetcher);
                    println!(
                        "Network: [{}], Balance: [balance: {}, pending: {}]",
                        cli.network, balance.confirmed, balance.unconfirmed
                    );
                },
                WalletCommands::ListUnspent => {
                    let unspent = wallet.list_unspent();
                    let hashes: Vec<String> = unspent.into_iter().map(|u| u.tx_hash).collect();

                    println!(
                        "Network: [{}], Unspent tx hashes: [\n{}\n]",
                        cli.network,
                        hashes.join("\n")
                    );
                },
                WalletCommands::Backup => {
                    let escrow = escrow::Escrow::load();

                    println!("Backup private share pending (it can take some time)...");

                    let now = Instant::now();
                    wallet.backup(escrow);
                    let elapsed = now.elapsed();

                    println!("Backup key saved in escrow (Took: {:?})", elapsed);
                },
                WalletCommands::Verify => {
                    let escrow = escrow::Escrow::load();

                    println!("verify encrypted backup (it can take some time)...");

                    let now = Instant::now();
                    wallet.verify_backup(escrow);
                    let elapsed = now.elapsed();

                    println!(" (Took: {:?})", elapsed);
                },
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
                    let mut fetcher = ElectrumxBalanceFetcher::new("ec2-34-219-15-143.us-west-2.compute.amazonaws.com:60001");

                    let txid = wallet.send(
                        &send_struct.to,
                        send_struct.amount,
                        &client_shim,
                        &mut fetcher
                    );
                    wallet.save();
                    println!(
                        "Network: [{}], Sent {} BTC to address {}. Transaction ID: {}",
                        cli.network, send_struct.amount, send_struct.to, txid
                    );
                },
            }

        }
    }
}

fn match_settings_and_cli(settings_cli: Option<String>, cli_str: Option<String>, key_name: &str) -> String {
    let endpoint = match (settings_cli, cli_str) {
        (Some(s), Some(c)) => {
            if s == c {
                s
            } else {
                panic!("{} \"{}\" in {} is different from endpoint \"{}\" in cli",key_name, s, SETTINGS_FILENAME, c);
            }
        },
        (Some(s), None) => s,
        (None, Some(c)) => c,
        (None, None) => {
            panic!("Missing {} value in both {} and cli", key_name, SETTINGS_FILENAME);
        }
    };
    endpoint
}