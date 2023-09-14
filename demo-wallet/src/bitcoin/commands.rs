use bitcoin::Network;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::time::Instant;
use electrumx_client::electrumx_client::ElectrumxClient;
use crate::bitcoin::BitcoinWallet;
use crate::bitcoin::escrow::Escrow;

#[derive(Args)]
pub struct BitcoinArgs {
    #[command(subcommand)]
    pub commands: BitcoinSubCommands,
}

#[derive(Subcommand)]
pub enum BitcoinSubCommands {
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
pub struct CreateWalletStruct {
    #[arg(short, long, help = GOTHAM_ARG_HELP, default_value= GOTHAM_ARG_DEFAULT)]
    pub gotham: String,

    #[arg(short, long, help = NETWORK_ARG_HELP, default_value= NETWORK_ARG_DEFAULT)]
    pub network: Network,

    #[arg(short, long, help = WALLET_ARG_HELP, default_value= WALLET_ARG_DEFAULT)]
    pub path: String,

    #[arg(short, long, help = ESCROW_ARG_HELP, default_value= ESCROW_ARG_DEFAULT)]
    pub escrow_path: String,
}

#[derive(Args)]
pub struct WalletStruct {
    #[arg(short, long, help = WALLET_ARG_HELP, default_value= WALLET_ARG_DEFAULT)]
    pub path: String,

    #[command(subcommand)]
    pub command: WalletCommands,
}

#[derive(Subcommand)]
pub enum WalletCommands {
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
pub struct NewAddressStruct {
    #[arg(short, long, help = NETWORK_ARG_HELP, default_value= NETWORK_ARG_DEFAULT)]
    pub network: Network,
}

#[derive(Args)]
pub struct ListUnspentStruct {
    #[arg(short, long, help = NETWORK_ARG_HELP, default_value= NETWORK_ARG_DEFAULT)]
    pub network: Network,

    #[arg(short, long, help = ELECTRUM_ARG_HELP)]
    pub electrum: String,
}

#[derive(Args)]
pub struct BackupStruct {
    #[arg(short, long, help = BACKUP_ARG_HELP, default_value= BACKUP_ARG_DEFAULT)]
    pub backup_path: String,

    #[arg(short, long, help = ESCROW_ARG_HELP, default_value= ESCROW_ARG_DEFAULT)]
    pub escrow_path: String,
}

#[derive(Args)]
pub struct VerifyStruct {
    #[arg(short, long, help = BACKUP_ARG_HELP, default_value= BACKUP_ARG_DEFAULT)]
    pub backup_path: String,

    #[arg(short, long, help = ESCROW_ARG_HELP, default_value= ESCROW_ARG_DEFAULT)]
    pub escrow_path: String,
}

#[derive(Args)]
pub struct GetBalanceStruct {
    #[arg(short, long, help = NETWORK_ARG_HELP, default_value= NETWORK_ARG_DEFAULT)]
    pub network: Network,

    #[arg(short, long, help = ELECTRUM_ARG_HELP)]
    pub electrum: String,
}

#[derive(Args)]
pub struct SendStruct {
    #[arg(short, long, help = GOTHAM_ARG_HELP, default_value= GOTHAM_ARG_DEFAULT)]
    pub gotham: String,

    #[arg(short, long, help = ELECTRUM_ARG_HELP)]
    pub electrum: String,

    // #[arg(short, long, help = WALLET_ARG_HELP, default_value= WALLET_ARG_DEFAULT)]
    // wallet: String,
    #[arg(short, long, help = NETWORK_ARG_HELP, default_value= NETWORK_ARG_DEFAULT)]
    pub network: Network,

    #[arg(short, long, help = "Recipient")]
    pub to: String,

    #[arg(short, long, help = "Amount in BTC")]
    pub amount: f32,
}


pub async fn bitcoin_commands(top_args: &BitcoinArgs) -> Result<(), Box<dyn std::error::Error>>{
    match &top_args.commands {
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
    }

    Ok(())
}

