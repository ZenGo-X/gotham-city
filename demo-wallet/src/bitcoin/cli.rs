use bitcoin::Network;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

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
