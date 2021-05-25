use std::path::PathBuf;

use bitcoin::network::constants::Network;
use rust_decimal::Decimal;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "gotham-client",
    about = "Command Line Interface for a minimalist decentralized crypto-currency wallet"
)]
pub struct Args {
    /// Gotham Server address
    #[structopt(long, default_value = "http://localhost:8000", env = "ENDPOINT")]
    pub endpoint: String,

    /// Electrum server address
    #[structopt(
        long,
        default_value = "ec2-34-219-15-143.us-west-2.compute.amazonaws.com:60001",
        env = "ELECTRUM_HOST"
    )]
    pub electrum_host: String,

    /// The cryptocurrency to act on
    #[structopt(long, default_value = "testnet", env = "GOTHAM_NETWORK")]
    pub network: Network,

    /// Path to file with wallet credentials (being created via `cli wallet create`)
    #[structopt(long, default_value = "wallet/wallet.data", env = "ELECTRUM_HOST")]
    pub wallet_file: PathBuf,

    /// Path to file with Escrow secret key (being created via `cli wallet create`)
    #[structopt(long, default_value = "escrow/escrow-sk.json")]
    pub escrow_secret_path: PathBuf,

    #[structopt(subcommand)]
    pub cmd: WalletCommand,
}

#[derive(Debug, StructOpt)]
pub enum WalletCommand {
    /// Create an MPC wallet
    Create,
    /// Generate a new address
    NewAddress,
    /// Retrieves total balance
    GetBalance,
    /// List unspent transactions (tx hash)
    ListUnspent,
    /// Private share backup
    Backup(BackupFile),
    /// Backup verification
    Verify(BackupFile),
    /// Private share recovery
    Restore(BackupFile),
    /// Private shares rotation
    Rotate,
    /// Send a transaction
    Send(SendArgs),
}

#[derive(Debug, StructOpt)]
pub struct BackupFile {
    /// Path to backup file
    #[structopt(long, default_value = "wallet/backup.data")]
    pub backup_file: PathBuf,
}

#[derive(Debug, StructOpt)]
pub struct SendArgs {
    /// Recipient address
    #[structopt(short, long)]
    pub to: String,
    /// Amount in BTC
    #[structopt(short, long, group = "amount")]
    pub amount_btc: Option<Decimal>,
    /// Amount in Satoshi
    #[structopt(short, long, group = "amount")]
    pub amount_satoshi: Option<u64>,
}
