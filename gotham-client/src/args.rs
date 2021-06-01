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
    /// Estimates transaction fee per kilobyte for a transaction to be confirmed
    /// within a certain number of blocks
    EstimateFee(BlockNumbers),
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
    #[structopt(short = "a", long, group = "amount")]
    pub amount_btc: Option<Decimal>,
    /// Amount in Satoshi
    #[structopt(short = "s", long, group = "amount")]
    pub amount_satoshi: Option<u64>,

    /// Fee value will be estimated by full node based on desired number of blocks within you want
    /// transaction to be included to the blockchain
    ///
    /// Before sending transaction, you'll be asked for confirmation if estimated fees value works
    /// for you.
    #[structopt(short = "n", long, default_value = "1")]
    pub estimate_fees: usize,

    /// Instructs to subtract fees from sending coins.
    ///
    /// E.g. if you're sending 100 satoshi and estimated fees are 10 satoshi, then recipient will
    /// receive 90 satoshi. By default, fees value is added to transaction cost.
    #[structopt(long)]
    pub subtract_fees: bool,
}

#[derive(Debug, StructOpt)]
pub struct BlockNumbers {
    /// Number of blocks within which transaction should be confirmed
    pub number: usize,
}
