use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub struct EvmArgs {
    #[arg(
        long,
        default_value_t = false,
        action,
        help = "Disable MPC Gotham wallet, use a wallet instantiated with a locally stored private key"
    )]
    pub no_mpc: bool,

    #[command(subcommand)]
    pub commands: EvmSubCommands,
}

#[derive(Subcommand)]
pub enum EvmSubCommands {
    /// Create new Gotham EVM wallet
    New(NewEvmWalletArgs),

    /// Broadcast a transaction to the network
    Send(SendEvmWalletArgs),

    /// Broadcast an ERC20 transfer command to the network
    Transfer(TransferEvmWalletArgs),

    /// Retrieve wallet balance
    Balance(BalanceEvmWalletArgs),
}

#[derive(Args)]
pub struct NewEvmWalletArgs {
    #[arg(long, help = "Network's Chain ID")]
    pub chain_id: u64,

    #[arg(
        long,
        use_value_delimiter = true,
        value_delimiter = ',',
        help = "Hierarchical Deterministic path"
    )]
    pub hd_path: Vec<u32>,
}

#[derive(Args)]
pub struct SendEvmWalletArgs {
    #[arg(long, help = "Recipient address")]
    pub to: String,

    #[arg(long, help = "Amount of Wei to transfer (10^18 Wei = 1 ETH)")]
    pub amount: u128,

    #[arg(
        long,
        help = "Maximum amount of gas units this transaction can consume"
    )]
    pub gas_limit: Option<u128>,

    #[arg(
        long,
        help = "Amount of Giga-Wei to pay for gas (10^9 Giga-Wei = 1 ETH)"
    )]
    pub gas_price: Option<u128>,

    #[arg(
        long,
        help = "Sequentially incrementing counter to indicates transaction number"
    )]
    pub nonce: Option<u128>,
}

#[derive(Args)]
pub struct BalanceEvmWalletArgs {
    #[arg(long, help = "ERC20 token addresses")]
    pub tokens: Option<Vec<String>>,
}

#[derive(Args)]
pub struct TransferEvmWalletArgs {
    #[arg(long, help = "ERC20 token address")]
    pub token: String,

    #[arg(long, help = "Recipient address")]
    pub to: String,

    #[arg(long, help = "Amount of tokens to transfer")]
    pub amount: u128,

    #[arg(long, help = "Custom number of decimals to use")]
    pub decimals: Option<u8>,

    #[arg(
        long,
        help = "Maximum amount of gas units this transaction can consume"
    )]
    pub gas_limit: Option<u128>,

    #[arg(
        long,
        help = "Amount of Giga-Wei to pay for gas (10^9 Giga-Wei = 1 ETH)"
    )]
    pub gas_price: Option<u128>,

    #[arg(
        long,
        help = "Sequentially incrementing counter to indicates transaction number"
    )]
    pub nonce: Option<u128>,
}
