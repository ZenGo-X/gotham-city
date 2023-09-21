use crate::ethereum::{
    create_new_wallet, get_balance, send_transaction, transfer_erc20, GothamSigner, GothamWallet,
    TransactionDetails, TransferDetails,
};
use crate::Settings;
use clap::{Args, Subcommand};
use ethers::prelude::{Address, LocalWallet, Signer};


use client_lib as GothamClient;

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
    /// Create new MPC EVM wallet
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
    #[arg(long, help = "Network Chain ID")]
    pub chain_id: u64,

    #[arg(short, long, help = "Output filepath", default_value = "wallet.json")]
    pub output: String,

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

    #[arg(long, help = "Amount of ETH to transfer")]
    pub amount: f64,

    #[arg(
        long,
        help = "Maximum amount of gas units this transaction can consume"
    )]
    pub gas_limit: Option<u128>,

    #[arg(
        long,
        help = "Amount of Giga-Wei to pay for gas (10^9 Giga-Wei = 1 ETH)"
    )]
    pub gas_price: Option<f64>,

    #[arg(
        long,
        help = "Sequentially incrementing counter to indicates transaction number"
    )]
    pub nonce: Option<u128>,
}

#[derive(Args)]
pub struct BalanceEvmWalletArgs {
    #[arg(
        long,
        use_value_delimiter = true,
        value_delimiter = ',',
        help = "ERC20 token addresses seperated by commas"
    )]
    pub tokens: Option<Vec<String>>,
}

#[derive(Args)]
pub struct TransferEvmWalletArgs {
    #[arg(long, help = "ERC20 token address")]
    pub token: String,

    #[arg(long, help = "Recipient address")]
    pub to: String,

    #[arg(long, help = "Amount of tokens to transfer")]
    pub amount: f64,

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
    pub gas_price: Option<f64>,

    #[arg(
        long,
        help = "Sequentially incrementing counter to indicates transaction number"
    )]
    pub nonce: Option<u128>,
}

pub async fn evm_commands(
    settings: Settings,
    top_args: &EvmArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    match &top_args.commands {
        EvmSubCommands::New(args) => {
            create_new_wallet(
                args.output.clone(),
                settings
                    .gotham_server_url
                    .expect("Missing 'gotham_server_url' in settings.toml"),
                args.hd_path.clone(),
                args.chain_id,
            );
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
                let wallet = settings
                    .private_key
                    .expect("Missing 'private_key' in settings.toml")
                    .parse::<LocalWallet>()?;

                send_transaction(
                    settings
                        .rpc_url
                        .expect("Missing 'rpc_url' in settings.toml"),
                    settings
                        .chain_id
                        .expect("Missing 'chain_id' in settings.toml"),
                    wallet,
                    details,
                )
                .await?;
            } else {
                let signer = GothamSigner {
                    gotham_client_shim: GothamClient::ClientShim::new(
                        settings
                            .gotham_server_url
                            .expect("Missing 'gotham_server_url' in settings.toml"),
                        None,
                    ),
                    wallet: GothamWallet::load(
                        settings
                            .wallet_file
                            .expect("Missing 'wallet_file' in settings.toml"),
                    ),
                };

                send_transaction(
                    settings
                        .rpc_url
                        .expect("Missing 'rpc_url' in settings.toml"),
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
                gas_limit: args.gas_limit.clone(),
                gas_price: args.gas_price.clone(),
                nonce: args.nonce.clone(),
            };

            if top_args.no_mpc == true {
                let wallet = settings
                    .private_key
                    .expect("Missing 'private_key' in settings.toml")
                    .parse::<LocalWallet>()?;

                transfer_erc20(
                    settings
                        .rpc_url
                        .expect("Missing 'rpc_url' in settings.toml"),
                    settings
                        .chain_id
                        .expect("Missing 'chain_id' in settings.toml"),
                    wallet,
                    details,
                )
                .await?;
            } else {
                let signer = GothamSigner {
                    gotham_client_shim: GothamClient::ClientShim::new(
                        settings
                            .gotham_server_url
                            .expect("Missing 'gotham_server_url' in settings.toml"),
                        None,
                    ),
                    wallet: GothamWallet::load(
                        settings
                            .wallet_file
                            .expect("Missing 'wallet_file' in settings.toml"),
                    ),
                };

                transfer_erc20(
                    settings
                        .rpc_url
                        .expect("Missing 'rpc_url' in settings.toml"),
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
                    .expect("Missing 'private_key' in settings.toml")
                    .parse::<LocalWallet>()?
                    .address();
            } else {
                address = GothamWallet::load(
                    settings
                        .wallet_file
                        .expect("Missing 'wallet_file' in settings.toml"),
                )
                .address;
            }

            get_balance(
                settings
                    .rpc_url
                    .expect("Missing 'rpc_url' in settings.toml"),
                address,
                args.tokens.clone(),
            )
            .await?;
        }
    }

    Ok(())
}
