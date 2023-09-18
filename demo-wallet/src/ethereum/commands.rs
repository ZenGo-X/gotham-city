use crate::ethereum::{
    create_new_wallet, get_balance, send_transaction, transfer_erc20, GothamSigner, GothamWallet,
    TransactionDetails, TransferDetails,
};
use crate::Settings;
use clap::{Args, Parser, Subcommand};
use ethers::prelude::{Address, LocalWallet, Signer};
use std::path::PathBuf;

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

pub async fn evm_commands(
    settings: Settings,
    top_args: &EvmArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    match &top_args.commands {
        EvmSubCommands::New(args) => {
            create_new_wallet(
                settings.gotham_wallet_file.unwrap(),
                settings.gotham_server_url.unwrap(),
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
    }

    Ok(())
}