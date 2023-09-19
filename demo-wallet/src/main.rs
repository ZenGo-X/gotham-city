use crate::bitcoin::commands::*;
use crate::ethereum::commands::*;
use clap::{Args, Parser, Subcommand};

use std::error::Error;
use std::ops::Deref;
use std::str::FromStr;

use config::{Config, File};
use serde::Deserialize;

pub mod bitcoin;
pub mod ethereum;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[arg(short, long, help = "Settings file", default_value = "settings.toml")]
    pub settings: String,

    #[command(subcommand)]
    pub commands: TopLevelSubCommands,
}

#[derive(Subcommand)]
pub enum TopLevelSubCommands {
    #[command(
        about = "EVM-compatible blockchain",
        long_about = "Configuration variables in settings file: \n \
    `rpc_url` - endpoint to communicate with the Ethereum network \n \
    `wallet_file` - file-path to wallet JSON file `[default: wallet.json]` \n \
    `gotham_server_url` - URL to Gotham Server `[default: http://127.0.0.1:8000]`"
    )]
    Evm(EvmArgs),

    #[command(
        about = "Bitcoin blockchain",
        long_about = "Configuration variables in settings file: \n \
    `electrum_server_url` - endpoint of Electrum server \n \
    `wallet_file` - file-path to wallet JSON file `[default: wallet.json]` \n \
    `gotham_server_url` - URL to Gotham Server `[default: http://127.0.0.1:8000]`"
    )]
    Bitcoin(BitcoinArgs),
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub wallet_file: Option<String>,
    pub rpc_url: Option<String>,
    pub gotham_server_url: Option<String>,

    pub private_key: Option<String>,
    pub chain_id: Option<u64>,

    pub electrum_server_url: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let config = Config::builder()
        .add_source(File::with_name(&cli.settings).required(false))
        .add_source(config::Environment::with_prefix("GOTHAM"))
        .build()?;
    let mut settings = config
        .try_deserialize::<Settings>()
        .expect("Unable to load settings file");

    if settings.gotham_server_url.is_none() {
        settings.gotham_server_url = Option::from("http://127.0.0.1:8000".to_string())
    }

    if settings.wallet_file.is_none() {
        settings.wallet_file = Option::from("wallet.json".to_string());
    }

    match &cli.commands {
        TopLevelSubCommands::Evm(top_args) => evm_commands(settings, &top_args).await?,
        TopLevelSubCommands::Bitcoin(top_args) => bitcoin_commands(settings, &top_args).await?,
    }

    Ok(())
}
