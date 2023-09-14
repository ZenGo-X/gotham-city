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
        TopLevelSubCommands::Evm(top_args) => evm_commands(settings, &top_args).await?,
        TopLevelSubCommands::Bitcoin(top_args) => bitcoin_commands(settings, &top_args).await?,
    }

    Ok(())
}


