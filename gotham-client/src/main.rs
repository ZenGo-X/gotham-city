// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use clap::*;
use rand::rngs::mock::StepRng;
use rand::Rng;
use client_lib::wallet;
use client_lib::ClientShim;
use floating_duration::TimeFormat;
use std::time::Instant;
pub use two_party_ecdsa::curv::{ BigInt};
use std::collections::HashMap;
use ethers::prelude::*;
use sha2::{Sha256, Digest};



#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let yaml = load_yaml!("../cli.yml");
    // let matches = App::from_yaml(yaml).get_matches();
    // #[derive(Debug,Parser)]
    // #[clap(author,version,about)]
    // pub struct walletArgs{
    //     pub first:String,
    //     #[command(subcommand)]
    //     pub second:Action,
    // }

    #[derive(clap::Parser)]
    struct walletArgs {
        #[command(subcommand)]
        action: Action,
        // #[arg(short, long)]
        // name: Option<String>,
    }
    #[derive(clap::Subcommand)]
    enum Action {
        /// create a new wallet
        create,
        /// load an existing wallet
        load,
        /// sign with the existing wallet
        // #[command(subcommand)]
        sign{ name: Option<String> },
        /// derive new addresses
        derive
    }
    let args = walletArgs::parse();
    let mut rng = StepRng::new(0, 1);

    let mut settings = config::Config::default();
    settings
        // Add in `./Settings.toml`
        .merge(config::File::with_name("Settings"))
        .unwrap()
        // Add in settings from the environment (with prefix "APP")
        // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        .merge(config::Environment::new())
        .unwrap();
    let hm = settings.try_into::<HashMap<String, String>>().unwrap();
    let endpoint = hm.get("endpoint").unwrap();

    let client_shim = ClientShim::new(endpoint.to_string(), None);

    let network = "testnet".to_string();
    match &args.action {
        Action::create {  } => {
            println!("'create: ");
            println!("Network: [{}], Creating wallet", network);
            let wallet = wallet::Wallet::new(&client_shim, &network);
            wallet.save();
            println!("Network: [{}], Wallet saved to disk", &network);
        }
        Action::load {  } => {
            println!("'load: ");
            let mut wallet: wallet::Wallet = wallet::Wallet::load();

        }
        Action::sign { name } => {
            let mut wallet: wallet::Wallet = wallet::Wallet::load();
            println!("Load wallet: [{}]", wallet.id);
            println!("Sign: ");
            let mut msg_buf = "Test Signature";
            println!("message: [{}]",msg_buf);

            // create a Sha256 object
            let mut hasher = Sha256::new();

            // write input message
            hasher.update(msg_buf);

            // read hash digest and consume hasher
            let msg = hasher.finalize();
            wallet.sign(&msg,&client_shim);
            println!("Network: [{}], MPC signature verified", &network);
        }
        Action::derive {  } => {
            const RPC_URL: &str = "https://eth.llamarpc.com";
            println!("'derive: ");
            let mut wallet: wallet::Wallet = wallet::Wallet::load();
            println!("Wallet: [{}], loaded", wallet.id);
            let provider = Provider::<Http>::try_from(RPC_URL)?;
            let block_number: U64 = provider.get_block_number().await?;
            println!("{block_number}");



        }
    }

    Ok(())


}
