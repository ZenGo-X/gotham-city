// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

#[macro_use]
extern crate clap;
use clap::App;

use client_lib::ClientShim;
use client_lib::escrow;
use client_lib::wallet;
use std::time::Instant;
use floating_duration::TimeFormat;

use std::collections::HashMap;

fn main() {
    let yaml = load_yaml!("../cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

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

    if let Some(_matches) = matches.subcommand_matches("create-wallet") {
        println!("Network: [{}], Creating wallet", network);
        let wallet = wallet::Wallet::new(&client_shim, &network);
        wallet.save();
        println!("Network: [{}], Wallet saved to disk", &network);

        let _escrow = escrow::Escrow::new();
        println!("Network: [{}], Escrow initiated", &network);
    } else if let Some(matches) = matches.subcommand_matches("wallet") {
        let mut wallet: wallet::Wallet = wallet::Wallet::load();

        if matches.is_present("new-address") {
            let address = wallet.get_new_bitcoin_address();
            println!("Network: [{}], Address: [{}]", network, address.to_string());
            wallet.save();
        } else if matches.is_present("get-balance") {
            let balance = wallet.get_balance();
            println!(
                "Network: [{}], Balance: [balance: {}, pending: {}]",
                network, balance.confirmed, balance.unconfirmed
            );
        } else if matches.is_present("list-unspent") {
            let unspent = wallet.list_unspent();
            let hashes: Vec<String> = unspent.into_iter().map(|u| u.tx_hash).collect();

            println!(
                "Network: [{}], Unspent tx hashes: [\n{}\n]",
                network,
                hashes.join("\n")
            );
        } else if matches.is_present("backup") {
            let escrow = escrow::Escrow::load();

            println!("Backup private share pending (it can take some time)...");

            let start = Instant::now();
            wallet.backup(escrow);

            println!("Backup key saved in escrow (Took: {})", TimeFormat(start.elapsed()));
        } else if matches.is_present("verify") {
            let escrow = escrow::Escrow::load();

            println!("verify encrypted backup (it can take some time)...");

            let start = Instant::now();
            wallet.verify_backup(escrow);

            println!(" (Took: {})", TimeFormat(start.elapsed()));
        } else if matches.is_present("restore") {
            let escrow = escrow::Escrow::load();

            println!("backup recovery in process 📲 (it can take some time)...");

            let start = Instant::now();
            wallet::Wallet::recover_and_save_share(escrow, &network, &client_shim);

            println!(" Backup recovered 💾(Took: {})", TimeFormat(start.elapsed()));
        } else if matches.is_present("rotate") {
            println!("Rotating secret shares");

            let start = Instant::now();
            let wallet = wallet.rotate(&client_shim);
            wallet.save();

            println!("key rotation complete, (Took: {})", TimeFormat(start.elapsed()));
        } else if matches.is_present("send") {
            if let Some(matches) = matches.subcommand_matches("send") {
                let to: &str = matches.value_of("to").unwrap();
                let amount_btc: &str = matches.value_of("amount").unwrap();
                let txid = wallet.send(
                    to.to_string(),
                    amount_btc.to_string().parse::<f32>().unwrap(),
                    &client_shim,
                );
                wallet.save();
                println!(
                    "Network: [{}], Sent {} BTC to address {}. Transaction ID: {}",
                    network, amount_btc, to, txid
                );
            }
        }
    }
}
