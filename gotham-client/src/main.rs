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

use client_lib::escrow;
use client_lib::wallet;
use reqwest;
use time::PreciseTime;

fn main() {
    let yaml = load_yaml!("../cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    let client = reqwest::Client::new();
    let network = "testnet".to_string();

    if let Some(_matches) = matches.subcommand_matches("create-wallet") {
        println!("Network: [{}], Creating wallet", network);
        let wallet = wallet::Wallet::new(&client, &network);
        wallet.save();
        println!("Network: [{}], Wallet saved to disk", &network);

        let _escrow = escrow::Escrow::new();
        println!("Network: [{}], Escrow initiated", &network);
    } else if let Some(matches) = matches.subcommand_matches("wallet") {
        let mut wallet: wallet::Wallet = wallet::Wallet::load();

        if matches.is_present("new-address") {
            let address = wallet.get_new_bitcoin_address();
            println!("Network: [{}], Address: [{}]", network, address.to_string());
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

            let start = PreciseTime::now();
            wallet.backup(&escrow);
            let end = PreciseTime::now();

            println!("Backup key saved in escrow (Took: {})", start.to(end));
        } else if matches.is_present("restore") {
            let escrow = escrow::Escrow::load();
            println!("Recovering private share pending (it can take some time)...");

            let start = PreciseTime::now();
            escrow.recover_and_save_shares();
            let end = PreciseTime::now();

            println!("Recovered key, saved in escrow (Took: {})", start.to(end));
        } else if matches.is_present("send") {
            if let Some(matches) = matches.subcommand_matches("send") {
                let to: &str = matches.value_of("to").unwrap();
                let amount_btc: &str = matches.value_of("amount").unwrap();
                let txid = wallet.send(
                    &client,
                    to.to_string(),
                    amount_btc.to_string().parse::<f32>().unwrap(),
                );

                println!(
                    "Network: [{}], Sent {} BTC to address {}. Transaction ID: {}",
                    network, amount_btc, to, txid
                );
            }
        }

        wallet.save();
    }
}
