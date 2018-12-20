#[macro_use]
extern crate clap;
use clap::App;

use reqwest;
use client_lib::wallet;
use client_lib::escrow;

fn main() {
    let yaml = load_yaml!("../cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    let client = reqwest::Client::new();
    let network = "testnet".to_string();

    if let Some(_matches) = matches.subcommand_matches("create-wallet") {
        wallet::Wallet::new(&client, network).save();
    } else if let Some(matches) = matches.subcommand_matches("wallet") {
        let mut wallet : wallet::Wallet = wallet::Wallet::load();
        let escrow = escrow::Escrow::new();

        if matches.is_present("new-address") {
            let address = wallet.get_new_bitcoin_address();
            println!("Network: [{}], Address: [{}]", network, address.to_string());
        } else if matches.is_present("get-balance") {
            let balance = wallet.get_balance();
            println!("Network: [{}], Balance: [balance: {}, pending: {}]",
                     network, balance.confirmed, balance.unconfirmed);
        } else if matches.is_present("list-unspent") {
            let unspent = wallet.list_unspent();
            let hashes : Vec<String>= unspent
                .into_iter()
                .map(|u| u.tx_hash)
                .collect();

            println!("Network: [{}], Unspent tx hashes: [\n{}\n]", network, hashes.join("\n"));
        } else if matches.is_present("backup") {
            wallet.backup(&escrow);
        } else if matches.is_present("send") {
            if let Some(matches) = matches.subcommand_matches("send") {
                let to: &str = matches.value_of("to").unwrap();
                let amount_btc: &str = matches.value_of("amount").unwrap();
                let signed_tx_hex = wallet.send(&client,
                                                to.to_string(),
                                                amount_btc.to_string().parse::<f32>().unwrap());

                println!("Network: [{}], Signed tx hex: [{}]", network, signed_tx_hex);
            }
        }

        wallet.save();
    }
}
