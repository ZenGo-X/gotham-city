#[macro_use]
extern crate clap;
use clap::App;

use reqwest;
use client_lib::wallet;

fn main() {
    let yaml = load_yaml!("../cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    let client = reqwest::Client::new();
    let network = "testnet".to_string();

    if let Some(matches) = matches.subcommand_matches("create-wallet") {
        let mut wallet : wallet::Wallet = wallet::Wallet::new(&client, network);
        wallet.save();
    } else if let Some(matches) = matches.subcommand_matches("wallet") {
        let mut wallet : wallet::Wallet = wallet::Wallet::load();

        if matches.is_present("new-address") {
            let address = wallet.get_new_bitcoin_address();
            println!("{:?}", address);
        } else if matches.is_present("get-balance") {
            let balance = wallet.get_balance();
            println!("{:?}", balance);
        }

        wallet.save();
    }
}
