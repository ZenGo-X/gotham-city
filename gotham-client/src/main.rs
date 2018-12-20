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

    let escrow = escrow::Escrow::new();

    if let Some(_matches) = matches.subcommand_matches("create-wallet") {
        let wallet : wallet::Wallet = wallet::Wallet::new(&client, network);
        wallet.save();
    } else if let Some(matches) = matches.subcommand_matches("wallet") {
        let mut wallet : wallet::Wallet = wallet::Wallet::load();

        if matches.is_present("new-address") {
            let address = wallet.get_new_bitcoin_address();
            println!("{:?}", address);
            wallet.derived();
        } else if matches.is_present("get-balance") {
//            let balance = wallet.get_balance();
//            println!("{:?}", balance);
            println!("trying send");
            let to = "tb1qpvwqq4e6l9jr735sdvjvv0ww4h796ffvttwfv3".to_string();
            let tx = wallet.send(&client, to, 0.001);
            println!("{:?}", tx);
        } else if matches.is_present("list-unspent") {
            let unspent = wallet.list_unspent();
            println!("{:?}", unspent);
        } else if matches.is_present("backup") {
            wallet.backup(&escrow);
        }

        wallet.save();
    }
}
