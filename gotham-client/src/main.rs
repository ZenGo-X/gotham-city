#[macro_use]
extern crate clap;
use clap::App;

use reqwest;
use client_lib::wallet;

fn main() {
    let yaml = load_yaml!("../cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    let client = reqwest::Client::new();

    if let Some(matches) = matches.subcommand_matches("create-wallet") {
        let wallet : wallet::Wallet = wallet::Wallet::new(&client);
        wallet.save();
    }
}
