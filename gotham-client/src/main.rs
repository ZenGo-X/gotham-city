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
use client_lib::ClientShim;
use floating_duration::TimeFormat;
use std::time::Instant;

use std::collections::HashMap;

fn main() {
    // let yaml = load_yaml!("../cli.yml");
    // let matches = App::from_yaml(yaml).get_matches();

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

    println!("Network: [{}], Creating wallet", network);
    let wallet = wallet::Wallet::new(&client_shim, &network);
    wallet.save_to("mywallet");
    println!("Network: [{}], Wallet saved to disk", &network);

    // let mut wallet: wallet::Wallet = wallet::Wallet::load();
}
