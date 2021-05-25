// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use std::convert::TryInto;
use std::time::Instant;

use client_lib::escrow;
use client_lib::wallet;
use client_lib::ClientShim;
use floating_duration::TimeFormat;
use rust_decimal::Decimal;
use structopt::StructOpt;

mod args;

fn main() {
    let args::Args {
        endpoint,
        electrum_host,
        network,
        wallet_file,
        escrow_secret_path,
        cmd,
    } = StructOpt::from_args();

    let client_shim = ClientShim::new(endpoint, None);

    match cmd {
        args::WalletCommand::Create => {
            println!("Network: [{}], Creating wallet", network);
            let wallet = wallet::Wallet::new(&client_shim, network);
            wallet.save(wallet_file);
            println!("Network: [{}], Wallet saved to disk", network);

            let _escrow = escrow::Escrow::new(&escrow_secret_path);
            println!("Network: [{}], Escrow initiated", network);
        }
        args::WalletCommand::NewAddress => {
            let mut wallet = wallet::Wallet::load(&wallet_file);
            let address = wallet.get_new_bitcoin_address();
            println!("Network: [{}], Address: [{}]", network, address);
            wallet.save(wallet_file);
        }
        args::WalletCommand::GetBalance => {
            let mut wallet = wallet::Wallet::load(&wallet_file);
            let balance = wallet.get_balance(&electrum_host);
            println!(
                "Network: [{}], Balance: [balance: {}, pending: {}]",
                network, balance.confirmed, balance.unconfirmed
            );
        }
        args::WalletCommand::ListUnspent => {
            let wallet = wallet::Wallet::load(&wallet_file);
            let unspent = wallet.list_unspent(&electrum_host);
            let hashes: Vec<String> = unspent.into_iter().map(|u| u.tx_hash).collect();

            println!(
                "Network: [{}], Unspent tx hashes: [\n{}\n]",
                network,
                hashes.join("\n")
            );
        }
        args::WalletCommand::Backup(file) => {
            let wallet = wallet::Wallet::load(&wallet_file);
            let escrow = escrow::Escrow::load(&escrow_secret_path);

            println!("Backup private share pending (it can take some time)...");

            let start = Instant::now();
            wallet.backup(escrow, file.backup_file);

            println!(
                "Backup key saved in escrow (Took: {})",
                TimeFormat(start.elapsed())
            );
        }
        args::WalletCommand::Verify(file) => {
            let wallet = wallet::Wallet::load(&wallet_file);
            let escrow = escrow::Escrow::load(&escrow_secret_path);

            println!("verify encrypted backup (it can take some time)...");

            let start = Instant::now();
            wallet.verify_backup(escrow, file.backup_file);

            println!(" (Took: {})", TimeFormat(start.elapsed()));
        }
        args::WalletCommand::Restore(file) => {
            let escrow = escrow::Escrow::load(&escrow_secret_path);

            println!("backup recovery in process 📲 (it can take some time)...");

            let start = Instant::now();
            wallet::Wallet::recover_and_save_share(
                escrow,
                network,
                &client_shim,
                file.backup_file,
                wallet_file,
            );

            println!(
                "Backup recovered 💾 (Took: {})",
                TimeFormat(start.elapsed())
            );
        }
        args::WalletCommand::Rotate => {
            let wallet = wallet::Wallet::load(&wallet_file);
            println!("Rotating secret shares");

            let start = Instant::now();
            let wallet = wallet.rotate(&client_shim);
            wallet.save(wallet_file);

            println!(
                "key rotation complete, (Took: {})",
                TimeFormat(start.elapsed())
            );
        }
        args::WalletCommand::Send(args) => {
            let mut wallet = wallet::Wallet::load(&wallet_file);

            let amount_satoshi = if let Some(amount_btc) = args.amount_btc {
                let satoshi = amount_btc * Decimal::from(100_000_000_u64);
                if satoshi.scale() != 0 {
                    eprintln!(
                        "You tried to send {} satoshi. Cannot send fractional amount of satoshi.",
                        satoshi
                    );
                    return;
                } else if satoshi.is_sign_negative() {
                    eprintln!("Cannot send negative amount of satoshi");
                    return;
                }
                satoshi.mantissa().try_into().unwrap()
            } else if let Some(amount_satoshi) = args.amount_satoshi {
                amount_satoshi
            } else {
                eprintln!("Invalid arguments: amount isn't specified");
                return;
            };

            let txid = wallet.send(
                &electrum_host,
                args.to.clone(),
                amount_satoshi,
                &client_shim,
            );
            wallet.save(wallet_file);
            println!(
                "Network: [{}], Sent {} satoshi to address {}. Transaction ID: {}",
                network, amount_satoshi, args.to, txid
            );
        }
    }
}
