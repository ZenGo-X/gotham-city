// Gotham-city 
// 
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

#[cfg(test)]
mod tests {
    use super::super::wallet::Wallet;

    const TEST_WALLET_FILENAME: &str = "test-assets/wallet.data";

    #[test]
    fn load_wallet_test() {
        Wallet::load_from(TEST_WALLET_FILENAME);
    }

    #[test]
    fn get_address_test() {
        let  mut w : Wallet = Wallet::load_from(TEST_WALLET_FILENAME);
        let a = w.get_new_bitcoin_address();
        assert!(!a.to_string().is_empty())
    }

    #[test]
    fn get_balance_test() {
        let  mut w : Wallet = Wallet::load_from(TEST_WALLET_FILENAME);
        let b = w.get_balance();
        assert!(b.confirmed > 0);
    }

// TODO: Find a reliable way of doing integration testing over the blockchain.
// TODO: Ideally we would like to do the whole flow of receiving and sending. PR welcome ;)
//    #[test]
//    fn send_test() {
//        // expect the server running
//        let client_shim : api::ClientShim = api::ClientShim::new(
//            "http://localhost:8000".to_string(), None);
//
//        let  mut w : Wallet = Wallet::load_from(TEST_WALLET_FILENAME);
//        let b = w.get_balance();
//        assert!(b.confirmed > 0);
//
//        let available_balance = b.confirmed as f32 / 100000000 as f32;
//        let to_send = 0.00000001;
//        let delta_pessimistic_fees = 0.00013; // 0.5 usd - 03/14/2019
//        assert!(available_balance > to_send + delta_pessimistic_fees, "You need to refund the wallet");
//
//        let to_address = w.get_new_bitcoin_address(); // inner wallet tx
//        let txid = w.send(to_address.to_string(), to_send, &client_shim);
//        assert!(!txid.is_empty());
//    }
}