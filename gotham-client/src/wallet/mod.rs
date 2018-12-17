use reqwest;
use uuid::Uuid;
use kms::ecdsa::two_party::MasterKey2;
use std::fs;
use serde_json;
use curv::BigInt;
use bitcoin;
use bitcoin::network::constants::Network;
use bitcoin::{Transaction, TxIn, TxOut};
use curv::elliptic::curves::traits::ECPoint;
use electrumx_client::{
    electrumx_client::ElectrumxClient,
    interface::Electrumx
};

use super::ecdsa::keygen;

// TODO: move that to a config file and double check electrum server addresses
const ELECTRUM_HOST : &str = "testnet.hsmiths.com:53011";
const WALLET_FILENAME : &str = "wallet/wallet.data";

#[derive(Debug, Deserialize, Clone)]
pub struct GetBalanceResponse {
    pub address: String,
    pub confirmed:   u64,
    pub unconfirmed: u64,
}

#[derive(Debug, Deserialize)]
pub struct GetWalletBalanceResponse {
    pub confirmed:   u64,
    pub unconfirmed: u64,
}

#[derive(Serialize, Deserialize)]
pub struct PrivateShares {
    pub id: String,
    pub master_key: MasterKey2
}

#[derive(Serialize, Deserialize)]
pub struct AddressDerivation {
    pub last_pos: u32,
    pub last_child_master_key: MasterKey2
}

#[derive(Serialize, Deserialize)]
pub struct Wallet {
    id: String,
    network: String,
    private_shares: PrivateShares,
    address_derivation: AddressDerivation
}

impl Wallet {
    pub fn new(client: &reqwest::Client, network: String) -> Wallet {
        let id = Uuid::new_v4().to_string();
        let private_shares = keygen::get_master_key(&client);
        let address_derivation = Self::derive_key(&private_shares, 0 /* init */);

        Wallet { id, network, private_shares, address_derivation }
    }

    pub fn save(&self) {
        let wallet_json = serde_json::to_string(self).unwrap();

        fs::write(WALLET_FILENAME, wallet_json)
            .expect("Unable to save wallet!");

        println!("(wallet id: {}) Saved wallet to disk", self.id);
    }

    pub fn load() -> Wallet {
        let data = fs::read_to_string(WALLET_FILENAME)
            .expect("Unable to load wallet!");

        let wallet: Wallet = serde_json::from_str(&data).unwrap();

        println!("(wallet id: {}) Loaded wallet to memory", wallet.id);

        wallet
    }

    /*pub fn send(to_address: String, amount_btc: u32) -> bool {

    }*/

    pub fn get_new_bitcoin_address(&mut self) -> bitcoin::Address {
        let address_derivation = Self::derive_key(
            &self.private_shares, self.address_derivation.last_pos/* init */);
        self.address_derivation = address_derivation;

        Self::to_bitcoin_address(&self.address_derivation, self.get_bitcoin_network())
    }

    pub fn get_balance(&mut self) -> GetWalletBalanceResponse  {
        let mut aggregated_balance = GetWalletBalanceResponse { confirmed: 0, unconfirmed: 0 };

        for b in self.get_all_addresses_balance() {
            aggregated_balance.unconfirmed += b.unconfirmed;
            aggregated_balance.confirmed += b.confirmed;
        }

        aggregated_balance
    }

    pub fn get_address_balance(address: &bitcoin::Address) -> GetBalanceResponse  {
        let mut client = ElectrumxClient::new(ELECTRUM_HOST).unwrap();

        let resp = client.get_balance(&address.to_string()).unwrap();

        GetBalanceResponse {
            confirmed: resp.confirmed,
            unconfirmed: resp.unconfirmed,
            address: address.to_string()
        }
    }

    // TODO: handle fees
    pub fn select_tx_in(&self, amount_btc: u16) -> Vec<GetBalanceResponse> { // greedy selection
        let balances = self.get_all_addresses_balance();

        let mut confirmed_balances : Vec<GetBalanceResponse> = balances
            .into_iter()
            .filter(|b| b.confirmed > 0)
            .collect();

        confirmed_balances.sort_by(|a, b|
                                       a.confirmed.partial_cmp(&b.confirmed).unwrap());

        let mut selected : Vec<GetBalanceResponse> = Vec::new();

        let mut remaining : i64 = amount_btc.into();
        for b in confirmed_balances {
            selected.push(b.clone());
            remaining -= b.confirmed as i64;

            if remaining < 0 { break; }
        }

        selected
    }

    fn get_all_addresses_balance(&self) -> Vec<GetBalanceResponse> {
        let init = 0;
        let last_pos = self.address_derivation.last_pos;

        let mut response : Vec<GetBalanceResponse> = Vec::new();

        for n in init..last_pos {
            let address_derivation = Self::derive_key(&self.private_shares, n);
            let bitcoin_address = Self::to_bitcoin_address(&address_derivation, self.get_bitcoin_network());

            response.push(Self::get_address_balance(&bitcoin_address));
        }

        response
    }

    fn derive_key(private_shares: &PrivateShares, pos: u32) -> AddressDerivation {
        let last_pos : u32 = pos + 1;

        let last_child_master_key = private_shares.master_key
            .get_child(vec![BigInt::from(last_pos)]);

        AddressDerivation { last_pos, last_child_master_key }
    }

    fn get_bitcoin_network(&self) -> Network {
        self.network.parse::<Network>().unwrap()
    }

    fn to_bitcoin_address(address_derivation: &AddressDerivation, network: Network) -> bitcoin::Address {
        bitcoin::Address::p2wpkh(
            &address_derivation.last_child_master_key.public.q.get_element(),
            network)
    }
}