use reqwest;
use uuid::Uuid;
use kms::ecdsa::two_party::MasterKey2;
use std::fs;
use serde_json;
use curv::BigInt;
use bitcoin;
use bitcoin::network::constants::Network;
use curv::elliptic::curves::traits::ECPoint;

use super::ecdsa::keygen;

const WALLET_FILENAME : &str = "wallet/wallet.data";

#[derive(Serialize, Deserialize)]
pub struct PrivateShares {
    pub id: String,
    pub masterKey: MasterKey2
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

    pub fn get_new_bitcoin_address(&mut self) -> bitcoin::Address {
        let address_derivation = Self::derive_key(
            &self.private_shares, self.address_derivation.last_pos/* init */);
        self.address_derivation = address_derivation;

        bitcoin::Address::p2wpkh(
            &self.address_derivation.last_child_master_key.public.q.get_element(),
            self.get_bitcoin_network())
    }

    fn derive_key(private_shares: &PrivateShares, pos: u32) -> AddressDerivation {
        let last_pos : u32 = pos + 1;

        let last_child_master_key = private_shares.masterKey
            .get_child(vec![BigInt::from(last_pos)]);

        AddressDerivation { last_pos, last_child_master_key }
    }

    fn get_bitcoin_network(&self) -> Network {
        self.network.parse::<Network>().unwrap()
    }
}