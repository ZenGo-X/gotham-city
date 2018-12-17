use reqwest;
use uuid::Uuid;
use kms::ecdsa::two_party::MasterKey2;
use std::fs;
use serde_json;
use curv::BigInt;
use bitcoin;
use bitcoin::network::constants::Network;
use curv::elliptic::curves::traits::ECPoint;
use std::net::TcpStream;
use electrumx_client::{
    electrumx_client::ElectrumxClient,
    interface::Electrumx,
    tools
};

use super::ecdsa::keygen;

const WALLET_FILENAME : &str = "wallet/wallet.data";

#[derive(Debug, Deserialize)]
pub struct GetBalanceResponse {
    pub confirmed:   u64,
    pub unconfirmed: u64,
}

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

        Self::to_bitcoin_address(&self.address_derivation, self.get_bitcoin_network())
    }

    pub fn get_balance(&mut self) -> GetBalanceResponse  {
        let init = 0;
        let last_pos = self.address_derivation.last_pos;

        let mut aggregated_balance = GetBalanceResponse { confirmed: 0, unconfirmed: 0 };

        for n in init..last_pos {
            let address_derivation = Self::derive_key(&self.private_shares, n);
            let bitcoin_address = Self::to_bitcoin_address(&address_derivation, self.get_bitcoin_network());

            let balance = Self::get_address_balance(&bitcoin_address);
            aggregated_balance.unconfirmed += balance.unconfirmed;
            aggregated_balance.confirmed += balance.confirmed;
        }

        aggregated_balance
    }

    pub fn get_address_balance(address: &bitcoin::Address) -> GetBalanceResponse  {
        let mut client = ElectrumxClient::new(
            "ec2-34-219-15-143.us-west-2.compute.amazonaws.com:60001").unwrap();


        let resp = client.get_balance(&address.to_string()).unwrap();
        GetBalanceResponse { confirmed: resp.confirmed, unconfirmed: resp.unconfirmed }
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

    fn to_bitcoin_address(address_derivation: &AddressDerivation, network: Network) -> bitcoin::Address {
        bitcoin::Address::p2wpkh(
            &address_derivation.last_child_master_key.public.q.get_element(),
            network)
    }
}