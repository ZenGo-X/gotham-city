use reqwest;
use uuid::Uuid;
use kms::ecdsa::two_party::MasterKey2;
use std::fs;
use serde_json;
use curv::BigInt;
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
    private_shares: PrivateShares,
    address_derivation: AddressDerivation
}

impl Wallet {
    pub fn new(client: &reqwest::Client) -> Wallet {
        let id = Uuid::new_v4().to_string();
        let private_shares = keygen::get_master_key(&client);
        let address_derivation = Self::derive_address(&private_shares, 0 /* init */);

        Wallet { id, private_shares, address_derivation }
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

    fn derive_address(private_shares: &PrivateShares, pos: u8) -> AddressDerivation {
        let last_pos : u32 = (pos + 1).into();

        let last_child_master_key = private_shares.masterKey
            .get_child(vec![BigInt::from(last_pos)]);

        AddressDerivation { last_pos, last_child_master_key }
    }
}