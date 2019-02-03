use super::ecdsa::{keygen, sign};
use kms::ecdsa::two_party::MasterKey2;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;
use reqwest;


#[derive(Serialize, Deserialize)]
pub struct PrivateShare {
    pub id: String,
    pub master_key: MasterKey2,
}

pub fn get_master_key() -> PrivateShare {
    let client: reqwest::Client = reqwest::Client::new();
    keygen::get_master_key(&client)
}

pub fn sign(message: bitcoin::util::hash::Sha256dHash, mk: &MasterKey2, pos: u32, id: &String) -> party_one::Signature {
    let client: reqwest::Client = reqwest::Client::new();
    sign::sign(&client, message, mk, pos, id)
}