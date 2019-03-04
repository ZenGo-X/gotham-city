use super::ecdsa::{keygen, sign};
use kms::ecdsa::two_party::MasterKey2;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;
use reqwest;

pub struct ClientShim {
    pub client: reqwest::Client,
    pub endpoint: String,
}

impl ClientShim {
    pub fn new(endpoint: String) -> ClientShim {
        let client = reqwest::Client::new();
        ClientShim { client, endpoint }
    }
}

#[derive(Serialize, Deserialize)]
pub struct PrivateShare {
    pub id: String,
    pub master_key: MasterKey2,
}

pub fn get_master_key(client_shim: &ClientShim) -> PrivateShare {
    keygen::get_master_key(&client_shim)
}

pub fn sign(
    client_shim: &ClientShim,
    message: bitcoin::util::hash::Sha256dHash,
    mk: &MasterKey2,
    pos: u32,
    id: &String,
) -> party_one::Signature {
    sign::sign(&client_shim, message, mk, pos, id)
}
