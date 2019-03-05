use super::ecdsa::{keygen, sign};
use kms::ecdsa::two_party::MasterKey2;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;
use reqwest;
use serde_json;

// iOS bindings
use std::os::raw::{c_char};
use std::ffi::{CString, CStr};

pub struct ClientShim {
    pub client: reqwest::Client,
    pub auth_token: Option<String>,
    pub endpoint: String,
}

impl ClientShim {
    pub fn new(endpoint: String, auth_token: Option<String>) -> ClientShim {
        let client = reqwest::Client::new();
        ClientShim { client, auth_token, endpoint }
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

#[no_mangle]
pub extern fn get_client_master_key(c_endpoint: *const c_char, auth_token: *const c_char) -> *mut c_char {
    let raw_endpoint = unsafe { CStr::from_ptr(c_endpoint) };
    let endpoint = match raw_endpoint.to_str() {
        Ok(s) => s,
        Err(_) => panic!("Error while decoding raw endpoint")
    };

    let raw_auth_token = unsafe { CStr::from_ptr(auth_token) };
    let auth_token = match raw_auth_token.to_str() {
        Ok(s) => s,
        Err(_) => panic!("Error while decoding auth token")
    };

    let client_shim = ClientShim::new(
        endpoint.to_string(), Some(auth_token.to_string()));

    let private_share : PrivateShare = keygen::get_master_key(&client_shim);

    let private_share_json = match serde_json::to_string(&private_share) {
        Ok(share) => share,
        Err(_) => panic!("Error while performing keygen to endpoint {}", endpoint)
    };

    CString::new(private_share_json.to_owned()).unwrap().into_raw()
}

