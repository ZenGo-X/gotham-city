use super::ecdsa::{keygen, sign};
use curv::BigInt;
use kms::ecdsa::two_party::MasterKey2;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;
use reqwest;
use serde_json;

// iOS bindings
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[derive(Debug)]
pub struct ClientShim {
    pub client: reqwest::Client,
    pub auth_token: Option<String>,
    pub endpoint: String,
}

impl ClientShim {
    pub fn new(endpoint: String, auth_token: Option<String>) -> ClientShim {
        let client = reqwest::Client::new();
        ClientShim {
            client,
            auth_token,
            endpoint,
        }
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
    message: BigInt,
    mk: &MasterKey2,
    x_pos: BigInt,
    y_pos: BigInt,
    id: &String,
) -> party_one::Signature {
    sign::sign(&client_shim, message, mk, x_pos, y_pos, id)
}

#[no_mangle]
pub extern "C" fn get_client_master_key(
    c_endpoint: *const c_char,
    c_auth_token: *const c_char,
) -> *mut c_char {
    let raw_endpoint = unsafe { CStr::from_ptr(c_endpoint) };
    let endpoint = match raw_endpoint.to_str() {
        Ok(s) => s,
        Err(_) => panic!("Error while decoding raw endpoint"),
    };

    let raw_auth_token = unsafe { CStr::from_ptr(c_auth_token) };
    let auth_token = match raw_auth_token.to_str() {
        Ok(s) => s,
        Err(_) => panic!("Error while decoding auth token"),
    };

    let client_shim = ClientShim::new(endpoint.to_string(), Some(auth_token.to_string()));

    let private_share: PrivateShare = keygen::get_master_key(&client_shim);

    let private_share_json = match serde_json::to_string(&private_share) {
        Ok(share) => share,
        Err(_) => panic!("Error while performing keygen to endpoint {}", endpoint),
    };

    CString::new(private_share_json.to_owned())
        .unwrap()
        .into_raw()
}

#[no_mangle]
pub extern "C" fn sign_message(
    c_endpoint: *const c_char,
    c_auth_token: *const c_char,
    c_message_le_hex: *const c_char,
    c_master_key_json: *const c_char,
    c_x_pos: i32,
    c_y_pos: i32,
    c_id: *const c_char,
) -> *mut c_char {
    let raw_endpoint = unsafe { CStr::from_ptr(c_endpoint) };
    let endpoint = match raw_endpoint.to_str() {
        Ok(s) => s,
        Err(_) => panic!("Error while decoding raw endpoint"),
    };

    let raw_auth_token = unsafe { CStr::from_ptr(c_auth_token) };
    let auth_token = match raw_auth_token.to_str() {
        Ok(s) => s,
        Err(_) => panic!("Error while decoding raw auth_token"),
    };

    let raw_message_hex = unsafe { CStr::from_ptr(c_message_le_hex) };
    let message_hex = match raw_message_hex.to_str() {
        Ok(s) => s,
        Err(_) => panic!("Error while decoding raw message_hex"),
    };

    let raw_master_key_json = unsafe { CStr::from_ptr(c_master_key_json) };
    let master_key_json = match raw_master_key_json.to_str() {
        Ok(s) => s,
        Err(_) => panic!("Error while decoding raw master_key_json"),
    };

    let raw_id = unsafe { CStr::from_ptr(c_id) };
    let id = match raw_id.to_str() {
        Ok(s) => s,
        Err(_) => panic!("Error while decoding raw id"),
    };

    let x: BigInt = BigInt::from(c_x_pos);;

    let y: BigInt = BigInt::from(c_y_pos);

    let client_shim = ClientShim::new(endpoint.to_string(), Some(auth_token.to_string()));

    let mk: MasterKey2 = serde_json::from_str(master_key_json).unwrap();

    let mk_child: MasterKey2 = mk.get_child(vec![x.clone(), y.clone()]);

    let message: BigInt = serde_json::from_str(message_hex).unwrap();

    let sig = sign::sign(
        &client_shim,
        message,
        &mk_child,
        x,
        y,
        &id.to_string(),
    );

    let signature_json = match serde_json::to_string(&sig) {
        Ok(share) => share,
        Err(_) => panic!("Error while signing to endpoint {}", endpoint),
    };

    CString::new(signature_json.to_owned()).unwrap().into_raw()
}
