use curv::BigInt;
use kms::ecdsa::two_party::party2;
use kms::ecdsa::two_party::MasterKey2;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two;

use super::super::utilities::requests;
use super::super::ClientShim;

// iOS bindings
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[derive(Serialize, Deserialize, Debug)]
pub struct SignSecondMsgRequest {
    pub message: BigInt,
    pub party_two_sign_message: party2::SignMessage,
    pub x_pos_child_key: BigInt,
    pub y_pos_child_key: BigInt,
}

pub fn sign(
    client_shim: &ClientShim,
    message: BigInt,
    mk: &MasterKey2,
    x_pos: BigInt,
    y_pos: BigInt,
    id: &String,
) -> party_one::SignatureRecid {
    let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
        MasterKey2::sign_first_message();

    let request: party_two::EphKeyGenFirstMsg = eph_key_gen_first_message_party_two;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/first", id), &request).unwrap();

    let sign_party_one_first_message: party_one::EphKeyGenFirstMsg =
        serde_json::from_str(&res_body).unwrap();

    let party_two_sign_message = mk.sign_second_message(
        &eph_ec_key_pair_party2,
        eph_comm_witness.clone(),
        &sign_party_one_first_message,
        &message,
    );

    let signature: party_one::SignatureRecid = get_signature(
        client_shim,
        message,
        party_two_sign_message,
        x_pos,
        y_pos,
        &id,
    );

    signature
}

fn get_signature(
    client_shim: &ClientShim,
    message: BigInt,
    party_two_sign_message: party2::SignMessage,
    x_pos_child_key: BigInt,
    y_pos_child_key: BigInt,
    id: &String,
) -> party_one::SignatureRecid {
    let request: SignSecondMsgRequest = SignSecondMsgRequest {
        message,
        party_two_sign_message,
        x_pos_child_key,
        y_pos_child_key,
    };

    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/second", id), &request).unwrap();

    let signature: party_one::SignatureRecid = serde_json::from_str(&res_body).unwrap();
    signature
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

    let sig = sign(
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
