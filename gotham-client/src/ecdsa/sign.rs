use failure::format_err;
use two_party_ecdsa::kms::ecdsa::two_party::{party2, MasterKey2};
use serde::{Deserialize, Serialize};
use two_party_ecdsa::{curv::BigInt, party_one, party_two};
// iOS bindings
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
//Android bindings
#[cfg(target_os = "android")]
use jni::{
    objects::{JClass, JString},
    strings::JavaStr,
    sys::{jint, jstring},
    JNIEnv,
};
use std::ops::Deref;

use crate::{utilities::error_to_c_string, Client, ClientShim, Result};

#[derive(Serialize, Deserialize, Debug)]
pub struct SignSecondMsgRequest {
    pub message: BigInt,
    pub party_two_sign_message: party2::SignMessage,
    pub x_pos_child_key: BigInt,
    pub y_pos_child_key: BigInt,
}

pub fn sign<C: Client>(
    client_shim: &ClientShim<C>,
    message: BigInt,
    mk: &MasterKey2,
    x_pos: BigInt,
    y_pos: BigInt,
    id: &str,
) -> Result<party_one::SignatureRecid> {
    let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
        MasterKey2::sign_first_message();

    let request: party_two::EphKeyGenFirstMsg = eph_key_gen_first_message_party_two;
    let sign_party_one_first_message: party_one::EphKeyGenFirstMsg =
        match client_shim.postb(&format!("/ecdsa/sign/{}/first", id), &request) {
            Some(s) => s,
            None => return Err(failure::err_msg("party1 sign first message request failed")),
        };

    let party_two_sign_message = mk.sign_second_message(
        &eph_ec_key_pair_party2,
        eph_comm_witness,
        &sign_party_one_first_message,
        &message,
    );

    let signature = match get_signature(
        client_shim,
        message,
        party_two_sign_message,
        x_pos,
        y_pos,
        id,
    ) {
        Ok(s) => s,
        Err(e) => return Err(format_err!("ecdsa::get_signature failed failed: {}", e)),
    };

    Ok(signature)
}

fn get_signature<C: Client>(
    client_shim: &ClientShim<C>,
    message: BigInt,
    party_two_sign_message: party2::SignMessage,
    x_pos_child_key: BigInt,
    y_pos_child_key: BigInt,
    id: &str,
) -> Result<party_one::SignatureRecid> {
    let request: SignSecondMsgRequest = SignSecondMsgRequest {
        message,
        party_two_sign_message,
        x_pos_child_key,
        y_pos_child_key,
    };

    let signature: party_one::SignatureRecid =
        match client_shim.postb(&format!("/ecdsa/sign/{}/second", id), &request) {
            Some(s) => s,
            None => {
                return Err(failure::err_msg(
                    "party1 sign second message request failed",
                ))
            }
        };

    Ok(signature)
}

/// # Safety
///
/// - This function should only be called with valid C pointers.
/// - Arguments are accessed in arbitrary locations.
/// - Strings should be null terminated array of bytes.
#[no_mangle]
pub unsafe extern "C" fn sign_message(
    c_endpoint: *const c_char,
    c_auth_token: *const c_char,
    c_message_le_hex: *const c_char,
    c_master_key_json: *const c_char,
    c_x_pos: i32,
    c_y_pos: i32,
    c_id: *const c_char,
) -> *mut c_char {
    let raw_endpoint = CStr::from_ptr(c_endpoint);
    let endpoint = match raw_endpoint.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw endpoint failed: {}", e)),
    };

    let raw_auth_token = CStr::from_ptr(c_auth_token);
    let auth_token = match raw_auth_token.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw auth_token failed: {}", e)),
    };

    let raw_message_hex = CStr::from_ptr(c_message_le_hex);
    let message_hex = match raw_message_hex.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw message_hex failed: {}", e)),
    };

    let raw_master_key_json = CStr::from_ptr(c_master_key_json);
    let master_key_json = match raw_master_key_json.to_str() {
        Ok(s) => s,
        Err(e) => {
            return error_to_c_string(format_err!("decoding raw master_key_json failed: {}", e))
        }
    };

    let raw_id = CStr::from_ptr(c_id);
    let id = match raw_id.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw id failed: {}", e)),
    };

    let x: BigInt = BigInt::from(c_x_pos);

    let y: BigInt = BigInt::from(c_y_pos);

    let client_shim = ClientShim::new(endpoint.to_string(), Some(auth_token.to_string()));

    let mk: MasterKey2 = serde_json::from_str(master_key_json).unwrap();

    let mk_child: MasterKey2 = mk.get_child(vec![x.clone(), y.clone()]);

    let message: BigInt = serde_json::from_str(message_hex).unwrap();

    let sig = match sign(&client_shim, message, &mk_child, x, y, id) {
        Ok(s) => s,
        Err(e) => {
            return error_to_c_string(format_err!(
                "signing to endpoint {} failed: {}",
                endpoint,
                e
            ))
        }
    };

    let signature_json = match serde_json::to_string(&sig) {
        Ok(share) => share,
        Err(e) => {
            return error_to_c_string(format_err!(
                "signing to endpoint {} failed: {}",
                endpoint,
                e
            ))
        }
    };

    CString::new(signature_json).unwrap().into_raw()
}

#[cfg(target_os = "android")]
#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn Java_com_zengo_components_kms_gotham_ECDSA_signMessage(
    env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have an
    // argument slot
    _class: JClass,
    j_endpoint: JString,
    j_auth_token: JString,
    j_message_le_hex: JString,
    j_master_key_json: JString,
    j_x_pos: jint,
    j_y_pos: jint,
    j_id: JString,
) -> jstring {
    /************************ START CONVERSION ************************/

    //Convert endpoint
    let JavaStr_endpoint = match env.get_string(j_endpoint) {
        Ok(java_endpoint) => java_endpoint,
        Err(e) => {
            return env
                .new_string(format!("Error from Rust in signMessage: {}", e.to_string()))
                .unwrap()
                .into_inner()
        }
    };

    let endpoint = match JavaStr::deref(&JavaStr_endpoint).to_str() {
        Ok(endpoint) => endpoint,
        Err(e) => {
            return env
                .new_string(format!("Error from Rust in signMessage: {}", e.to_string()))
                .unwrap()
                .into_inner()
        }
    };

    //Convert auth_token
    let JavaStr_auth_token = match env.get_string(j_auth_token) {
        Ok(java_auth_token) => java_auth_token,
        Err(e) => {
            return env
                .new_string(format!("Error from Rust in signMessage: {}", e.to_string()))
                .unwrap()
                .into_inner()
        }
    };
    let auth_token = match JavaStr::deref(&JavaStr_auth_token).to_str() {
        Ok(auth_token) => auth_token,
        Err(e) => {
            return env
                .new_string(format!("Error from Rust in signMessage: {}", e.to_string()))
                .unwrap()
                .into_inner()
        }
    };

    //Convert message_le_hex
    let JavaStr_message_le_hex = match env.get_string(j_message_le_hex) {
        Ok(java_message_le_hex) => java_message_le_hex,
        Err(e) => {
            return env
                .new_string(format!("Error from Rust in signMessage: {}", e.to_string()))
                .unwrap()
                .into_inner()
        }
    };

    let message_le_hex = match JavaStr::deref(&JavaStr_message_le_hex).to_str() {
        Ok(message_le_hex) => message_le_hex,
        Err(e) => {
            return env
                .new_string(format!("Error from Rust in signMessage: {}", e.to_string()))
                .unwrap()
                .into_inner()
        }
    };

    //Convert master_key_json
    let JavaStr_master_key_json = match env.get_string(j_master_key_json) {
        Ok(java_master_key_json) => java_master_key_json,
        Err(e) => {
            return env
                .new_string(format!("Error from Rust in signMessage: {}", e.to_string()))
                .unwrap()
                .into_inner()
        }
    };
    let master_key_json = match JavaStr::deref(&JavaStr_master_key_json).to_str() {
        Ok(master_key_json) => master_key_json,
        Err(e) => {
            return env
                .new_string(format!("Error from Rust in signMessage: {}", e.to_string()))
                .unwrap()
                .into_inner()
        }
    };

    //Convert x_pos
    let x: BigInt = BigInt::from(j_x_pos);

    //Convert y_pos
    let y: BigInt = BigInt::from(j_y_pos);

    //Convert id
    let JavaStr_id = match env.get_string(j_id) {
        Ok(java_id) => java_id,
        Err(e) => {
            return env
                .new_string(format!("Error from Rust in signMessage: {}", e.to_string()))
                .unwrap()
                .into_inner()
        }
    };
    let id = match JavaStr::deref(&JavaStr_id).to_str() {
        Ok(id) => id,
        Err(e) => {
            return env
                .new_string(format!("Error from Rust in signMessage: {}", e.to_string()))
                .unwrap()
                .into_inner()
        }
    };

    /************************ END CONVERSION ************************/

    let client_shim = ClientShim::new(endpoint.to_string(), Some(auth_token.to_string()));

    let mk: MasterKey2 = serde_json::from_str(master_key_json).unwrap();

    let mk_child: MasterKey2 = mk.get_child(vec![x.clone(), y.clone()]);

    let message: BigInt = serde_json::from_str(message_le_hex).unwrap();

    let sig = match sign(&client_shim, message, &mk_child, x, y, &id.to_string()) {
        Ok(s) => s,
        Err(e) => {
            return env
                .new_string(format!("Error from Rust in signMessage: {}", e.to_string()))
                .unwrap()
                .into_inner()
        }
    };

    let signature_json = match serde_json::to_string(&sig) {
        Ok(share) => share,
        Err(e) => {
            return env
                .new_string(format!("Error from Rust in signMessage: {}", e.to_string()))
                .unwrap()
                .into_inner()
        }
    };

    env.new_string(signature_json).unwrap().into_inner()
}
