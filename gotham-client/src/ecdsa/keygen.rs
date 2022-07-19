// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use floating_duration::TimeFormat;

use two_party_ecdsa::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::*;
use two_party_ecdsa::party_one;
use kms::chain_code::two_party as chain_code;
use kms::ecdsa::two_party::{MasterKey2, party1};
// iOS bindings
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::time::Instant;

use super::types::PrivateShare;
use crate::{utilities::requests, ClientShim};

// Android bindings

use jni::objects::{JClass, JString};
use jni::strings::JavaStr;
use jni::sys::jstring;
use jni::JNIEnv;
use std::ops::Deref;

const KG_PATH_PRE: &str = "ecdsa/keygen";

pub fn get_master_key(client_shim: &ClientShim) -> PrivateShare {
    let start = PreciseTime::now();

    let (id, kg_party_one_first_message): (String, party_one::KeyGenFirstMsg) =
        requests::post(client_shim, &format!("{}/first", KG_PATH_PRE)).unwrap();

    let (kg_party_two_first_message, kg_ec_key_pair_party2) = MasterKey2::key_gen_first_message();

    let body = &kg_party_two_first_message.d_log_proof;

    let kg_party_one_second_message: party1::KeyGenParty1Message2 =
        requests::postb(client_shim, &format!("{}/{}/second", KG_PATH_PRE, id), body).unwrap();

    let key_gen_second_message = MasterKey2::key_gen_second_message(
        &kg_party_one_first_message,
        &kg_party_one_second_message,
    );

    let (party_two_second_message, party_two_paillier, party_two_pdl_chal) =
        key_gen_second_message.unwrap();

    let body = &party_two_second_message.pdl_first_message;

    let party_one_third_message: party_one::PDLFirstMessage =
        requests::postb(client_shim, &format!("{}/{}/third", KG_PATH_PRE, id), body).unwrap();

    let pdl_decom_party2 = MasterKey2::key_gen_third_message(&party_two_pdl_chal);

    let party_2_pdl_second_message = pdl_decom_party2;

    let body = &party_2_pdl_second_message;

    let party_one_pdl_second_message: party_one::PDLSecondMessage =
        requests::postb(client_shim, &format!("{}/{}/fourth", KG_PATH_PRE, id), body).unwrap();

    MasterKey2::key_gen_fourth_message(
        &party_two_pdl_chal,
        &party_one_third_message,
        &party_one_pdl_second_message,
    )
    .expect("pdl error party1");

    let cc_party_one_first_message: Party1FirstMessage = requests::post(
        client_shim,
        &format!("{}/{}/chaincode/first", KG_PATH_PRE, id),
    )
    .unwrap();

    let (cc_party_two_first_message, cc_ec_key_pair2) =
        chain_code::party2::ChainCode2::chain_code_first_message();

    let body = &cc_party_two_first_message.d_log_proof;

    let cc_party_one_second_message: Party1SecondMessage = requests::postb(
        client_shim,
        &format!("{}/{}/chaincode/second", KG_PATH_PRE, id),
        body,
    )
    .unwrap();

    let cc_party_two_second_message = chain_code::party2::ChainCode2::chain_code_second_message(
        &cc_party_one_first_message,
        &cc_party_one_second_message,
    );

    assert!(cc_party_two_second_message.is_ok());

    let party2_cc = chain_code::party2::ChainCode2::compute_chain_code(
        &cc_ec_key_pair2,
        &cc_party_one_second_message.comm_witness.public_share,
    )
    .chain_code;

    let master_key = MasterKey2::set_master_key(
        &party2_cc,
        &kg_ec_key_pair_party2,
        &kg_party_one_second_message
            .ecdh_second_message
            .comm_witness
            .public_share,
        &party_two_paillier,
    );

    let end = PreciseTime::now();
    println!("(id: {}) Took: {:?}", id, start.to(end));

    PrivateShare { id, master_key }
}

/// # Safety
///
/// - This function should only be called with valid C pointers.
/// - Arguments are accessed in arbitrary locations.
/// - Strings should be null terminated array of bytes.
#[no_mangle]
pub unsafe extern "C" fn get_client_master_key(
    c_endpoint: *const c_char,
    c_auth_token: *const c_char,
) -> *mut c_char {
    let raw_endpoint = CStr::from_ptr(c_endpoint);
    let endpoint = match raw_endpoint.to_str() {
        Ok(s) => s,
        Err(_) => panic!("Error while decoding raw endpoint"),
    };

    let raw_auth_token = CStr::from_ptr(c_auth_token);
    let auth_token = match raw_auth_token.to_str() {
        Ok(s) => s,
        Err(_) => panic!("Error while decoding auth token"),
    };

    let client_shim = ClientShim::new(endpoint.to_string(), Some(auth_token.to_string()));

    let private_share: PrivateShare = get_master_key(&client_shim);

    let private_share_json = match serde_json::to_string(&private_share) {
        Ok(share) => share,
        Err(_) => panic!("Error while performing keygen to endpoint {}", endpoint),
    };

    CString::new(private_share_json).unwrap().into_raw()
}

#[cfg(target_os = "android")]
#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn Java_com_zengo_components_kms_gotham_ECDSA_getClientMasterKey(
    env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have an
    // argument slot
    _class: JClass,
    j_endpoint: JString,
    j_auth_token: JString,
) -> jstring {
    // Convert j_endpoint JString to &str
    let JavaStr_endpoint = match env.get_string(j_endpoint) {
        Ok(java_endpoint) => java_endpoint,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in getClientMasterKey: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };

    let endpoint = match JavaStr::deref(&JavaStr_endpoint).to_str() {
        Ok(endpoint) => endpoint,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in getClientMasterKey: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };

    // Convert j_auth_token JString to &str
    let JavaStr_auth_token = match env.get_string(j_auth_token) {
        Ok(java_auth_token) => java_auth_token,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in getClientMasterKey: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };
    let auth_token = match JavaStr::deref(&JavaStr_auth_token).to_str() {
        Ok(auth_token) => auth_token,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in getClientMasterKey: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };

    let client_shim = ClientShim::new(endpoint.to_string(), Some(auth_token.to_string()));

    let private_share: PrivateShare = get_master_key(&client_shim);

    let private_share_json = match serde_json::to_string(&private_share) {
        Ok(share) => share.to_owned(),
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in getClientMasterKey: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };

    env.new_string(private_share_json).unwrap().into_inner()
}
