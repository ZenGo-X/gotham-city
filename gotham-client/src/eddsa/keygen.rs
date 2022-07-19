// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use super::super::utilities::requests;
use super::super::Result;
use crate::ClientShim;

use two_party_ecdsa::curv::elliptic::curves::ed25519::{FE, GE};
use two_party_ecdsa::curv::BigInt;
// iOS bindings
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

// Android bindings
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::strings::JavaStr;
use std::ops::Deref;

use multi_party_ed25519::protocols::aggsig::*;

const PARTY2_INDEX: usize = 1; // client (self)

pub fn generate_key(client_shim: &ClientShim) -> Result<(KeyPair, KeyAgg, String)> {
    let party2_key_pair: KeyPair = KeyPair::create();
    let (id, mut party1_public_key): (String, GE) = requests::postb(
        client_shim,
        "eddsa/keygen",
        &party2_key_pair.public_key)
        .unwrap();
    let eight: FE = ECScalar::from(&BigInt::from(8));
    let eight_inverse: FE = eight.invert();
    party1_public_key = party1_public_key * eight_inverse;

    // compute apk:
    let pks: Vec<GE> = vec![ party1_public_key, party2_key_pair.public_key];
    let key_agg = KeyPair::key_aggregation_n(&pks, &PARTY2_INDEX);

    Ok((party2_key_pair, key_agg, id))
}

#[no_mangle]
pub extern "C" fn generate_client_key(
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

    let key: (KeyPair, KeyAgg, String) = match generate_key(&client_shim) {
        Ok(k) => k,
        Err(_) => panic!("Error while performing keygen to endpoint {}", endpoint),
    };

    let key_json = match serde_json::to_string(&key) {
        Ok(kj) => kj,
        Err(_) => panic!("Error while encoding key"),
    };

    CString::new(key_json)
        .unwrap()
        .into_raw()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EdDSAShareWrapper {
    keys_pair: KeyPair,
    key_agg: KeyAgg,
    id: String
}

#[cfg(target_os="android")]
#[no_mangle]
#[allow(non_snake_case)]
pub extern fn
Java_com_zengo_components_kms_gotham_EdDSA_generateClientKey(
    env: JNIEnv,
    _class: JClass,
    j_endpoint: JString,
    j_auth_token: JString,
) -> jstring {

    // Convert j_endpoint JString to &str
    let JavaStr_endpoint = match env.get_string(j_endpoint) {
        Ok(java_endpoint) => java_endpoint,
        Err(e) => return env.new_string(format!("Error from Rust in generateClientKey: {}", e.to_string()))
            .unwrap()
            .into_inner()
    };

    let endpoint = match JavaStr::deref(&JavaStr_endpoint).to_str() {
        Ok(endpoint) => endpoint,
        Err(e) => return env.new_string(format!("Error from Rust in generateClientKey: {}", e.to_string()))
            .unwrap()
            .into_inner()
    };

    // Convert j_auth_token JString to &str
    let JavaStr_auth_token= match env.get_string(j_auth_token) {
        Ok(java_auth_token) => java_auth_token,
        Err(e) => return env.new_string(format!("Error from Rust in generateClientKey: {}", e.to_string()))
            .unwrap()
            .into_inner()
    };
    let auth_token = match JavaStr::deref(&JavaStr_auth_token).to_str() {
        Ok(auth_token) => auth_token,
        Err(e) => return env.new_string(format!("Error from Rust in generateClientKey: {}", e.to_string()))
            .unwrap()
            .into_inner()
    };

    let client_shim = ClientShim::new(endpoint.to_string(), Some(auth_token.to_string()));

    let (keys_pair, key_agg, id): (KeyPair, KeyAgg, String) = match generate_key(&client_shim) {
        Ok((keys_pair, key_agg, id)) => (keys_pair, key_agg, id),
        Err(e) => return env.new_string(format!("Error from Rust in generateClientKey: {}", e.to_string()))
            .unwrap()
            .into_inner()
    };

    let eddsa_share_wrapper = EdDSAShareWrapper { keys_pair, key_agg, id };

    let key_json = match serde_json::to_string(&eddsa_share_wrapper) {
        Ok(kj) => kj,
        Err(e) => return env.new_string(format!("Error from Rust in generateClientKey: {}", e.to_string()))
            .unwrap()
            .into_inner()
    };

    return env.new_string(key_json)
        .unwrap()
        .into_inner();
}
