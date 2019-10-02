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
use super::super::ClientShim;

// iOS bindings
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use multi_party_eddsa::protocols::aggsig::*;

const PARTY2_INDEX: usize = 1; // client (self)

pub fn generate_key(client_shim: &ClientShim) -> Result<(KeyPair, KeyAgg, String)> {
    let party2_key_pair: KeyPair = KeyPair::create();
    let (id, mut party1_public_key): (String, GE) = requests::postb(
        client_shim,
        &format!("eddsa/keygen"),
        &party2_key_pair.public_key)
        .unwrap();
    let eight: FE = ECScalar::from(&BigInt::from(8));
    let eight_inverse: FE = eight.invert();
    party1_public_key = party1_public_key * &eight_inverse;

    // compute apk:
    let mut pks: Vec<GE> = Vec::new();
    pks.push(party1_public_key.clone());
    pks.push(party2_key_pair.public_key.clone());
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

    CString::new(key_json.to_owned())
        .unwrap()
        .into_raw()
}
