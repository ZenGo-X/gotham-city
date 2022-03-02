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

use two_party_musig2_eddsa::{KeyPair, AggPublicKeyAndMusigCoeff};

// iOS bindings
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Generate a keypair for 2-party Ed25519 signing
pub fn generate_key(client_shim: &ClientShim) -> Result<(KeyPair, AggPublicKeyAndMusigCoeff, String)> {
    let (client_key_pair, _) = KeyPair::create();
    
    // Send public key to server and receive its public key
    let (id, server_pubkey): (String, [u8; 32]) = requests::postb(
        client_shim,
        "eddsa/keygen",
        &client_key_pair.pubkey())
        .unwrap();
    
    // Compute aggregated pubkey and a "musig coefficient" used later for signing - fails if received invalid pubkey!
    let agg_pubkey = AggPublicKeyAndMusigCoeff::aggregate_public_keys(client_key_pair.pubkey(), server_pubkey);
    
    match agg_pubkey {
        Ok(agg_pubkey) => Ok((client_key_pair, agg_pubkey, id)),
        Err(e) => Err(e.into()),
    }
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

    let key: (KeyPair, AggPublicKeyAndMusigCoeff, String) = match generate_key(&client_shim) {
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
