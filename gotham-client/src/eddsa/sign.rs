// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use super::super::utilities::requests;
use super::super::utilities::error_to_c_string;
use super::super::Result;
use super::super::ClientShim;

// iOS bindings
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use multi_party_eddsa::protocols::aggsig::*;

#[allow(non_snake_case)]
pub fn sign(
    client_shim: &ClientShim,
    message: BigInt,
    party2_key_pair: &KeyPair,
    key_agg: &KeyAgg,
    id: &String
) -> Result<Signature> {
    // round 1: send commitments to ephemeral public keys
    let (party2_ephemeral_key, party2_sign_first_msg, party2_sign_second_msg) =
        Signature::create_ephemeral_key_and_commit(&party2_key_pair, BigInt::to_vec(&message).as_slice());

    let party1_sign_first_msg: SignFirstMsg = match requests::postb(
        client_shim,
        &format!("eddsa/sign/{}/first", id),
        &(party2_sign_first_msg, message.clone())) {
            Some(s) => s,
            None => return Err(failure::err_msg("party1 sign first message request failed"))
        };

    // round 2: send ephemeral public keys and check commitments.
    // in the two-party setting, the counterparty can immediately return its local signature.
    let (mut party1_sign_second_msg, mut s1): (SignSecondMsg, Signature) = match requests::postb(
        client_shim,
        &format!("eddsa/sign/{}/second", id),
        &party2_sign_second_msg) {
            Some(s) => s,
            None => return Err(failure::err_msg("party1 sign second message request failed"))
        };

    let eight: FE = ECScalar::from(&BigInt::from(8));
    let eight_inverse: FE = eight.invert();
    party1_sign_second_msg.R = party1_sign_second_msg.R * &eight_inverse;
    s1.R = s1.R * &eight_inverse;
    assert!(test_com(
        &party1_sign_second_msg.R,
        &party1_sign_second_msg.blind_factor,
        &party1_sign_first_msg.commitment
    ));

    // round 3:
    // compute R' = sum(Ri):
    let mut Ri: Vec<GE> = Vec::new();
    Ri.push(party1_sign_second_msg.R.clone());
    Ri.push(party2_sign_second_msg.R.clone());
    // each party i should run this:
    let R_tot = Signature::get_R_tot(Ri);
    let k = Signature::k(&R_tot, &key_agg.apk, BigInt::to_vec(&message).as_slice());
    let s2 = Signature::partial_sign(
        &party2_ephemeral_key.r,
        &party2_key_pair,
        &k,
        &key_agg.hash,
        &R_tot,
    );

    let mut s: Vec<Signature> = Vec::new();
    s.push(s1);
    s.push(s2);
    let signature = Signature::add_signature_parts(s);

    // verify:
    verify(&signature, BigInt::to_vec(&message).as_slice(), &key_agg.apk)
        .or_else(|e| Err(format_err!("verifying signature failed: {}", e)))
        .and_then(|_| Ok(signature))
}

#[no_mangle]
pub extern "C" fn sign_message_eddsa(
    c_endpoint: *const c_char,
    c_auth_token: *const c_char,
    c_message_le_hex: *const c_char,
    c_key_pair_json: *const c_char,
    c_key_agg_json: *const c_char,
    c_id: *const c_char,
) -> *mut c_char {
    let raw_endpoint = unsafe { CStr::from_ptr(c_endpoint) };
    let endpoint = match raw_endpoint.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw endpoint failed: {}", e)),
    };

    let raw_auth_token = unsafe { CStr::from_ptr(c_auth_token) };
    let auth_token = match raw_auth_token.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw auth_token failed: {}", e)),
    };

    let raw_message_hex = unsafe { CStr::from_ptr(c_message_le_hex) };
    let message_hex = match raw_message_hex.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw message_hex failed: {}", e)),
    };

    let raw_key_pair_json = unsafe { CStr::from_ptr(c_key_pair_json) };
    let key_pair_json = match raw_key_pair_json.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw key_pair_json failed: {}", e)),
    };

    let raw_key_agg_json = unsafe { CStr::from_ptr(c_key_agg_json) };
    let key_agg_json = match raw_key_agg_json.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw key_agg_json failed: {}", e)),
    };

    let raw_id = unsafe { CStr::from_ptr(c_id) };
    let id = match raw_id.to_str() {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("decoding raw id failed: {}", e)),
    };

    let client_shim = ClientShim::new(endpoint.to_string(), Some(auth_token.to_string()));

    let message: BigInt = serde_json::from_str(message_hex).unwrap();

    let mut key_pair: KeyPair = serde_json::from_str(key_pair_json).unwrap();

    let mut key_agg: KeyAgg = serde_json::from_str(key_agg_json).unwrap();

    let eight: FE = ECScalar::from(&BigInt::from(8));
    let eight_inverse: FE = eight.invert();

    key_pair.public_key = key_pair.public_key * &eight_inverse;
    key_agg.apk = key_agg.apk * &eight_inverse;

    let sig = match sign(&client_shim, message, &key_pair, &key_agg, &id.to_string()) {
        Ok(s) => s,
        Err(e) => return error_to_c_string(format_err!("signing to endpoint {} failed: {}", endpoint, e))
    };

    let signature_json = match serde_json::to_string(&sig) {
        Ok(share) => share,
        Err(e) => return error_to_c_string(format_err!("encoding signature failed: {}", e)),
    };

    CString::new(signature_json.to_owned()).unwrap().into_raw()
}
