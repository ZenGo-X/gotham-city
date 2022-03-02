// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use super::super::utilities::error_to_c_string;
use super::super::utilities::requests;
use super::super::ClientShim;
use super::super::Result;

// iOS bindings
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use two_party_musig2_eddsa::{
    generate_partial_nonces, AggPublicKeyAndMusigCoeff, KeyPair, PartialSignature,
    PublicPartialNonces, Signature,
};

#[allow(non_snake_case)]
pub fn sign(
    client_shim: &ClientShim,
    message: &[u8],
    client_keypair: &KeyPair,
    agg_pubkey: &AggPublicKeyAndMusigCoeff,
    id: &str,
) -> Result<Signature> {
    // Generate partial nonces.
    let (private_nonces, public_nonces) = generate_partial_nonces(client_keypair, Some(message));

    // Send your public nonces to the server and recv their nonces.
    let server_nonces: PublicPartialNonces = match requests::postb(
        client_shim,
        &format!("eddsa/sign/{}/first", id),
        &(public_nonces.clone(), message.to_vec()),
    ) {
        Some(s) => s,
        None => return Err(failure::err_msg("eddsa first message(nonces) failed!")),
    };

    // Validates server's response
    let server_nonces_bytes = server_nonces.serialize();
    match PublicPartialNonces::deserialize(server_nonces_bytes) {
        Some(_) => (),
        None => return Err(failure::err_msg("Received invalid public nonces from server!")),
    }

    // Create a partial signature
    let (partial_sig, agg_nonce) = client_keypair.partial_sign(
        private_nonces,
        [public_nonces, server_nonces],
        agg_pubkey,
        message,
    );

    // Send your partial signature to the server and recv their partial signature.
    let server_partial_sig: PartialSignature = match requests::postb(
        client_shim,
        &format!("eddsa/sign/{}/second", id),
        &(partial_sig),
    ) {
        Some(s) => s,
        None => return Err(failure::err_msg("eddsa second message failed!")),
    };

    // Validate server partial signature
    let server_partial_sig_bytes = server_partial_sig.serialize();
    match PartialSignature::deserialize(server_partial_sig_bytes) {
        Some(_) => (),
        None => return Err(failure::err_msg("Received invalid partial signature from server!")),
    }

    // Aggregate the partial signatures together
    let signature = Signature::aggregate_partial_signatures(agg_nonce, [partial_sig, server_partial_sig]);

    // Make sure the signature verifies against the aggregated public key
    match signature.verify(message, agg_pubkey.aggregated_pubkey()) {
        Ok(_) => Ok(signature),
        Err(e) => Err(e.into()),
    }
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
        Err(e) => {
            return error_to_c_string(format_err!("decoding raw key_pair_json failed: {}", e))
        }
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

    let message: Vec<u8> = serde_json::from_str(message_hex).unwrap();

    let key_pair: KeyPair = serde_json::from_str(key_pair_json).unwrap();

    let key_agg: AggPublicKeyAndMusigCoeff = serde_json::from_str(key_agg_json).unwrap();

    let sig = match sign(&client_shim, &message[..], &key_pair, &key_agg, &id.to_string()) {
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
        Err(e) => return error_to_c_string(format_err!("encoding signature failed: {}", e)),
    };

    CString::new(signature_json).unwrap().into_raw()
}
