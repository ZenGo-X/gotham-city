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
        &(party2_sign_first_msg, message.clone()),
    ) {
        Some(s) => s,
        None => return Err(failure::err_msg("party1 sign first message request failed")),
    };

    // round 2: send ephemeral public keys and check commitments.
    // in the two-party setting, the counterparty can immediately return its local signature.
    let (mut party1_sign_second_msg, mut s1): (SignSecondMsg, Signature) = match requests::postb(
        client_shim,
        &format!("eddsa/sign/{}/second", id),
        &party2_sign_second_msg,
    ) {
        Some(s) => s,
        None => {
            return Err(failure::err_msg(
                "party1 sign second message request failed",
            ))
        }
    };

    let eight: FE = ECScalar::from(&BigInt::from(8u32));
    let eight_inverse: FE = eight.invert();
    party1_sign_second_msg.R = party1_sign_second_msg.R * eight_inverse;
    s1.R = s1.R * eight_inverse;
    assert!(test_com(
        &party1_sign_second_msg.R,
        &party1_sign_second_msg.blind_factor,
        &party1_sign_first_msg.commitment
    ));

    // round 3:
    // compute R' = sum(Ri):
    let Ri = vec![party1_sign_second_msg.R, party2_sign_second_msg.R];
    // each party i should run this:
    let R_tot = Signature::get_R_tot(Ri);
    let k = Signature::k(&R_tot, &key_agg.apk, BigInt::to_vec(&message).as_slice());
    let s2 = Signature::partial_sign(
        &party2_ephemeral_key.r,
        party2_key_pair,
        &k,
        &key_agg.hash,
        &R_tot,
    );

    let s = vec![s1, s2];
    let signature = Signature::add_signature_parts(s);

    // verify:
    verify(
        &signature,
        BigInt::to_bytes(&message).as_slice(),
        &key_agg.apk,
    )
    .map_err(|e| format_err!("verifying signature failed: {}", e))
    .map(|_| signature)
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

    let sig = match sign(
        &client_shim,
        &message[..],
        &key_pair,
        &key_agg,
        &id.to_string(),
    ) {
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

#[cfg(target_os = "android")]
#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn Java_com_zengo_components_kms_gotham_EdDSA_signMessageEddsa(
    env: JNIEnv,
    _class: JClass,
    j_endpoint: JString,
    j_auth_token: JString,
    j_message_le_hex: JString,
    j_key_pair_json: JString,
    j_key_agg_json: JString,
    j_id: JString,
) -> jstring {
    let endpoint = match get_String_from_JString(&env, j_endpoint) {
        Ok(s) => s,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in signMessageEddsa: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };
    let auth_token = match get_String_from_JString(&env, j_auth_token) {
        Ok(s) => s,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in signMessageEddsa: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };
    let message_hex = match get_String_from_JString(&env, j_message_le_hex) {
        Ok(s) => s,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in signMessageEddsa: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };
    let key_pair_json = match get_String_from_JString(&env, j_key_pair_json) {
        Ok(s) => s,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in signMessageEddsa: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };
    let key_agg_json = match get_String_from_JString(&env, j_key_agg_json) {
        Ok(s) => s,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in signMessageEddsa: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };
    let id = match get_String_from_JString(&env, j_id) {
        Ok(s) => s,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in signMessageEddsa: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };

    let client_shim = ClientShim::new(endpoint.to_string(), Some(auth_token.to_string()));

    let message: BigInt = serde_json::from_str(&message_hex).unwrap();

    let mut key_pair: KeyPair = serde_json::from_str(&key_pair_json).unwrap();

    let mut key_agg: KeyAgg = serde_json::from_str(&key_agg_json).unwrap();

    let eight: FE = ECScalar::from(&BigInt::from(8));
    let eight_inverse: FE = eight.invert();

    key_pair.public_key = key_pair.public_key * &eight_inverse;
    key_agg.apk = key_agg.apk * &eight_inverse;

    let sig = match sign(&client_shim, message, &key_pair, &key_agg, &id) {
        Ok(s) => s,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in signMessageEddsa: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };

    let signature_json = match serde_json::to_string(&sig) {
        Ok(share) => share,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in signMessageEddsa: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };

    env.new_string(signature_json.to_owned())
        .unwrap()
        .into_inner()
}

#[allow(non_snake_case)]
fn get_String_from_JString(env: &JNIEnv, j_string: JString) -> Result<String> {
    let java_str_string = match env.get_string(j_string) {
        Ok(java_string) => java_string,
        Err(e) => unimplemented!(),
    };

    let string_ref = match JavaStr::deref(&java_str_string).to_str() {
        Ok(string_ref) => string_ref,
        Err(e) => unimplemented!(),
    };

    Ok(string_ref.to_string())
}
