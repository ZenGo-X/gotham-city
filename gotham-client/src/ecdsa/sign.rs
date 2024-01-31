use failure::format_err;
use serde::{Deserialize, Serialize};
use two_party_ecdsa::kms::ecdsa::two_party::{party2, MasterKey2};
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
    pub derivation_path: Vec<BigInt>,
}

pub fn sign<C: Client>(
    client_shim: &ClientShim<C>,
    message: BigInt,
    mk: &MasterKey2,
    derivation_path: Vec<BigInt>,
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
        derivation_path,
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
    derivation_path: Vec<BigInt>,
    id: &str,
) -> Result<party_one::SignatureRecid> {
    let request: SignSecondMsgRequest = SignSecondMsgRequest {
        message,
        party_two_sign_message,
        derivation_path
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