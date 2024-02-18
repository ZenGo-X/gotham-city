use failure::format_err;
use serde::{Deserialize, Serialize};
use two_party_ecdsa::kms::ecdsa::two_party::{party2, MasterKey2};
use two_party_ecdsa::{curv::BigInt, party_one, party_two};
use two_party_ecdsa::kms::ecdsa::two_party::party2::{Party2SignMessage, Party2SignSecondMessageVector};
use two_party_ecdsa::party_one::{Party1EphKeyGenFirstMessage, Party1SignatureRecid};
use two_party_ecdsa::party_two::Party2EphKeyGenFirstMessage;

use crate::{ Client, ClientShim, Result};


pub fn sign<C: Client>(
    client_shim: &ClientShim<C>,
    message: BigInt,
    mk: &MasterKey2,
    derivation_path: Vec<BigInt>,
    id: &str,
) -> Result<Party1SignatureRecid> {
    let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
        MasterKey2::sign_first_message();

    let request: Party2EphKeyGenFirstMessage = eph_key_gen_first_message_party_two;
    let sign_party_one_first_message: Party1EphKeyGenFirstMessage =
        match client_shim.postb(&format!("/ecdsa/sign_v3/{}/first", id), &request) {
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
    party_two_sign_message: Party2SignMessage,
    pos_child_key: Vec<BigInt>,
    id: &str,
) -> Result<Party1SignatureRecid> {
    let request: Party2SignSecondMessageVector = Party2SignSecondMessageVector {
        message,
        party_two_sign_message,
        pos_child_key,
    };

    let signature: Party1SignatureRecid =
        match client_shim.postb(&format!("/ecdsa/sign_v3/{}/second", id), &request) {
            Some(s) => s,
            None => {
                return Err(failure::err_msg(
                    "party1 sign second message request failed",
                ))
            }
        };

    Ok(signature)
}