// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use serde_json;
use time::PreciseTime;

use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::Party1FirstMessage as CCParty1FirstMessage;
use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::Party1SecondMessage as CCParty1SecondMessage;
use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::Party2FirstMessage as CCParty2FirstMessage;
use curv::FE;
use kms::chain_code::two_party as chain_code;
use kms::ecdsa::two_party_gg18::*;

use super::super::api;
use super::super::utilities::requests;

#[derive(Serialize, Deserialize)]
pub struct Party1KeyGenCCFirst {
    pub party1_message1: KeyGenMessage1,
    pub cc_party1_message1: CCParty1FirstMessage,
    pub id: String,
}

#[derive(Serialize, Deserialize)]
pub struct Party1KeyGenCCSecond {
    pub party1_message2: KeyGenMessage2,
    pub cc_party1_message2: CCParty1SecondMessage,
}

const KG_PATH_PRE: &str = "ecdsa/keygen";

pub fn get_master_key_new(id: String, u: FE, client_shim: &api::ClientShim) -> api::PrivateShareGG {
    let start = PreciseTime::now();
    let (party1_message1, party1_additive_key, party1_decom1) =
        MasterKey1::key_gen_first_message(u);

    // starting chain code protocol in parallel:
    let (cc_party1_message1, cc_comm_witness, cc_ec_key_pair1) =
        chain_code::party1::ChainCode1::chain_code_first_message();

    let body = &Party1KeyGenCCFirst {
        party1_message1: party1_message1.clone(),
        cc_party1_message1,
        id,
    };
    let res_body = requests::postb(client_shim, &format!("{}/first", KG_PATH_PRE), body).unwrap();

    let (id, party2_message1, cc_party2_message1): (String, KeyGenMessage1, CCParty2FirstMessage) =
        serde_json::from_str(&res_body).unwrap();
    let party1_message2 = MasterKey1::keygen_second_message(party1_decom1);

    // adding chain code
    let cc_party1_message2 = chain_code::party1::ChainCode1::chain_code_second_message(
        cc_comm_witness,
        &cc_party2_message1.d_log_proof,
    );

    let party1_message2 = Party1KeyGenCCSecond {
        party1_message2,
        cc_party1_message2,
    };
    let body = &party1_message2;

    let cc_party2_pub = &cc_party2_message1.public_share;

    let party1_cc =
        chain_code::party1::ChainCode1::compute_chain_code(&cc_ec_key_pair1, &cc_party2_pub);
    let res_body =
        requests::postb(client_shim, &format!("{}/{}/second", KG_PATH_PRE, id), body).unwrap();

    let party2_message2: KeyGenMessage2 = serde_json::from_str(&res_body).unwrap();
    let (party1_message3, ss1_to_self, party1_y_vec, party1_ek_vec) =
        MasterKey1::key_gen_third_message(
            &party1_additive_key,
            party1_message1,
            party2_message1,
            party1_message2.party1_message2,
            party2_message2,
        );

    let body = &party1_message3;

    let res_body =
        requests::postb(client_shim, &format!("{}/{}/third", KG_PATH_PRE, id), body).unwrap();

    let party2_message3: KeyGenMessage3 = serde_json::from_str(&res_body).unwrap();

    let (party1_message4, party1_linear_key, party1_vss_vec) = MasterKey1::key_gen_fourth_message(
        &party1_additive_key,
        party1_message3,
        party2_message3,
        ss1_to_self,
        &party1_y_vec,
    );

    let body = &party1_message4;

    let res_body =
        requests::postb(client_shim, &format!("{}/{}/fourth", KG_PATH_PRE, id), body).unwrap();

    let party2_message4: KeyGenMessage4 = serde_json::from_str(&res_body).unwrap();

    let master_key = MasterKey1::set_master_key(
        party1_message4,
        party2_message4,
        party1_y_vec.clone(),
        party1_additive_key,
        party1_linear_key,
        party1_vss_vec,
        party1_ek_vec,
        &party1_cc.chain_code,
    );

    let end = PreciseTime::now();
    println!("(id: {}) Took: {}", id, start.to(end));

    api::PrivateShareGG { id, master_key }
}
