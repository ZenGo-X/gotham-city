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

use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::*;
use kms::chain_code::two_party as chain_code;
use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;

use super::super::api;
use super::super::utilities::requests;

const KG_PATH_PRE: &str = "ecdsa/keygen";

pub fn get_master_key(client_shim: &api::ClientShim) -> api::PrivateShare {
    let start = PreciseTime::now();

    let res_body = requests::post(client_shim, &format!("{}/first", KG_PATH_PRE)).unwrap();

    let (id, kg_party_one_first_message): (String, party_one::KeyGenFirstMsg) =
        serde_json::from_str(&res_body).unwrap();

    let (kg_party_two_first_message, kg_ec_key_pair_party2) = MasterKey2::key_gen_first_message();

    let body = &kg_party_two_first_message.d_log_proof;

    let res_body =
        requests::postb(client_shim, &format!("{}/{}/second", KG_PATH_PRE, id), body).unwrap();

    let kg_party_one_second_message: party1::KeyGenParty1Message2 =
        serde_json::from_str(&res_body).unwrap();

    let key_gen_second_message = MasterKey2::key_gen_second_message(
        &kg_party_one_first_message,
        &kg_party_one_second_message,
    );

    let (party_two_second_message, party_two_paillier, party_two_pdl_chal) =
        key_gen_second_message.unwrap();

    let body = &party_two_second_message.pdl_first_message;

    let res_body =
        requests::postb(client_shim, &format!("{}/{}/third", KG_PATH_PRE, id), body).unwrap();

    let party_one_third_message: party_one::PDLFirstMessage =
        serde_json::from_str(&res_body).unwrap();

    let pdl_decom_party2 = MasterKey2::key_gen_third_message(&party_two_pdl_chal);

    let party_2_pdl_second_message = pdl_decom_party2;

    let body = &party_2_pdl_second_message;

    let res_body =
        requests::postb(client_shim, &format!("{}/{}/fourth", KG_PATH_PRE, id), body).unwrap();

    let party_one_pdl_second_message: party_one::PDLSecondMessage =
        serde_json::from_str(&res_body).unwrap();

    MasterKey2::key_gen_fourth_message(
        &party_two_pdl_chal,
        &party_one_third_message,
        &party_one_pdl_second_message,
    )
    .expect("pdl error party1");

    let res_body = requests::post(
        client_shim,
        &format!("{}/{}/chaincode/first", KG_PATH_PRE, id),
    )
    .unwrap();

    let cc_party_one_first_message: Party1FirstMessage = serde_json::from_str(&res_body).unwrap();

    let (cc_party_two_first_message, cc_ec_key_pair2) =
        chain_code::party2::ChainCode2::chain_code_first_message();

    let body = &cc_party_two_first_message.d_log_proof;

    let res_body = requests::postb(
        client_shim,
        &format!("{}/{}/chaincode/second", KG_PATH_PRE, id),
        body,
    )
    .unwrap();

    let cc_party_one_second_message: Party1SecondMessage = serde_json::from_str(&res_body).unwrap();

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
    println!("(id: {}) Took: {}", id, start.to(end));

    api::PrivateShare { id, master_key }
}
