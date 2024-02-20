// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use floating_duration::TimeFormat;

use two_party_ecdsa::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::*;
use two_party_ecdsa::party_one;
use two_party_ecdsa::kms::chain_code::two_party as chain_code;
use two_party_ecdsa::kms::ecdsa::two_party::{MasterKey2, party1};

use std::time::Instant;

use super::types::PrivateShare;
use crate::{Client, ClientShim};

use two_party_ecdsa::party_one::{Party1KeyGenFirstMessage, Party1KeyGenSecondMessage, Party1PDLFirstMessage, Party1PDLSecondMessage};

const KG_PATH_PRE: &str = "ecdsa/keygen";

pub fn get_master_key<C: Client>(client_shim: &ClientShim<C>) -> PrivateShare {
    let start = Instant::now();

    let (id, kg_party_one_first_message): (String, Party1KeyGenFirstMessage) =
        client_shim.post(&format!("{}/first", KG_PATH_PRE)).unwrap();

    let (kg_party_two_first_message, kg_ec_key_pair_party2) = MasterKey2::key_gen_first_message();

    let body = &kg_party_two_first_message.d_log_proof;

    let kg_party_one_second_message: Party1KeyGenSecondMessage = client_shim
        .postb(&format!("{}/{}/second", KG_PATH_PRE, id), body)
        .unwrap();

    let key_gen_second_message = MasterKey2::key_gen_second_message(
        &kg_party_one_first_message,
        &kg_party_one_second_message,
    );

    let (party_two_second_message, party_two_paillier, party_two_pdl_chal) =
        key_gen_second_message.unwrap();

    let body = &party_two_second_message.pdl_first_message;

    let party_one_third_message: Party1PDLFirstMessage = client_shim
        .postb(&format!("{}/{}/third", KG_PATH_PRE, id), body)
        .unwrap();

    let pdl_decom_party2 = MasterKey2::key_gen_third_message(&party_two_pdl_chal);

    let party_2_pdl_second_message = pdl_decom_party2;

    let body = &party_2_pdl_second_message;

    let party_one_pdl_second_message: Party1PDLSecondMessage = client_shim
        .postb(&format!("{}/{}/fourth", KG_PATH_PRE, id), body)
        .unwrap();

    MasterKey2::key_gen_fourth_message(
        &party_two_pdl_chal,
        &party_one_third_message,
        &party_one_pdl_second_message,
    )
    .expect("pdl error party1");

    let cc_party_one_first_message: DHPoKParty1FirstMessage = client_shim
        .post(&format!("{}/{}/chaincode/first", KG_PATH_PRE, id))
        .unwrap();

    let (cc_party_two_first_message, cc_ec_key_pair2) =
        chain_code::party2::ChainCode2::chain_code_first_message();

    let body = &cc_party_two_first_message.d_log_proof;

    let cc_party_one_second_message: DHPoKParty1SecondMessage = client_shim
        .postb(&format!("{}/{}/chaincode/second", KG_PATH_PRE, id), body)
        .unwrap();

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

    println!("(id: {}) Took: {:?}", id, TimeFormat(start.elapsed()));

    PrivateShare { id, master_key }
}