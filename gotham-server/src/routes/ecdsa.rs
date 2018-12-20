// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use kms::ecdsa::two_party::*;
use kms::chain_code::two_party as chain_code;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use zk_paillier::zkproofs::*;
use curv::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use curv::cryptographic_primitives::twoparty::dh_key_exchange::*;
use curv::{BigInt, FE, GE};
use rocket::State;
use rocket_contrib::json::{Json};
use uuid::Uuid;
use rocksdb::DB;
use serde_json;
use std::string::ToString;

use super::super::utilities::db;

#[derive(ToString, Debug)]
pub enum Share {
    KeyGenFirstMsg,
    CommWitness,
    EcKeyPair,
    PaillierKeyPair,
    Party1Private,

    PDLProver,
    PDLDecommit,
    PDLFirstMessage,

    CCKeyGenFirstMsg,
    CCCommWitness,
    CCEcKeyPair,
    CC,

    MasterKey,

    EphEcKeyPair
}

pub struct Config {
    pub db : DB
}

#[post("/ecdsa/keygen/first", format = "json")]
pub fn first_message(
    state: State<Config>
) -> Json<(
    String,
    party_one::KeyGenFirstMsg,
)> {
    let id = Uuid::new_v4().to_string();

    let (key_gen_first_msg, comm_witness, ec_key_pair) =
        MasterKey1::key_gen_first_message();

    db::insert(&state.db, &id, &Share::KeyGenFirstMsg, &key_gen_first_msg);
    db::insert(&state.db, &id, &Share::CommWitness, &comm_witness);
    db::insert(&state.db, &id, &Share::EcKeyPair, &ec_key_pair);

    Json((id, key_gen_first_msg))
}


#[post("/ecdsa/keygen/<id>/second", format = "json", data = "<d_log_proof>")]
pub fn second_message(
    state: State<Config>,
    id: String,
    d_log_proof: Json<DLogProof>
) -> Json<(
    party1::KeyGenParty1Message2,
    party_one::PaillierKeyPair
)>
{
    let db_comm_witness = db::get(&state.db, &id, &Share::CommWitness);
    let comm_witness: party_one::CommWitness = match db_comm_witness {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let ec_key_pair = db::get(&state.db, &id, &Share::EcKeyPair);
    let ec_key_pair: party_one::EcKeyPair = match ec_key_pair {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let (kg_party_one_second_message, paillier_key_pair, party_one_private) =
        MasterKey1::key_gen_second_message(comm_witness, &ec_key_pair, &d_log_proof.0);

    db::insert(&state.db, &id, &Share::PaillierKeyPair, &paillier_key_pair);
    db::insert(&state.db, &id, &Share::Party1Private, &party_one_private);

    Json((kg_party_one_second_message, paillier_key_pair))
}

#[post("/ecdsa/keygen/<id>/third", format = "json", data = "<party_2_pdl_first_message>")]
pub fn third_message(
    state: State<Config>,
    id: String,
    party_2_pdl_first_message: Json<party_two::PDLFirstMessage>
) -> Json<(
    party_one::PDLFirstMessage
)>
{
    let db_paillier_key_pair = db::get(&state.db, &id, &Share::PaillierKeyPair);
    let paillier_key_pair: party_one::PaillierKeyPair = match db_paillier_key_pair {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let db_party_one_private = db::get(&state.db, &id, &Share::Party1Private);
    let party_one_private: party_one::Party1Private = match db_party_one_private {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let (party_one_third_message, party_one_pdl_decommit) =
        MasterKey1::key_gen_third_message(&party_2_pdl_first_message.0, &party_one_private);

    db::insert(&state.db, &id, &Share::PDLDecommit, &party_one_pdl_decommit);
    db::insert(&state.db, &id, &Share::PDLFirstMessage, &party_one_third_message);

    Json(party_one_third_message)
}

// Added here because the attribute data takes only a single struct
#[derive(Serialize, Deserialize)]
pub struct FourthMsgRequest {
    pub party_2_pdl_first_message: party_two::PDLFirstMessage,
    pub party_2_pdl_second_message: party_two::PDLSecondMessage
}

#[post("/ecdsa/keygen/<id>/fourth", format = "json", data = "<request>")]
pub fn fourth_message(
    state: State<Config>,
    id: String,
    request: Json<FourthMsgRequest>
) -> Json<(
    party_one::PDLSecondMessage
)>
{
    let db_pdl_party_one_third_message = db::get(&state.db, &id, &Share::PDLFirstMessage);
    let pdl_party_one_third_message : party_one::PDLFirstMessage = match db_pdl_party_one_third_message {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let db_party_one_private = db::get(&state.db, &id, &Share::Party1Private);
    let party_one_private: party_one::Party1Private = match db_party_one_private {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let db_party_one_pdl_decommit = db::get(&state.db, &id, &Share::PDLDecommit);
    let party_one_pdl_decommit: party_one::PDLdecommit = match db_party_one_pdl_decommit {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let res = MasterKey1::key_gen_fourth_message(
        &pdl_party_one_third_message,
        &request.party_2_pdl_first_message,
        &request.party_2_pdl_second_message,
        party_one_private,
        party_one_pdl_decommit);

    assert!(res.is_ok());

    Json(res.unwrap())
}

#[post("/ecdsa/keygen/<id>/chaincode/first", format = "json")]
pub fn chain_code_first_message(
    state: State<Config>,
    id: String,
) -> Json<(
    Party1FirstMessage
)>
{
    let (cc_party_one_first_message, cc_comm_witness, cc_ec_key_pair1) =
        chain_code::party1::ChainCode1::chain_code_first_message();

    db::insert(&state.db, &id, &Share::CCKeyGenFirstMsg, &cc_party_one_first_message);
    db::insert(&state.db, &id, &Share::CCCommWitness, &cc_comm_witness);
    db::insert(&state.db, &id, &Share::CCEcKeyPair, &cc_ec_key_pair1);

    Json(cc_party_one_first_message)
}

#[post("/ecdsa/keygen/<id>/chaincode/second", format = "json", data = "<cc_party_two_first_message_d_log_proof>")]
pub fn chain_code_second_message(
    state: State<Config>,
    id: String,
    cc_party_two_first_message_d_log_proof: Json<DLogProof>
) -> Json<(
    Party1SecondMessage
)>
{
    let db_cc_comm_witness = db::get(&state.db, &id, &Share::CCCommWitness);
    let cc_comm_witness: CommWitness = match db_cc_comm_witness {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let party1_cc= chain_code::party1::ChainCode1::chain_code_second_message(
        cc_comm_witness,
        &cc_party_two_first_message_d_log_proof.0
    );

    Json(party1_cc)
}

#[post("/ecdsa/keygen/<id>/chaincode/compute", format = "json", data = "<cc_party_two_first_message_public_share>")]
pub fn chain_code_compute_message(
    state: State<Config>,
    id: String,
    cc_party_two_first_message_public_share: Json<GE>
) -> Json<(

)>
{
    let cc_ec_key_pair = db::get(&state.db, &id, &Share::CCEcKeyPair);
    let cc_ec_key_pair_party1:  EcKeyPair = match cc_ec_key_pair {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let party1_cc= chain_code::party1::ChainCode1::compute_chain_code(
        &cc_ec_key_pair_party1,
        &cc_party_two_first_message_public_share.0
    );

    db::insert(&state.db, &id, &Share::CC, &party1_cc);

    Json(())
}


#[post("/ecdsa/keygen/<id>/master_key", format = "json", data = "<kg_party_two_first_message_public_share>")]
pub fn master_key(
    state: State<Config>,
    id: String,
    kg_party_two_first_message_public_share: Json<GE>
) -> Json<(

)>
{
    let db_paillier_key_pair = db::get(&state.db, &id, &Share::PaillierKeyPair);
    let paillier_key_pair: party_one::PaillierKeyPair = match db_paillier_key_pair {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let db_party1_cc = db::get(&state.db, &id, &Share::CC);
    let party1_cc: chain_code::party1::ChainCode1 = match db_party1_cc {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let db_party_one_private = db::get(&state.db, &id, &Share::Party1Private);
    let party_one_private: party_one::Party1Private = match db_party_one_private {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let db_comm_witness = db::get(&state.db, &id, &Share::CommWitness);
    let comm_witness: party_one::CommWitness = match db_comm_witness {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let masterKey = MasterKey1::set_master_key(
        &party1_cc.chain_code,
        party_one_private,
        &comm_witness.public_share,
        &kg_party_two_first_message_public_share.0,
        paillier_key_pair
    );

    db::insert(&state.db, &id, &Share::MasterKey, &masterKey);

    Json(())
}

#[post("/ecdsa/sign/<id>/first", format = "json")]
pub fn sign_first(
    state: State<Config>,
    id: String
) -> Json<(
    party_one::EphKeyGenFirstMsg
)>
{
    let (sign_party_one_first_message, eph_ec_key_pair_party1) =
        MasterKey1::sign_first_message();

    db::insert(&state.db, &id, &Share::EphEcKeyPair, &eph_ec_key_pair_party1);

    Json(sign_party_one_first_message)
}

// Added here because the attribute data takes only a single struct
#[derive(Serialize, Deserialize)]
pub struct SignSecondMsgRequest {
    pub message: BigInt,
    pub party_two_sign_message: party2::SignMessage,
    pub eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg,
    pub pos_child_key: u32
}

#[post("/ecdsa/sign/<id>/second", format = "json", data = "<request>")]
pub fn sign_second(
    state: State<Config>,
    id: String,
    request: Json<SignSecondMsgRequest>
) -> Json<(
    party_one::Signature
)>
{

    let db_master_key = db::get(&state.db, &id, &Share::MasterKey);
    let master_key: MasterKey1 = match db_master_key {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let child_master_key = master_key.get_child(vec![BigInt::from(request.pos_child_key)]);

    let db_eph_ec_key_pair_party1 = db::get(&state.db, &id, &Share::EphEcKeyPair);
    let eph_ec_key_pair_party1: party_one::EphEcKeyPair = match db_eph_ec_key_pair_party1 {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let signatures = child_master_key.sign_second_message(
        &request.party_two_sign_message,
        &request.eph_key_gen_first_message_party_two,
        &eph_ec_key_pair_party1,
        &request.message,
    );

    assert!(signatures.is_ok());

    Json(signatures.unwrap())
}