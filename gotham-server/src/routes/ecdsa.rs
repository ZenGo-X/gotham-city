#![allow(non_snake_case)]
// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use super::super::Result;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::{
    CommWitness, EcKeyPair, Party1FirstMessage, Party1SecondMessage,
};
use curv::elliptic::curves::secp256_k1::Secp256k1Scalar;
use curv::{BigInt, GE};
use kms::chain_code::two_party as chain_code;
use kms::ecdsa::two_party::*;
use kms::rotation::two_party::party1::Rotation1;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use rocket::State;
use rocket_contrib::json::Json;
use std::string::ToString;
use uuid::Uuid;

use super::super::auth::jwt::Claims;
use super::super::storage::db;
use super::super::Config;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct HDPos {
    pos: u32,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct Alpha {
    value: BigInt
}

#[derive(Debug)]
pub enum EcdsaStruct {
    KeyGenFirstMsg,
    CommWitness,
    EcKeyPair,
    PaillierKeyPair,
    Party1Private,
    Party2Public,

    PDLProver,
    PDLDecommit,
    Alpha,
    Party2PDLFirstMsg,

    CCKeyGenFirstMsg,
    CCCommWitness,
    CCEcKeyPair,
    CC,

    Party1MasterKey,

    EphEcKeyPair,
    EphKeyGenFirstMsg,

    RotateCommitMessage1M,
    RotateCommitMessage1R,
    RotateRandom1,
    RotateFirstMsg,
    RotatePrivateNew,
    RotatePdlDecom,
    RotateParty2First,
    RotateParty1Second,

    POS,
}

impl db::MPCStruct for EcdsaStruct {
    fn to_string(&self) -> String {
        format!("{:?}", self)
    }

    // backward compatibility
    fn to_table_name(&self, env: &str) -> String {
        if self.to_string() == "Party1MasterKey" {
            format!("{}_{}", env, self.to_string())
        } else {
            format!("{}-gotham-{}", env, self.to_string())
        }
    }

    fn require_customer_id(&self) -> bool {
        self.to_string() == "Party1MasterKey"
    }
}

#[post("/ecdsa/keygen/first", format = "json")]
pub fn first_message(
    state: State<Config>,
    claim: Claims,
) -> Result<Json<(String, party_one::KeyGenFirstMsg)>> {
    let id = Uuid::new_v4().to_string();

    let (key_gen_first_msg, comm_witness, ec_key_pair) = MasterKey1::key_gen_first_message();

    //save pos 0
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::POS,
        &HDPos { pos: 0u32 },
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::KeyGenFirstMsg,
        &key_gen_first_msg,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::CommWitness,
        &comm_witness,
    )?;
    db::insert(&state.db, &claim.sub, &id, &EcdsaStruct::EcKeyPair, &ec_key_pair)?;

    Ok(Json((id, key_gen_first_msg)))
}

#[post("/ecdsa/keygen/<id>/second", format = "json", data = "<dlog_proof>")]
pub fn second_message(
    state: State<Config>,
    claim: Claims,
    id: String,
    dlog_proof: Json<DLogProof>,
) -> Result<Json<party1::KeyGenParty1Message2>> {
    let party2_public: GE = dlog_proof.0.pk.clone();
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::Party2Public,
        &party2_public,
    )?;

    let comm_witness: party_one::CommWitness =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::CommWitness)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let ec_key_pair: party_one::EcKeyPair = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::EcKeyPair)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let (kg_party_one_second_message, paillier_key_pair, party_one_private) =
        MasterKey1::key_gen_second_message(comm_witness, &ec_key_pair, &dlog_proof.0);

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::PaillierKeyPair,
        &paillier_key_pair,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::Party1Private,
        &party_one_private,
    )?;

    Ok(Json(kg_party_one_second_message))
}

#[post(
    "/ecdsa/keygen/<id>/third",
    format = "json",
    data = "<party_2_pdl_first_message>"
)]
pub fn third_message(
    state: State<Config>,
    claim: Claims,
    id: String,
    party_2_pdl_first_message: Json<party_two::PDLFirstMessage>,
) -> Result<Json<(party_one::PDLFirstMessage)>> {
    let party_one_private: party_one::Party1Private =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Party1Private)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let (party_one_third_message, party_one_pdl_decommit, alpha) =
        MasterKey1::key_gen_third_message(&party_2_pdl_first_message.0, &party_one_private);

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::PDLDecommit,
        &party_one_pdl_decommit,
    )?;

    db::insert(&state.db, &claim.sub, &id, &EcdsaStruct::Alpha, &Alpha { value: alpha })?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::Party2PDLFirstMsg,
        &party_2_pdl_first_message.0,
    )?;

    Ok(Json(party_one_third_message))
}

#[post(
    "/ecdsa/keygen/<id>/fourth",
    format = "json",
    data = "<party_two_pdl_second_message>"
)]
pub fn fourth_message(
    state: State<Config>,
    claim: Claims,
    id: String,
    party_two_pdl_second_message: Json<party_two::PDLSecondMessage>,
) -> Result<Json<(party_one::PDLSecondMessage)>> {
    let party_one_private: party_one::Party1Private =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Party1Private)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party_one_pdl_decommit: party_one::PDLdecommit =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::PDLDecommit)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party_2_pdl_first_message: party_two::PDLFirstMessage =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Party2PDLFirstMsg)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let alpha: Alpha = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Alpha)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let res = MasterKey1::key_gen_fourth_message(
        &party_2_pdl_first_message,
        &party_two_pdl_second_message.0,
        party_one_private,
        party_one_pdl_decommit,
        alpha.value,
    );

    assert!(res.is_ok());

    Ok(Json(res.unwrap()))
}

#[post("/ecdsa/keygen/<id>/chaincode/first", format = "json")]
pub fn chain_code_first_message(
    state: State<Config>,
    claim: Claims,
    id: String,
) -> Result<Json<(Party1FirstMessage)>> {
    let (cc_party_one_first_message, cc_comm_witness, cc_ec_key_pair1) =
        chain_code::party1::ChainCode1::chain_code_first_message();

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::CCKeyGenFirstMsg,
        &cc_party_one_first_message,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::CCCommWitness,
        &cc_comm_witness,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::CCEcKeyPair,
        &cc_ec_key_pair1,
    )?;

    Ok(Json(cc_party_one_first_message))
}

#[post(
    "/ecdsa/keygen/<id>/chaincode/second",
    format = "json",
    data = "<cc_party_two_first_message_d_log_proof>"
)]
pub fn chain_code_second_message(
    state: State<Config>,
    claim: Claims,
    id: String,
    cc_party_two_first_message_d_log_proof: Json<DLogProof>,
) -> Result<Json<(Party1SecondMessage)>> {
    let cc_comm_witness: CommWitness = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::CCCommWitness)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let party1_cc = chain_code::party1::ChainCode1::chain_code_second_message(
        cc_comm_witness,
        &cc_party_two_first_message_d_log_proof.0,
    );

    let party2_pub = &cc_party_two_first_message_d_log_proof.pk;
    chain_code_compute_message(state, claim, id, party2_pub)?;

    Ok(Json(party1_cc))
}

pub fn chain_code_compute_message(
    state: State<Config>,
    claim: Claims,
    id: String,
    cc_party2_public: &GE,
) -> Result<Json<()>> {
    let cc_ec_key_pair_party1: EcKeyPair =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::CCEcKeyPair)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let party1_cc = chain_code::party1::ChainCode1::compute_chain_code(
        &cc_ec_key_pair_party1,
        &cc_party2_public,
    );

    db::insert(&state.db, &claim.sub, &id, &EcdsaStruct::CC, &party1_cc)?;
    master_key(state, claim, id)?;
    Ok(Json(()))
}

pub fn master_key(state: State<Config>, claim: Claims, id: String) -> Result<()> {
    let party2_public: GE = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Party2Public)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let paillier_key_pair: party_one::PaillierKeyPair =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::PaillierKeyPair)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party1_cc: chain_code::party1::ChainCode1 =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::CC)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party_one_private: party_one::Party1Private =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Party1Private)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let comm_witness: party_one::CommWitness =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::CommWitness)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let masterKey = MasterKey1::set_master_key(
        &party1_cc.chain_code,
        party_one_private,
        &comm_witness.public_share,
        &party2_public,
        paillier_key_pair,
    );

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::Party1MasterKey,
        &masterKey,
    )
}

#[post(
    "/ecdsa/sign/<id>/first",
    format = "json",
    data = "<eph_key_gen_first_message_party_two>"
)]
pub fn sign_first(
    state: State<Config>,
    claim: Claims,
    id: String,
    eph_key_gen_first_message_party_two: Json<party_two::EphKeyGenFirstMsg>,
) -> Result<Json<(party_one::EphKeyGenFirstMsg)>> {
    let (sign_party_one_first_message, eph_ec_key_pair_party1) = MasterKey1::sign_first_message();

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::EphKeyGenFirstMsg,
        &eph_key_gen_first_message_party_two.0,
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::EphEcKeyPair,
        &eph_ec_key_pair_party1,
    )?;

    Ok(Json(sign_party_one_first_message))
}

// Added here because the attribute data takes only a single struct
#[derive(Serialize, Deserialize)]
pub struct SignSecondMsgRequest {
    pub message: BigInt,
    pub party_two_sign_message: party2::SignMessage,
    pub x_pos_child_key: BigInt,
    pub y_pos_child_key: BigInt,
}
#[post("/ecdsa/sign/<id>/second", format = "json", data = "<request>")]
pub fn sign_second(
    state: State<Config>,
    claim: Claims,
    id: String,
    request: Json<SignSecondMsgRequest>,
) -> Result<Json<(party_one::SignatureRecid)>> {
    let master_key: MasterKey1 = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Party1MasterKey)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let x: BigInt = request.x_pos_child_key.clone();
    let y: BigInt = request.y_pos_child_key.clone();

    let child_master_key = master_key.get_child(vec![x, y]);

    let eph_ec_key_pair_party1: party_one::EphEcKeyPair =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::EphEcKeyPair)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::EphKeyGenFirstMsg)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let signature_with_recid = child_master_key.sign_second_message(
        &request.party_two_sign_message,
        &eph_key_gen_first_message_party_two,
        &eph_ec_key_pair_party1,
        &request.message,
    );

    if signature_with_recid.is_err() {
        panic!("validation failed")
    };

    Ok(Json(signature_with_recid.unwrap()))
}

pub fn get_mk(state: &State<Config>, claim: Claims, id: &String) -> Result<MasterKey1> {
    db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Party1MasterKey)?
        .ok_or(format_err!("No data for such identifier {}", id))
}

#[post("/ecdsa/rotate/<id>/first", format = "json")]
pub fn rotate_first(
    state: State<Config>,
    claim: Claims,
    id: String,
) -> Result<Json<(coin_flip_optimal_rounds::Party1FirstMessage)>> {
    let (party1_coin_flip_first_message, m1, r1) = Rotation1::key_rotate_first_message();
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::RotateCommitMessage1M,
        &m1,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::RotateCommitMessage1R,
        &r1,
    )?;
    Ok(Json(party1_coin_flip_first_message))
}

#[post(
    "/ecdsa/rotate/<id>/second",
    format = "json",
    data = "<party2_first_message>"
)]
pub fn rotate_second(
    state: State<Config>,
    id: String,
    claim: Claims,
    party2_first_message: Json<coin_flip_optimal_rounds::Party2FirstMessage>,
) -> Result<
    Json<
        ((
            coin_flip_optimal_rounds::Party1SecondMessage,
            party1::RotationParty1Message1,
        )),
    >,
> {
    let party_one_master_key = get_mk(&state, claim.clone(), &id)?;

    let m1: Secp256k1Scalar = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::RotateCommitMessage1M)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let r1: Secp256k1Scalar = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::RotateCommitMessage1R)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let (party1_second_message, random1) =
        Rotation1::key_rotate_second_message(&party2_first_message.0, &m1, &r1);
    db::insert(&state.db, &claim.sub, &id, &EcdsaStruct::RotateRandom1, &random1)?;

    let (rotation_party_one_first_message, party_one_private_new) =
        party_one_master_key.rotation_first_message(&random1);

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::RotateFirstMsg,
        &rotation_party_one_first_message,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::RotatePrivateNew,
        &party_one_private_new,
    )?;
    Ok(Json((
        party1_second_message,
        rotation_party_one_first_message,
    )))
}

#[post(
    "/ecdsa/rotate/<id>/third",
    format = "json",
    data = "<rotation_party_two_first_message>"
)]
pub fn rotate_third(
    state: State<Config>,
    claim: Claims,
    id: String,
    rotation_party_two_first_message: Json<party_two::PDLFirstMessage>,
) -> Result<Json<(party_one::PDLFirstMessage)>> {
    let party_one_private_new: party_one::Party1Private =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::RotatePrivateNew)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let (rotation_party_one_second_message, party_one_pdl_decommit, alpha) =
        MasterKey1::rotation_second_message(
            &rotation_party_two_first_message.0,
            &party_one_private_new,
        );

    db::insert(&state.db, &claim.sub, &id, &EcdsaStruct::Alpha, &Alpha { value: alpha })?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::RotatePdlDecom,
        &party_one_pdl_decommit,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::RotateParty2First,
        &rotation_party_two_first_message.0,
    )?;
    db::insert(
        &state.db,
        &id,
        &claim.sub,
        &EcdsaStruct::RotateParty1Second,
        &rotation_party_one_second_message,
    )?;

    Ok(Json(rotation_party_one_second_message))
}

#[post(
    "/ecdsa/rotate/<id>/fourth",
    format = "json",
    data = "<rotation_party_two_second_message>"
)]
pub fn rotate_fourth(
    state: State<Config>,
    claim: Claims,
    id: String,
    rotation_party_two_second_message: Json<party_two::PDLSecondMessage>,
) -> Result<Json<(party_one::PDLSecondMessage)>> {
    let party_one_master_key = get_mk(&state, claim.clone(), &id)?;

    let rotation_party_one_first_message: party1::RotationParty1Message1 =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::RotateFirstMsg)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party_one_private_new: party_one::Party1Private =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::RotatePrivateNew)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let random1: kms::rotation::two_party::Rotation =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::RotateRandom1)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let rotation_party_two_first_message: party_two::PDLFirstMessage =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::RotateParty2First)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party_one_pdl_decommit: party_one::PDLdecommit =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::RotatePdlDecom)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let alpha: Alpha = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Alpha)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let result_rotate_party_two_second_message = party_one_master_key.rotation_third_message(
        &rotation_party_one_first_message,
        party_one_private_new,
        &random1,
        &rotation_party_two_first_message,
        &rotation_party_two_second_message.0,
        party_one_pdl_decommit,
        alpha.value,
    );
    if result_rotate_party_two_second_message.is_err() {
        panic!("rotation failed");
    }
    let (rotation_party_one_third_message, party_one_master_key_rotated) =
        result_rotate_party_two_second_message.unwrap();

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::Party1MasterKey,
        &party_one_master_key_rotated,
    )?;

    Ok(Json(rotation_party_one_third_message))
}

#[post("/ecdsa/<id>/recover", format = "json")]
pub fn recover(state: State<Config>, claim: Claims, id: String) -> Result<Json<(u32)>> {
    let pos_old: u32 = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::POS)?
        .ok_or(format_err!("No data for such identifier {}", id))?;
    Ok(Json(pos_old))
}
