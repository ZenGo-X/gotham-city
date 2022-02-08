#![allow(non_snake_case)]
// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::{
    CommWitness, EcKeyPair, Party1FirstMessage, Party1SecondMessage,
};
use curv::elliptic::curves::secp256_k1::Secp256k1Scalar;
use curv::elliptic::curves::secp256_k1::GE;
use curv::BigInt;
use kms::chain_code::two_party as chain_code;
use kms::ecdsa::two_party::*;
use kms::rotation::two_party::party1::Rotation1;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use rocket::serde::json::Json;
use rocket::State;
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
    value: BigInt,
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
pub async fn first_message(
    state: &State<Config>,
    claim: Claims,
) -> Result<Json<(String, party_one::KeyGenFirstMsg)>, String> {
    let id = Uuid::new_v4().to_string();

    let (key_gen_first_msg, comm_witness, ec_key_pair) = MasterKey1::key_gen_first_message();

    //save pos 0
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::POS,
        &HDPos { pos: 0u32 },
    )
    .await
    .or(Err("Failed to insert into db"))?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::KeyGenFirstMsg,
        &key_gen_first_msg,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::CommWitness,
        &comm_witness,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::EcKeyPair,
        &ec_key_pair,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    Ok(Json((id, key_gen_first_msg)))
}

#[post("/ecdsa/keygen/<id>/second", format = "json", data = "<dlog_proof>")]
pub async fn second_message(
    state: &State<Config>,
    claim: Claims,
    id: String,
    dlog_proof: Json<DLogProof<GE>>,
) -> Result<Json<party1::KeyGenParty1Message2>, String> {
    let party2_public: GE = dlog_proof.0.pk;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::Party2Public,
        &party2_public,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    let comm_witness: party_one::CommWitness =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::CommWitness)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;
    let ec_key_pair: party_one::EcKeyPair =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::EcKeyPair)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;

    let (kg_party_one_second_message, paillier_key_pair, party_one_private) =
        MasterKey1::key_gen_second_message(comm_witness, &ec_key_pair, &dlog_proof.0);

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::PaillierKeyPair,
        &paillier_key_pair,
    )
    .await
    .or(Err("Failed to insert into db"))?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::Party1Private,
        &party_one_private,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    Ok(Json(kg_party_one_second_message))
}

#[post("/ecdsa/keygen/<id>/chaincode/first", format = "json")]
pub async fn chain_code_first_message(
    state: &State<Config>,
    claim: Claims,
    id: String,
) -> Result<Json<Party1FirstMessage>, String> {
    let (cc_party_one_first_message, cc_comm_witness, cc_ec_key_pair1) =
        chain_code::party1::ChainCode1::chain_code_first_message();

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::CCKeyGenFirstMsg,
        &cc_party_one_first_message,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::CCCommWitness,
        &cc_comm_witness,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::CCEcKeyPair,
        &cc_ec_key_pair1,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    Ok(Json(cc_party_one_first_message))
}

#[post(
    "/ecdsa/keygen/<id>/chaincode/second",
    format = "json",
    data = "<cc_party_two_first_message_d_log_proof>"
)]
pub async fn chain_code_second_message(
    state: &State<Config>,
    claim: Claims,
    id: String,
    cc_party_two_first_message_d_log_proof: Json<DLogProof<GE>>,
) -> Result<Json<Party1SecondMessage<GE>>, String> {
    let cc_comm_witness: CommWitness<GE> =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::CCCommWitness)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;

    let party1_cc = chain_code::party1::ChainCode1::chain_code_second_message(
        cc_comm_witness,
        &cc_party_two_first_message_d_log_proof.0,
    );

    let party2_pub = &cc_party_two_first_message_d_log_proof.pk;
    chain_code_compute_message(state, claim, id, party2_pub).await?;

    Ok(Json(party1_cc))
}

pub async fn chain_code_compute_message(
    state: &State<Config>,
    claim: Claims,
    id: String,
    cc_party2_public: &GE,
) -> Result<Json<()>, String> {
    let cc_ec_key_pair_party1: EcKeyPair<GE> =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::CCEcKeyPair)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;
    let party1_cc = chain_code::party1::ChainCode1::compute_chain_code(
        &cc_ec_key_pair_party1,
        cc_party2_public,
    );

    db::insert(&state.db, &claim.sub, &id, &EcdsaStruct::CC, &party1_cc)
        .await
        .or(Err("Failed to insert into db"))?;
    master_key(state, claim, id)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Json(()))
}

pub async fn master_key(
    state: &State<Config>,
    claim: Claims,
    id: String,
) -> Result<(), failure::Error> {
    let party2_public: GE = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Party2Public)
        .await?
        .ok_or_else(|| format_err!("No data for such identifier {}", id))?;

    let paillier_key_pair: party_one::PaillierKeyPair =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::PaillierKeyPair)
            .await?
            .ok_or_else(|| format_err!("No data for such identifier {}", id))?;

    let party1_cc: chain_code::party1::ChainCode1 =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::CC)
            .await?
            .ok_or_else(|| format_err!("No data for such identifier {}", id))?;

    let party_one_private: party_one::Party1Private =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Party1Private)
            .await?
            .ok_or_else(|| format_err!("No data for such identifier {}", id))?;

    let comm_witness: party_one::CommWitness =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::CommWitness)
            .await?
            .ok_or_else(|| format_err!("No data for such identifier {}", id))?;

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
    .await
}

#[post(
    "/ecdsa/sign/<id>/first",
    format = "json",
    data = "<eph_key_gen_first_message_party_two>"
)]
pub async fn sign_first(
    state: &State<Config>,
    claim: Claims,
    id: String,
    eph_key_gen_first_message_party_two: Json<party_two::EphKeyGenFirstMsg>,
) -> Result<Json<party_one::EphKeyGenFirstMsg>, String> {
    let (sign_party_one_first_message, eph_ec_key_pair_party1) = MasterKey1::sign_first_message();

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::EphKeyGenFirstMsg,
        &eph_key_gen_first_message_party_two.0,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::EphEcKeyPair,
        &eph_ec_key_pair_party1,
    )
    .await
    .or(Err("Failed to insert into db"))?;

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
pub async fn sign_second(
    state: &State<Config>,
    claim: Claims,
    id: String,
    request: Json<SignSecondMsgRequest>,
) -> Result<Json<party_one::SignatureRecid>, String> {
    let master_key: MasterKey1 = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::Party1MasterKey)
        .await
        .or(Err("Failed to get from db"))?
        .ok_or(format!("No data for such identifier {}", id))?;

    let x: BigInt = request.x_pos_child_key.clone();
    let y: BigInt = request.y_pos_child_key.clone();

    let child_master_key = master_key.get_child(vec![x, y]);

    let eph_ec_key_pair_party1: party_one::EphEcKeyPair =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::EphEcKeyPair)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;

    let eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg =
        db::get(&state.db, &claim.sub, &id, &EcdsaStruct::EphKeyGenFirstMsg)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;

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

pub async fn get_mk(
    state: &State<Config>,
    claim: Claims,
    id: &str,
) -> Result<MasterKey1, failure::Error> {
    db::get(&state.db, &claim.sub, id, &EcdsaStruct::Party1MasterKey)
        .await?
        .ok_or_else(|| format_err!("No data for such identifier {}", id))
}

#[post("/ecdsa/rotate/<id>/first", format = "json")]
pub async fn rotate_first(
    state: &State<Config>,
    claim: Claims,
    id: String,
) -> Result<Json<coin_flip_optimal_rounds::Party1FirstMessage<GE>>, String> {
    let (party1_coin_flip_first_message, m1, r1) = Rotation1::key_rotate_first_message();
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::RotateCommitMessage1M,
        &m1,
    )
    .await
    .or(Err("Failed to insert into db"))?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::RotateCommitMessage1R,
        &r1,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    Ok(Json(party1_coin_flip_first_message))
}

#[post(
    "/ecdsa/rotate/<id>/second",
    format = "json",
    data = "<party2_first_message>"
)]
pub async fn rotate_second(
    state: &State<Config>,
    id: String,
    claim: Claims,
    party2_first_message: Json<coin_flip_optimal_rounds::Party2FirstMessage<GE>>,
) -> Result<
    Json<(
        coin_flip_optimal_rounds::Party1SecondMessage<GE>,
        party1::RotationParty1Message1,
    )>,
    String,
> {
    let party_one_master_key = get_mk(state, claim.clone(), &id)
        .await
        .map_err(|e| e.to_string())?;

    let m1: Secp256k1Scalar = db::get(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::RotateCommitMessage1M,
    )
    .await
    .or(Err("Failed to get from db"))?
    .ok_or(format!("No data for such identifier {}", id))?;

    let r1: Secp256k1Scalar = db::get(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::RotateCommitMessage1R,
    )
    .await
    .or(Err("Failed to get from db"))?
    .ok_or(format!("No data for such identifier {}", id))?;

    let (party1_second_message, random1) =
        Rotation1::key_rotate_second_message(&party2_first_message.0, &m1, &r1);
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::RotateRandom1,
        &random1,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    let (rotation_party_one_first_message, party_one_master_key_rotated) =
        party_one_master_key.rotation_first_message(&random1);

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &EcdsaStruct::Party1MasterKey,
        &party_one_master_key_rotated,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    Ok(Json((
        party1_second_message,
        rotation_party_one_first_message,
    )))
}

#[post("/ecdsa/<id>/recover", format = "json")]
pub async fn recover(
    state: &State<Config>,
    claim: Claims,
    id: String,
) -> Result<Json<u32>, String> {
    let pos_old: u32 = db::get(&state.db, &claim.sub, &id, &EcdsaStruct::POS)
        .await
        .or(Err("Failed to get from db"))?
        .ok_or(format!("No data for such identifier {}", id))?;
    Ok(Json(pos_old))
}
