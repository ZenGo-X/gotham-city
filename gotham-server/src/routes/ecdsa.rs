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
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use curv::{BigInt, FE, GE};

use curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds::Party1SecondMessage as RotParty1SecondMessage;
use curv::elliptic::curves::secp256_k1::Secp256k1Scalar;
use curv::elliptic::curves::traits::ECScalar;
use kms::chain_code::two_party as chain_code;
use kms::ecdsa::two_party_gg18::*;
use kms::rotation::two_party::party2::Rotation2;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::KeyGenDecommitMessage1;
use paillier::EncryptionKey;
use rocket::State;
use rocket_contrib::json::Json;
use std::string::ToString;
use uuid::Uuid;

use super::super::auth::jwt::Claims;
use super::super::storage::db;
use super::super::storage::db::DB;

use self::Share::*;
use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::Party1FirstMessage as CCParty1FirstMessage;
use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::Party1SecondMessage as CCParty1SecondMessage;
use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::Party2FirstMessage as CCParty2FirstMessage;
use std::slice::Iter;

use kms::ecdsa::two_party_gg18::party1::KeyGenMessage0Party1Transform;
use kms::ecdsa::two_party_lindell17::MasterKey1 as MasterKey1L;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::LocalSignature;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::Phase5DDecom2;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::{
    Keys, Phase5ADecom1, SignDecommitPhase1, SignKeys,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct HDPos {
    pub pos: u32,
}

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

#[derive(Serialize, Deserialize)]
pub struct RotCfParty1 {
    pub party1_message1: KeyGenMessage1,
    pub cf_party1_message2: RotParty1SecondMessage,
}

#[derive(ToString, Debug)]
pub enum Share {
    KgParty1Message1,
    KgParty1Message2,
    KgParty1Message3,
    KgParty1Message4,
    KgParty2Message1,
    KgParty2Message2,
    KgParty2Message3,
    KgParty2Message4,
    Decom1,
    AdditiveKey,
    SS2,
    KgYVec,
    KgEkVec,
    KgVssVec,
    LinearKey,

    CCParty1Message1,
    CCEcKeyPair,
    CC,

    PartyMasterKey, // gg18 masterkey

    PartyMasterKeyL, // legacy
    SignParty1Message1,
    SignParty2Message1,
    SignParty1Message2,
    SignParty2Message2,
    SignParty1Message3,
    SignParty2Message3,
    SignParty1Message4,
    SignParty2Message4,
    SignParty1Message5,
    SignParty2Message5,
    SignParty1Message6,
    SignParty2Message6,
    SignParty1Message7,
    SignParty2Message7,
    SignParty1Message8,
    SignParty2Message8,
    SignParty1Message9,
    SignParty2Message9,
    ChildMasterKey,
    SignDecomPhase1,
    SigningKeys,
    Sigma,
    Message,
    Beta,
    Ni,
    SignDecomAPhase5,
    ElGamal,
    LocalSig,
    R,
    SignDecomDPhase5,

    CfParty2Message1,
    CfParty1Message1,
    POS,

    // legacy fields:
    KeyGenFirstMsg,
    CommWitness,
    EcKeyPair,
    PaillierKeyPair,
    Party1Private,
    Party2Public,

    PDLProver,
    PDLDecommit,
    Alpha,
    PDLFirstMessage,
    Party2PDLFirstMsg,

    CCKeyGenFirstMsg,
    CCCommWitness,
    //CCEcKeyPair,

    //Party1MasterKey,
    RotateCommitMessage1M,
    RotateCommitMessage1R,
    RotateRandom1,
    RotateFirstMsg,
    RotatePrivateNew,
    RotatePdlDecom,
    RotateParty2First,
    RotateParty1Second,
}

impl Share {
    pub fn iterator() -> Iter<'static, Share> {
        static FIELDS: [Share; 74] = [
            KgParty1Message1,
            KgParty1Message2,
            KgParty1Message3,
            KgParty1Message4,
            KgParty2Message1,
            KgParty2Message2,
            KgParty2Message3,
            KgParty2Message4,
            Decom1,
            AdditiveKey,
            SS2,
            KgYVec,
            KgEkVec,
            KgVssVec,
            LinearKey,
            CCParty1Message1,
            CCEcKeyPair,
            CC,
            PartyMasterKey,  // gg18 masterkey
            PartyMasterKeyL, // legacy
            SignParty1Message1,
            SignParty2Message1,
            SignParty1Message2,
            SignParty2Message2,
            SignParty1Message3,
            SignParty2Message3,
            SignParty1Message4,
            SignParty2Message4,
            SignParty1Message5,
            SignParty2Message5,
            SignParty1Message6,
            SignParty2Message6,
            SignParty1Message7,
            SignParty2Message7,
            SignParty1Message8,
            SignParty2Message8,
            SignParty1Message9,
            SignParty2Message9,
            ChildMasterKey,
            SignDecomPhase1,
            SigningKeys,
            Sigma,
            Message,
            Beta,
            Ni,
            SignDecomAPhase5,
            ElGamal,
            LocalSig,
            R,
            SignDecomDPhase5,
            CfParty2Message1,
            CfParty1Message1,
            POS,
            // legacy fields:
            KeyGenFirstMsg,
            CommWitness,
            EcKeyPair,
            PaillierKeyPair,
            Party1Private,
            Party2Public,
            PDLProver,
            PDLDecommit,
            Alpha,
            PDLFirstMessage,
            Party2PDLFirstMsg,
            CCKeyGenFirstMsg,
            CCCommWitness,
            //CCEcKeyPair,

            //Party1MasterKey,
            RotateCommitMessage1M,
            RotateCommitMessage1R,
            RotateRandom1,
            RotateFirstMsg,
            RotatePrivateNew,
            RotatePdlDecom,
            RotateParty2First,
            RotateParty1Second,
        ];

        FIELDS.iter()
    }
}

pub struct Config {
    pub db: DB,
}
#[derive(Serialize, Deserialize)]
pub struct TransformFirstMessage {
    pub message: BigInt,
    pub party1_message1: KeyGenMessage0Party1Transform,
    pub x_pos_child_key: BigInt,
    pub y_pos_child_key: BigInt,
}

#[post(
    "/ecdsa/sign_keygen_lindell/<id>/first",
    format = "json",
    data = "<party1_message1>"
)]
pub fn transform_first_message(
    state: State<Config>,
    claim: Claims,
    id: String,
    party1_message1: Json<TransformFirstMessage>,
) -> Result<Json<KeyGenMessage1>> {
    let master_key1_l: MasterKey1L = db::get(&state.db, &claim.sub, &id, &Share::PartyMasterKeyL)?
        .ok_or(format_err!("No data for such identifier {}", id))?;
    let master_key1_l = master_key1_l.get_child(vec![
        party1_message1.x_pos_child_key.clone(),
        party1_message1.y_pos_child_key.clone(),
    ]);

    let (party2_message1, party2_additive_key, party2_decom1) =
        MasterKey2::key_gen_zero_message_transform(
            &master_key1_l,
            &party1_message1.party1_message1,
        );

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::AdditiveKey,
        &party2_additive_key,
    )?;
    db::insert(&state.db, &claim.sub, &id, &Share::Decom1, &party2_decom1)?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::KgParty1Message1,
        &party1_message1.party1_message1.p1m1,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::KgParty2Message1,
        &party2_message1,
    )?;

    Ok(Json(party2_message1))
}

#[post(
    "/ecdsa/sign_keygen_lindell/<id>/second",
    format = "json",
    data = "<party1_message2>"
)]
pub fn transform_second_message(
    state: State<Config>,
    claim: Claims,
    id: String,
    party1_message2: Json<KeyGenMessage2>,
) -> Result<Json<(KeyGenMessage2)>> {
    let party2_decom1: KeyGenDecommitMessage1 =
        db::get(&state.db, &claim.sub, &id, &Share::Decom1)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let party2_message2 = MasterKey1::keygen_second_message(party2_decom1);

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::KgParty1Message2,
        &party1_message2.clone(),
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::KgParty2Message2,
        &party2_message2,
    )?;

    Ok(Json(party2_message2))
}

#[post("/ecdsa/keygen/first", format = "json", data = "<party1_message1>")]
pub fn first_message(
    state: State<Config>,
    claim: Claims,
    party1_message1: Json<Party1KeyGenCCFirst>,
) -> Result<Json<(String, KeyGenMessage1, CCParty2FirstMessage)>> {
    //handle recover:
    let id = if party1_message1.id.clone() != "" {
        party1_message1.id.clone()
    } else {
        Uuid::new_v4().to_string()
    };

    let recover_maybe: Option<Keys> =
        db::get(&state.db, &claim.sub, &id, &Share::AdditiveKey).unwrap();

    let u = match recover_maybe {
        Some(x) => x.u_i,
        _ => FE::zero(),
    };
    let (party2_message1, party2_additive_key, party2_decom1) =
        MasterKey2::key_gen_first_message(u);

    let (cc_party_two_first_message, cc_ec_key_pair2) =
        chain_code::party2::ChainCode2::chain_code_first_message();
    //save pos 0
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::POS,
        &HDPos { pos: 0u32 },
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::AdditiveKey,
        &party2_additive_key,
    )?;
    db::insert(&state.db, &claim.sub, &id, &Share::Decom1, &party2_decom1)?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::KgParty1Message1,
        &party1_message1.party1_message1.clone(),
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::KgParty2Message1,
        &party2_message1,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::CCParty1Message1,
        &party1_message1.cc_party1_message1.clone(),
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::CCEcKeyPair,
        &cc_ec_key_pair2,
    )?;

    Ok(Json((id, party2_message1, cc_party_two_first_message)))
}

#[post(
    "/ecdsa/keygen/<id>/second",
    format = "json",
    data = "<party1_message2>"
)]
pub fn second_message(
    state: State<Config>,
    claim: Claims,
    id: String,
    party1_message2: Json<Party1KeyGenCCSecond>,
) -> Result<Json<(KeyGenMessage2)>> {
    let party2_decom1: KeyGenDecommitMessage1 =
        db::get(&state.db, &claim.sub, &id, &Share::Decom1)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let party2_message2 = MasterKey1::keygen_second_message(party2_decom1);

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::KgParty1Message2,
        &party1_message2.party1_message2,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::KgParty2Message2,
        &party2_message2,
    )?;

    // finalizing chain code:
    let cc_party1_message1: CCParty1FirstMessage =
        db::get(&state.db, &claim.sub, &id, &Share::CCParty1Message1)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let cc_party2_message2 = chain_code::party2::ChainCode2::chain_code_second_message(
        &cc_party1_message1,
        &party1_message2.cc_party1_message2,
    );

    assert!(cc_party2_message2.is_ok());

    let cc_ec_key_pair2: EcKeyPair = db::get(&state.db, &claim.sub, &id, &Share::CCEcKeyPair)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_cc = chain_code::party2::ChainCode2::compute_chain_code(
        &cc_ec_key_pair2,
        &party1_message2.cc_party1_message2.comm_witness.public_share,
    )
    .chain_code;

    //handle recover: TODO: optimize
    let recover_maybe: Option<BigInt> = db::get(&state.db, &claim.sub, &id, &Share::CC).unwrap();

    let party2_cc = match recover_maybe {
        Some(x) => x,
        _ => party2_cc,
    };
    db::insert(&state.db, &claim.sub, &id, &Share::CC, &party2_cc)?;

    Ok(Json(party2_message2))
}

#[post(
    "/ecdsa/keygen/<id>/third",
    format = "json",
    data = "<party1_message3>"
)]
pub fn third_message(
    state: State<Config>,
    claim: Claims,
    id: String,
    party1_message3: Json<KeyGenMessage3>,
) -> Result<Json<(KeyGenMessage3)>> {
    let party1_message1: KeyGenMessage1 =
        db::get(&state.db, &claim.sub, &id, &Share::KgParty1Message1)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let party1_message2: KeyGenMessage2 =
        db::get(&state.db, &claim.sub, &id, &Share::KgParty1Message2)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let party2_message1: KeyGenMessage1 =
        db::get(&state.db, &claim.sub, &id, &Share::KgParty2Message1)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let party2_message2: KeyGenMessage2 =
        db::get(&state.db, &claim.sub, &id, &Share::KgParty2Message2)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let party2_additive_key: Keys = db::get(&state.db, &claim.sub, &id, &Share::AdditiveKey)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let (party2_message3, ss2_to_self, party2_y_vec, party2_ek_vec) =
        MasterKey2::key_gen_third_message(
            &party2_additive_key,
            party1_message1,
            party2_message1,
            party1_message2,
            party2_message2,
        );

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::KgParty2Message3,
        &party2_message3,
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::KgParty1Message3,
        &party1_message3.clone(),
    )?;

    db::insert(&state.db, &claim.sub, &id, &Share::SS2, &ss2_to_self)?;

    db::insert(&state.db, &claim.sub, &id, &Share::KgYVec, &party2_y_vec)?;

    db::insert(&state.db, &claim.sub, &id, &Share::KgEkVec, &party2_ek_vec)?;

    Ok(Json(party2_message3))
}

#[post(
    "/ecdsa/keygen/<id>/fourth",
    format = "json",
    data = "<party1_message4>"
)]
pub fn fourth_message(
    state: State<Config>,
    claim: Claims,
    id: String,
    party1_message4: Json<KeyGenMessage4>,
) -> Result<Json<(KeyGenMessage4)>> {
    let party2_additive_key: Keys = db::get(&state.db, &claim.sub, &id, &Share::AdditiveKey)?
        .ok_or(format_err!("No data for such identifier {}", id))?;
    let party1_message3: KeyGenMessage3 =
        db::get(&state.db, &claim.sub, &id, &Share::KgParty1Message3)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let party2_message3: KeyGenMessage3 =
        db::get(&state.db, &claim.sub, &id, &Share::KgParty2Message3)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let ss2_to_self: FE = db::get(&state.db, &claim.sub, &id, &Share::SS2)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_y_vec: Vec<GE> = db::get(&state.db, &claim.sub, &id, &Share::KgYVec)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let (party2_message4, party2_linear_key, party2_vss_vec) = MasterKey2::key_gen_fourth_message(
        &party2_additive_key,
        party1_message3,
        party2_message3,
        ss2_to_self,
        &party2_y_vec,
    );

    let party2_ek_vec: Vec<EncryptionKey> =
        db::get(&state.db, &claim.sub, &id, &Share::KgEkVec)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_cc: BigInt = db::get(&state.db, &claim.sub, &id, &Share::CC)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let master_key2 = MasterKey2::set_master_key(
        party1_message4.clone(),
        party2_message4.clone(),
        party2_y_vec,
        party2_additive_key,
        party2_linear_key,
        party2_vss_vec,
        party2_ek_vec,
        &party2_cc,
    );

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::PartyMasterKey,
        &master_key2,
    )?;

    Ok(Json(party2_message4))
}

// Added here because the attribute data takes only a single struct
#[derive(Serialize, Deserialize)]
pub struct SignSecondMsgRequest {
    pub message: BigInt,
    pub party1_message1: SignMessage1,
    pub x_pos_child_key: BigInt,
    pub y_pos_child_key: BigInt,
}

#[post("/ecdsa/sign/<id>/first", format = "json", data = "<party1_message1>")]
pub fn sign_first(
    state: State<Config>,
    claim: Claims,
    id: String,
    party1_message1: Json<SignSecondMsgRequest>,
) -> Result<Json<(SignMessage1)>> {
    let master_key2: MasterKey2 = db::get(&state.db, &claim.sub, &id, &Share::PartyMasterKey)?
        .ok_or(format_err!("No data for such identifier {}", id))?;
    let mut master_key2_child;
    if party1_message1.y_pos_child_key != BigInt::zero() {
        //regular signing flow
        master_key2_child = master_key2.get_child(vec![
            party1_message1.x_pos_child_key.clone(),
            party1_message1.y_pos_child_key.clone(),
        ]);
    } else {
        // lindell to gg signing flow
        master_key2_child = master_key2;
    }
    let (party2_message1, party2_decommit_phase1, party2_sign_keys) =
        master_key2_child.sign_first_message();

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::ChildMasterKey,
        &master_key2_child,
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignDecomPhase1,
        &party2_decommit_phase1,
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SigningKeys,
        &party2_sign_keys,
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignParty1Message1,
        &party1_message1.party1_message1.clone(),
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignParty2Message1,
        &party2_message1,
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::Message,
        &party1_message1.message,
    )?;

    Ok(Json(party2_message1))
}

#[post("/ecdsa/sign/<id>/second", format = "json", data = "<party1_message2>")]
pub fn sign_second(
    state: State<Config>,
    claim: Claims,
    id: String,
    party1_message2: Json<SignMessage2>,
) -> Result<Json<(SignMessage2)>> {
    let master_key2: MasterKey2 = db::get(&state.db, &claim.sub, &id, &Share::ChildMasterKey)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_sign_keys: SignKeys = db::get(&state.db, &claim.sub, &id, &Share::SigningKeys)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let party1_message1: SignMessage1 =
        db::get(&state.db, &claim.sub, &id, &Share::SignParty1Message1)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let (party2_message2, party2_beta, party2_ni) =
        master_key2.sign_second_message(&party1_message1, &party2_sign_keys);

    db::insert(&state.db, &claim.sub, &id, &Share::Beta, &party2_beta)?;

    db::insert(&state.db, &claim.sub, &id, &Share::Ni, &party2_ni)?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignParty1Message2,
        &party1_message2.clone(),
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignParty2Message2,
        &party2_message2,
    )?;

    Ok(Json(party2_message2))
}

#[post("/ecdsa/sign/<id>/third", format = "json", data = "<party1_message3>")]
pub fn sign_third(
    state: State<Config>,
    claim: Claims,
    id: String,
    party1_message3: Json<SignMessage3>,
) -> Result<Json<(SignMessage3)>> {
    let master_key2: MasterKey2 = db::get(&state.db, &claim.sub, &id, &Share::ChildMasterKey)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let party1_message2: SignMessage2 =
        db::get(&state.db, &claim.sub, &id, &Share::SignParty1Message2)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_sign_keys: SignKeys = db::get(&state.db, &claim.sub, &id, &Share::SigningKeys)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_beta: FE = db::get(&state.db, &claim.sub, &id, &Share::Beta)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_ni: FE = db::get(&state.db, &claim.sub, &id, &Share::Ni)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let (party2_message3, party2_sigma) =
        master_key2.sign_third_message(&party1_message2, &party2_sign_keys, party2_beta, party2_ni);

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignParty1Message3,
        &party1_message3.clone(),
    )?;

    db::insert(&state.db, &claim.sub, &id, &Share::Sigma, &party2_sigma)?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignParty2Message3,
        &party2_message3,
    )?;

    Ok(Json(party2_message3))
}

#[post("/ecdsa/sign/<id>/fourth", format = "json", data = "<party1_message4>")]
pub fn sign_fourth(
    state: State<Config>,
    claim: Claims,
    id: String,
    party1_message4: Json<SignMessage4>,
) -> Result<Json<(SignMessage4)>> {
    let party2_decommit_phase1: SignDecommitPhase1 =
        db::get(&state.db, &claim.sub, &id, &Share::SignDecomPhase1)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_message4 = MasterKey2::sign_fourth_message(party2_decommit_phase1);

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignParty1Message4,
        &party1_message4.clone(),
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignParty2Message4,
        &party2_message4,
    )?;

    Ok(Json(party2_message4))
}

#[post("/ecdsa/sign/<id>/fifth", format = "json", data = "<party1_message5>")]
pub fn sign_fifth(
    state: State<Config>,
    claim: Claims,
    id: String,
    party1_message5: Json<SignMessage5>,
) -> Result<Json<(SignMessage5)>> {
    let master_key2: MasterKey2 = db::get(&state.db, &claim.sub, &id, &Share::ChildMasterKey)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let message: BigInt = db::get(&state.db, &claim.sub, &id, &Share::Message)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_sigma: FE = db::get(&state.db, &claim.sub, &id, &Share::Sigma)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_sign_keys: SignKeys = db::get(&state.db, &claim.sub, &id, &Share::SigningKeys)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_message4: SignMessage4 =
        db::get(&state.db, &claim.sub, &id, &Share::SignParty2Message4)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_message3: SignMessage3 =
        db::get(&state.db, &claim.sub, &id, &Share::SignParty2Message3)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party1_message3: SignMessage3 =
        db::get(&state.db, &claim.sub, &id, &Share::SignParty1Message3)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party1_message4: SignMessage4 =
        db::get(&state.db, &claim.sub, &id, &Share::SignParty1Message4)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party1_message2: SignMessage2 =
        db::get(&state.db, &claim.sub, &id, &Share::SignParty1Message2)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party1_message1: SignMessage1 =
        db::get(&state.db, &claim.sub, &id, &Share::SignParty1Message1)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let (party2_message5, party2_phase5a_decom1, party2_elgamal_proof, party2_local_sig, party2_R) =
        master_key2.sign_fifth_message(
            message,
            party2_sigma,
            &party2_sign_keys,
            party2_message4,
            party2_message3,
            party1_message3,
            party1_message4,
            party1_message2,
            party1_message1,
        );

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignParty1Message5,
        &party1_message5.clone(),
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignParty2Message5,
        &party2_message5,
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignDecomAPhase5,
        &party2_phase5a_decom1,
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::ElGamal,
        &party2_elgamal_proof,
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::LocalSig,
        &party2_local_sig,
    )?;

    db::insert(&state.db, &claim.sub, &id, &Share::R, &party2_R)?;

    Ok(Json(party2_message5))
}

#[post("/ecdsa/sign/<id>/sixth", format = "json", data = "<party1_message6>")]
pub fn sign_sixth(
    state: State<Config>,
    claim: Claims,
    id: String,
    party1_message6: Json<SignMessage6>,
) -> Result<Json<(SignMessage6)>> {
    let party2_phase5a_decom1: Phase5ADecom1 =
        db::get(&state.db, &claim.sub, &id, &Share::SignDecomAPhase5)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_elgamal_proof: HomoELGamalProof =
        db::get(&state.db, &claim.sub, &id, &Share::ElGamal)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_message6 =
        MasterKey2::sign_sixth_message(party2_phase5a_decom1, party2_elgamal_proof);

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignParty1Message6,
        &party1_message6.clone(),
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignParty2Message6,
        &party2_message6,
    )?;

    Ok(Json(party2_message6))
}

#[post(
    "/ecdsa/sign/<id>/seventh",
    format = "json",
    data = "<party1_message7>"
)]
pub fn sign_seventh(
    state: State<Config>,
    claim: Claims,
    id: String,
    party1_message7: Json<SignMessage7>,
) -> Result<Json<(SignMessage7)>> {
    let party2_message6: SignMessage6 =
        db::get(&state.db, &claim.sub, &id, &Share::SignParty2Message6)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party1_message6: SignMessage6 =
        db::get(&state.db, &claim.sub, &id, &Share::SignParty1Message6)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party1_message5: SignMessage5 =
        db::get(&state.db, &claim.sub, &id, &Share::SignParty1Message5)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_local_sig: LocalSignature =
        db::get(&state.db, &claim.sub, &id, &Share::LocalSig)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_R: GE = db::get(&state.db, &claim.sub, &id, &Share::R)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let (party2_message7, party2_phase5d_decom2) = MasterKey2::sign_seventh_message(
        party2_message6,
        party1_message6,
        party1_message5,
        &party2_local_sig,
        party2_R,
    );

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignParty1Message7,
        &party1_message7.clone(),
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignParty2Message7,
        &party2_message7,
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignDecomDPhase5,
        &party2_phase5d_decom2,
    )?;

    Ok(Json(party2_message7))
}

#[post("/ecdsa/sign/<id>/eighth", format = "json", data = "<party1_message8>")]
pub fn sign_eighth(
    state: State<Config>,
    claim: Claims,
    id: String,
    party1_message8: Json<SignMessage8>,
) -> Result<Json<(SignMessage8)>> {
    let party2_phase5d_decom2: Phase5DDecom2 =
        db::get(&state.db, &claim.sub, &id, &Share::SignDecomDPhase5)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_message8 = MasterKey2::sign_eighth_message(party2_phase5d_decom2);

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignParty1Message8,
        &party1_message8.clone(),
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::SignParty2Message8,
        &party2_message8,
    )?;

    Ok(Json(party2_message8))
}

#[post("/ecdsa/sign/<id>/nineth", format = "json", data = "<party1_message9>")]
pub fn sign_ninth(
    state: State<Config>,
    claim: Claims,
    id: String,
    party1_message9: Json<SignMessage9>,
) -> Result<Json<(SignMessage9)>> {
    let party2_local_sig: LocalSignature =
        db::get(&state.db, &claim.sub, &id, &Share::LocalSig)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party1_message6: SignMessage6 =
        db::get(&state.db, &claim.sub, &id, &Share::SignParty1Message6)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_message6: SignMessage6 =
        db::get(&state.db, &claim.sub, &id, &Share::SignParty2Message6)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party1_message7: SignMessage7 =
        db::get(&state.db, &claim.sub, &id, &Share::SignParty1Message7)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_message7: SignMessage7 =
        db::get(&state.db, &claim.sub, &id, &Share::SignParty2Message7)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party1_message8: SignMessage8 =
        db::get(&state.db, &claim.sub, &id, &Share::SignParty1Message8)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_message8: SignMessage8 =
        db::get(&state.db, &claim.sub, &id, &Share::SignParty2Message8)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_message9 = MasterKey2::sign_ninth_message(
        party1_message6,
        party2_message6,
        party1_message7,
        party2_message7,
        party1_message8,
        party2_message8,
        &party2_local_sig,
    );

    // test signature is verified
    let _sig2 = MasterKey2::output_signature(party1_message9.clone(), party2_local_sig);

    Ok(Json(party2_message9))
}

#[post(
    "/ecdsa/rotate/<id>/zero",
    format = "json",
    data = "<cf_party1_message1>"
)]
pub fn rotate_zero(
    state: State<Config>,
    claim: Claims,
    id: String,
    cf_party1_message1: Json<coin_flip_optimal_rounds::Party1FirstMessage>,
) -> Result<Json<(coin_flip_optimal_rounds::Party2FirstMessage)>> {
    let cf_party2_message1 = Rotation2::key_rotate_first_message(&cf_party1_message1);
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::CfParty2Message1,
        &cf_party2_message1,
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::CfParty1Message1,
        &cf_party1_message1.clone(),
    )?;

    Ok(Json(cf_party2_message1))
}

#[post(
    "/ecdsa/rotate/<id>/first",
    format = "json",
    data = "<party1_message1>"
)]
pub fn rotate_first(
    state: State<Config>,
    id: String,
    claim: Claims,
    party1_message1: Json<RotCfParty1>,
) -> Result<Json<((KeyGenMessage1))>> {
    let master_key2: MasterKey2 = db::get(&state.db, &claim.sub, &id, &Share::PartyMasterKey)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let cf_party2_message1: coin_flip_optimal_rounds::Party2FirstMessage =
        db::get(&state.db, &claim.sub, &id, &Share::CfParty2Message1)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let cf_party1_message1: coin_flip_optimal_rounds::Party1FirstMessage =
        db::get(&state.db, &claim.sub, &id, &Share::CfParty1Message1)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let random2 = Rotation2::key_rotate_second_message(
        &party1_message1.cf_party1_message2,
        &cf_party2_message1,
        &cf_party1_message1,
    );

    let (party2_message1, party2_additive_key, party2_decom1) =
        master_key2.rotation_first_message(&random2);

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::KgParty1Message1,
        &party1_message1.party1_message1,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::AdditiveKey,
        &party2_additive_key,
    )?;
    db::insert(&state.db, &claim.sub, &id, &Share::Decom1, &party2_decom1)?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::KgParty2Message1,
        &party2_message1,
    )?;

    Ok(Json(party2_message1))
}

#[post(
    "/ecdsa/rotate/<id>/second",
    format = "json",
    data = "<party1_message2>"
)]
pub fn rotate_second(
    state: State<Config>,
    claim: Claims,
    id: String,
    party1_message2: Json<KeyGenMessage2>,
) -> Result<Json<(KeyGenMessage2)>> {
    let party2_decom1: KeyGenDecommitMessage1 =
        db::get(&state.db, &claim.sub, &id, &Share::Decom1)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let party2_message2 = MasterKey1::rotation_second_message(party2_decom1);

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::KgParty1Message2,
        &party1_message2.clone(),
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::KgParty2Message2,
        &party2_message2,
    )?;

    Ok(Json(party2_message2))
}

#[post(
    "/ecdsa/rotate/<id>/third",
    format = "json",
    data = "<party1_message3>"
)]
pub fn rotate_third(
    state: State<Config>,
    claim: Claims,
    id: String,
    party1_message3: Json<KeyGenMessage3>,
) -> Result<Json<(KeyGenMessage3)>> {
    let master_key2: MasterKey2 = db::get(&state.db, &claim.sub, &id, &Share::PartyMasterKey)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let party1_message1: KeyGenMessage1 =
        db::get(&state.db, &claim.sub, &id, &Share::KgParty1Message1)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let party1_message2: KeyGenMessage2 =
        db::get(&state.db, &claim.sub, &id, &Share::KgParty1Message2)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let party2_message1: KeyGenMessage1 =
        db::get(&state.db, &claim.sub, &id, &Share::KgParty2Message1)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let party2_message2: KeyGenMessage2 =
        db::get(&state.db, &claim.sub, &id, &Share::KgParty2Message2)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let party2_additive_key: Keys = db::get(&state.db, &claim.sub, &id, &Share::AdditiveKey)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let (party2_message3, ss2_to_self, party2_y_vec, party2_ek_vec) = master_key2
        .rotation_third_message(
            &party2_additive_key,
            party1_message1,
            party2_message1,
            party1_message2,
            party2_message2,
        );

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::KgParty2Message3,
        &party2_message3,
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::KgParty1Message3,
        &party1_message3.clone(),
    )?;

    db::insert(&state.db, &claim.sub, &id, &Share::SS2, &ss2_to_self)?;

    db::insert(&state.db, &claim.sub, &id, &Share::KgYVec, &party2_y_vec)?;

    db::insert(&state.db, &claim.sub, &id, &Share::KgEkVec, &party2_ek_vec)?;

    Ok(Json(party2_message3))
}

#[post(
    "/ecdsa/rotate/<id>/fourth",
    format = "json",
    data = "<party1_message4>"
)]
pub fn rotate_fourth(
    state: State<Config>,
    claim: Claims,
    id: String,
    party1_message4: Json<KeyGenMessage4>,
) -> Result<Json<(KeyGenMessage4)>> {
    let master_key2: MasterKey2 = db::get(&state.db, &claim.sub, &id, &Share::PartyMasterKey)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_additive_key: Keys = db::get(&state.db, &claim.sub, &id, &Share::AdditiveKey)?
        .ok_or(format_err!("No data for such identifier {}", id))?;
    let party1_message3: KeyGenMessage3 =
        db::get(&state.db, &claim.sub, &id, &Share::KgParty1Message3)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let party2_message3: KeyGenMessage3 =
        db::get(&state.db, &claim.sub, &id, &Share::KgParty2Message3)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let ss2_to_self: FE = db::get(&state.db, &claim.sub, &id, &Share::SS2)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let party2_y_vec: Vec<GE> = db::get(&state.db, &claim.sub, &id, &Share::KgYVec)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let (party2_message4, party2_linear_key, party2_vss_vec) = MasterKey2::rotation_fourth_message(
        &party2_additive_key,
        party1_message3,
        party2_message3,
        ss2_to_self,
        &party2_y_vec,
    );

    let party2_ek_vec: Vec<EncryptionKey> =
        db::get(&state.db, &claim.sub, &id, &Share::KgEkVec)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let master_key2 = master_key2.rotate_master_key(
        party1_message4.clone(),
        party2_message4.clone(),
        party2_y_vec,
        party2_additive_key,
        party2_linear_key,
        party2_vss_vec,
        party2_ek_vec,
    );

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::PartyMasterKey,
        &master_key2,
    )?;

    Ok(Json(party2_message4))
}

#[post("/ecdsa/<id>/recover", format = "json")]
pub fn recover(state: State<Config>, claim: Claims, id: String) -> Result<Json<(HDPos)>> {
    let pos_old: HDPos = db::get(&state.db, &claim.sub, &id, &Share::POS)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    Ok(Json(pos_old))
}

use curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::{
    CommWitness, EcKeyPair,
};
use kms::ecdsa::two_party_lindell17::party1::KeyGenParty1Message2 as KeyGenParty1Message2L;
use kms::ecdsa::two_party_lindell17::party1::RotationParty1Message1 as RotationParty1Message1L;
use kms::rotation::two_party::party1::Rotation1;
/// LEGACY (LINDELL)
//legacy
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two;

#[derive(Serialize, Deserialize)]
pub struct Party2KeyGenCCFirst {
    pub kg_party_two_first_message_d_log_proof: DLogProof,
    pub cc_party_two_first_message_d_log_proof: DLogProof,
}

#[post("/ecdsa/keygen/first_legacy", format = "json")]
pub fn first_message_legacy(
    state: State<Config>,
    claim: Claims,
) -> Result<Json<(String, party_one::KeyGenFirstMsg, CCParty1FirstMessage)>> {
    let id = Uuid::new_v4().to_string();

    let (key_gen_first_msg, comm_witness, ec_key_pair) = MasterKey1L::key_gen_first_message();

    //save pos 0
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::POS,
        &HDPos { pos: 0u32 },
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::KeyGenFirstMsg,
        &key_gen_first_msg,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::CommWitness,
        &comm_witness,
    )?;
    db::insert(&state.db, &claim.sub, &id, &Share::EcKeyPair, &ec_key_pair)?;

    // starting chain code protocol in parallel:
    let (cc_party_one_first_message, cc_comm_witness, cc_ec_key_pair1) =
        chain_code::party1::ChainCode1::chain_code_first_message();

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::CCKeyGenFirstMsg,
        &cc_party_one_first_message,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::CCCommWitness,
        &cc_comm_witness,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::CCEcKeyPair,
        &cc_ec_key_pair1,
    )?;

    Ok(Json((id, key_gen_first_msg, cc_party_one_first_message)))
}

#[post(
    "/ecdsa/keygen/<id>/second_legacy",
    format = "json",
    data = "<party2_kg_cc_first>"
)]
pub fn second_message_legacy(
    state: State<Config>,
    claim: Claims,
    id: String,
    party2_kg_cc_first: Json<Party2KeyGenCCFirst>,
) -> Result<Json<(KeyGenParty1Message2L, CCParty1SecondMessage)>> {
    let party2_public: GE = party2_kg_cc_first
        .kg_party_two_first_message_d_log_proof
        .pk
        .clone();
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::Party2Public,
        &party2_public,
    )?;

    let comm_witness: party_one::CommWitness =
        db::get(&state.db, &claim.sub, &id, &Share::CommWitness)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let ec_key_pair: party_one::EcKeyPair = db::get(&state.db, &claim.sub, &id, &Share::EcKeyPair)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let (kg_party_one_second_message, paillier_key_pair, party_one_private) =
        MasterKey1L::key_gen_second_message(
            comm_witness,
            &ec_key_pair,
            &party2_kg_cc_first.kg_party_two_first_message_d_log_proof,
        );

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::PaillierKeyPair,
        &paillier_key_pair,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::Party1Private,
        &party_one_private,
    )?;

    let cc_comm_witness: CommWitness = db::get(&state.db, &claim.sub, &id, &Share::CCCommWitness)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let party1_cc = chain_code::party1::ChainCode1::chain_code_second_message(
        cc_comm_witness,
        &party2_kg_cc_first.cc_party_two_first_message_d_log_proof,
    );

    let party2_pub = &party2_kg_cc_first.cc_party_two_first_message_d_log_proof.pk;
    chain_code_compute_message(state, claim, id, party2_pub)?;

    Ok(Json((kg_party_one_second_message, party1_cc)))
}

#[post(
    "/ecdsa/keygen/<id>/third_legacy",
    format = "json",
    data = "<party_2_pdl_first_message>"
)]
pub fn third_message_legacy(
    state: State<Config>,
    claim: Claims,
    id: String,
    party_2_pdl_first_message: Json<party_two::PDLFirstMessage>,
) -> Result<Json<(party_one::PDLFirstMessage)>> {
    let party_one_private: party_one::Party1Private =
        db::get(&state.db, &claim.sub, &id, &Share::Party1Private)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let (party_one_third_message, party_one_pdl_decommit, alpha) =
        MasterKey1L::key_gen_third_message(&party_2_pdl_first_message.0, &party_one_private);

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::PDLDecommit,
        &party_one_pdl_decommit,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::Party2PDLFirstMsg,
        &party_2_pdl_first_message.0,
    )?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::PDLFirstMessage,
        &party_one_third_message,
    )?;

    db::insert(&state.db, &claim.sub, &id, &Share::Alpha, &alpha)?;

    Ok(Json(party_one_third_message))
}

#[post(
    "/ecdsa/keygen/<id>/fourth_legacy",
    format = "json",
    data = "<party_two_pdl_second_message>"
)]
pub fn fourth_message_legacy(
    state: State<Config>,
    claim: Claims,
    id: String,
    party_two_pdl_second_message: Json<party_two::PDLSecondMessage>,
) -> Result<Json<(party_one::PDLSecondMessage)>> {
    let alpha: BigInt = db::get(&state.db, &claim.sub, &id, &Share::Alpha)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let party_one_private: party_one::Party1Private =
        db::get(&state.db, &claim.sub, &id, &Share::Party1Private)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party_one_pdl_decommit: party_one::PDLdecommit =
        db::get(&state.db, &claim.sub, &id, &Share::PDLDecommit)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party_2_pdl_first_message: party_two::PDLFirstMessage =
        db::get(&state.db, &claim.sub, &id, &Share::Party2PDLFirstMsg)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let res = MasterKey1L::key_gen_fourth_message(
        &party_2_pdl_first_message,
        &party_two_pdl_second_message.0,
        party_one_private,
        party_one_pdl_decommit,
        alpha,
    );

    assert!(res.is_ok());

    Ok(Json(res.unwrap()))
}

pub fn chain_code_compute_message(
    state: State<Config>,
    claim: Claims,
    id: String,
    cc_party2_public: &GE,
) -> Result<Json<()>> {
    let cc_ec_key_pair_party1: EcKeyPair =
        db::get(&state.db, &claim.sub, &id, &Share::CCEcKeyPair)?
            .ok_or(format_err!("No data for such identifier {}", id))?;
    let party1_cc = chain_code::party1::ChainCode1::compute_chain_code(
        &cc_ec_key_pair_party1,
        &cc_party2_public,
    );

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::CC,
        &party1_cc.chain_code,
    )?;
    master_key(state, claim, id)?;
    Ok(Json(()))
}

pub fn master_key(state: State<Config>, claim: Claims, id: String) -> Result<()> {
    let party2_public: GE = db::get(&state.db, &claim.sub, &id, &Share::Party2Public)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let paillier_key_pair: party_one::PaillierKeyPair =
        db::get(&state.db, &claim.sub, &id, &Share::PaillierKeyPair)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party1_cc: BigInt = db::get(&state.db, &claim.sub, &id, &Share::CC)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let party_one_private: party_one::Party1Private =
        db::get(&state.db, &claim.sub, &id, &Share::Party1Private)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let comm_witness: party_one::CommWitness =
        db::get(&state.db, &claim.sub, &id, &Share::CommWitness)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let masterKey = MasterKey1L::set_master_key(
        &party1_cc,
        party_one_private,
        &comm_witness.public_share,
        &party2_public,
        paillier_key_pair,
    );

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::PartyMasterKeyL,
        &masterKey,
    )
}

pub fn get_mk(state: &State<Config>, claim: Claims, id: &String) -> Result<MasterKey1L> {
    db::get(&state.db, &claim.sub, &id, &Share::PartyMasterKeyL)?
        .ok_or(format_err!("No data for such identifier {}", id))
}

#[post("/ecdsa/rotate/<id>/first_legacy", format = "json")]
pub fn rotate_first_legacy(
    state: State<Config>,
    claim: Claims,
    id: String,
) -> Result<Json<(coin_flip_optimal_rounds::Party1FirstMessage)>> {
    let (party1_coin_flip_first_message, m1, r1) = Rotation1::key_rotate_first_message();
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::RotateCommitMessage1M,
        &m1,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::RotateCommitMessage1R,
        &r1,
    )?;
    Ok(Json(party1_coin_flip_first_message))
}

#[post(
    "/ecdsa/rotate/<id>/second_legacy",
    format = "json",
    data = "<party2_first_message>"
)]
pub fn rotate_second_legacy(
    state: State<Config>,
    id: String,
    claim: Claims,
    party2_first_message: Json<coin_flip_optimal_rounds::Party2FirstMessage>,
) -> Result<
    Json<
        ((
            coin_flip_optimal_rounds::Party1SecondMessage,
            RotationParty1Message1L,
        )),
    >,
> {
    let party_one_master_key = get_mk(&state, claim.clone(), &id)?;

    let m1: Secp256k1Scalar = db::get(&state.db, &claim.sub, &id, &Share::RotateCommitMessage1M)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let r1: Secp256k1Scalar = db::get(&state.db, &claim.sub, &id, &Share::RotateCommitMessage1R)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let (party1_second_message, random1) =
        Rotation1::key_rotate_second_message(&party2_first_message.0, &m1, &r1);
    db::insert(&state.db, &claim.sub, &id, &Share::RotateRandom1, &random1)?;

    let (rotation_party_one_first_message, party_one_private_new) =
        party_one_master_key.rotation_first_message(&random1);

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::RotateFirstMsg,
        &rotation_party_one_first_message,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::RotatePrivateNew,
        &party_one_private_new,
    )?;
    Ok(Json((
        party1_second_message,
        rotation_party_one_first_message,
    )))
}

#[post(
    "/ecdsa/rotate/<id>/third_legacy",
    format = "json",
    data = "<rotation_party_two_first_message>"
)]
pub fn rotate_third_legacy(
    state: State<Config>,
    claim: Claims,
    id: String,
    rotation_party_two_first_message: Json<party_two::PDLFirstMessage>,
) -> Result<Json<(party_one::PDLFirstMessage)>> {
    let party_one_private_new: party_one::Party1Private =
        db::get(&state.db, &claim.sub, &id, &Share::RotatePrivateNew)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let (rotation_party_one_second_message, party_one_pdl_decommit, alpha) =
        MasterKey1L::rotation_second_message(
            &rotation_party_two_first_message.0,
            &party_one_private_new,
        );
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::RotatePdlDecom,
        &party_one_pdl_decommit,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::RotateParty2First,
        &rotation_party_two_first_message.0,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Share::RotateParty1Second,
        &rotation_party_one_second_message,
    )?;

    db::insert(&state.db, &claim.sub, &id, &Share::Alpha, &alpha)?;

    Ok(Json(rotation_party_one_second_message))
}

#[post(
    "/ecdsa/rotate/<id>/fourth_legacy",
    format = "json",
    data = "<rotation_party_two_second_message>"
)]
pub fn rotate_fourth_legacy(
    state: State<Config>,
    claim: Claims,
    id: String,
    rotation_party_two_second_message: Json<party_two::PDLSecondMessage>,
) -> Result<Json<(party_one::PDLSecondMessage)>> {
    let party_one_master_key = get_mk(&state, claim.clone(), &id)?;

    let rotation_party_one_first_message: RotationParty1Message1L =
        db::get(&state.db, &claim.sub, &id, &Share::RotateFirstMsg)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party_one_private_new: party_one::Party1Private =
        db::get(&state.db, &claim.sub, &id, &Share::RotatePrivateNew)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let random1: kms::rotation::two_party::Rotation =
        db::get(&state.db, &claim.sub, &id, &Share::RotateRandom1)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let alpha: BigInt = db::get(&state.db, &claim.sub, &id, &Share::Alpha)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let rotation_party_two_first_message: party_two::PDLFirstMessage =
        db::get(&state.db, &claim.sub, &id, &Share::RotateParty2First)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let party_one_pdl_decommit: party_one::PDLdecommit =
        db::get(&state.db, &claim.sub, &id, &Share::RotatePdlDecom)?
            .ok_or(format_err!("No data for such identifier {}", id))?;

    let result_rotate_party_two_second_message = party_one_master_key.rotation_third_message(
        &rotation_party_one_first_message,
        party_one_private_new,
        &random1,
        &rotation_party_two_first_message,
        &rotation_party_two_second_message.0,
        party_one_pdl_decommit,
        alpha,
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
        &Share::PartyMasterKeyL,
        &party_one_master_key_rotated,
    )?;

    Ok(Json(rotation_party_one_third_message))
}

#[post("/ecdsa/<id>/recover_legacy", format = "json")]
pub fn recover_legacy(state: State<Config>, claim: Claims, id: String) -> Result<Json<(HDPos)>> {
    let pos_old: HDPos = db::get(&state.db, &claim.sub, &id, &Share::POS)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    Ok(Json(pos_old))
}
