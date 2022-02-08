use rocket::serde::json::Json;
use rocket::State;
use uuid::Uuid;

use super::super::auth::jwt::Claims;
use super::super::storage::db;
use super::super::Config;

use self::EddsaStruct::*;
use curv::elliptic::curves::ed25519::{FE, GE};
use curv::BigInt;
use multi_party_eddsa::protocols::aggsig::*;

const PARTY1_INDEX: usize = 0;

#[derive(Debug)]
pub enum EddsaStruct {
    Party2PublicKey,
    Party1KeyPair,
    AggregatedPublicKey,
    Party2SignFirstMsg,
    Message,
    Party1EphemeralKey,
    Party1SignFirstMsg,
    Party1SignSecondMsg,
}

impl db::MPCStruct for EddsaStruct {
    fn to_string(&self) -> String {
        format!("Eddsa{:?}", self)
    }
}

// creating a wrapper for dynamodb insertion compatibility
#[derive(Debug, Serialize, Deserialize)]
struct MessageStruct {
    message: BigInt,
}

#[post("/eddsa/keygen", format = "json", data = "<party2_public_key_json>")]
pub async fn keygen(
    state: &State<Config>,
    claim: Claims,
    party2_public_key_json: Json<GE>,
) -> Result<Json<(String, GE)>, String> {
    let id = Uuid::new_v4().to_string();
    let party1_key_pair: KeyPair = KeyPair::create();
    let eight: FE = ECScalar::from(&BigInt::from(8u32));
    let eight_inverse: FE = eight.invert();
    let party2_public_key = party2_public_key_json.0 * eight_inverse;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party2PublicKey,
        &party2_public_key,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    // compute apk:
    let pks: Vec<GE> = vec![party1_key_pair.public_key, party2_public_key];
    let key_agg = KeyPair::key_aggregation_n(&pks, &PARTY1_INDEX);
    db::insert(&state.db, &claim.sub, &id, &Party1KeyPair, &party1_key_pair)
        .await
        .or(Err("Failed to insert into db"))?;
    db::insert(&state.db, &claim.sub, &id, &AggregatedPublicKey, &key_agg)
        .await
        .or(Err("Failed to insert into db"))?;

    Ok(Json((id, party1_key_pair.public_key)))
}

#[post(
    "/eddsa/sign/<id>/first",
    format = "json",
    data = "<party2_sign_first_msg_obj>"
)]
pub async fn sign_first(
    state: &State<Config>,
    claim: Claims,
    id: String,
    party2_sign_first_msg_obj: Json<(SignFirstMsg, BigInt)>,
) -> Result<Json<SignFirstMsg>, String> {
    let (party2_sign_first_msg, message): (SignFirstMsg, BigInt) = party2_sign_first_msg_obj.0;

    let party1_key_pair: KeyPair = db::get(&state.db, &claim.sub, &id, &Party1KeyPair)
        .await
        .or(Err("Failed to get from db"))?
        .ok_or(format!("No data for such identifier {}", id))?;

    let (party1_ephemeral_key, party1_sign_first_msg, party1_sign_second_msg) =
        Signature::create_ephemeral_key_and_commit(
            &party1_key_pair,
            BigInt::to_bytes(&message).as_slice(),
        );

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party2SignFirstMsg,
        &party2_sign_first_msg,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    let message_struct = MessageStruct { message };
    db::insert(&state.db, &claim.sub, &id, &Message, &message_struct)
        .await
        .or(Err("Failed to insert into db"))?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party1EphemeralKey,
        &party1_ephemeral_key,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party1SignFirstMsg,
        &party1_sign_first_msg,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party1SignSecondMsg,
        &party1_sign_second_msg,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    Ok(Json(party1_sign_first_msg))
}

#[allow(non_snake_case)]
#[post(
    "/eddsa/sign/<id>/second",
    format = "json",
    data = "<party2_sign_second_msg>"
)]
pub async fn sign_second(
    state: &State<Config>,
    claim: Claims,
    id: String,
    mut party2_sign_second_msg: Json<SignSecondMsg>,
) -> Result<Json<(SignSecondMsg, Signature)>, String> {
    let party2_sign_first_msg: SignFirstMsg =
        db::get(&state.db, &claim.sub, &id, &Party2SignFirstMsg)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;
    let eight: FE = ECScalar::from(&BigInt::from(8u32));
    let eight_inverse: FE = eight.invert();
    party2_sign_second_msg.R = party2_sign_second_msg.R * eight_inverse;
    assert!(test_com(
        &party2_sign_second_msg.R,
        &party2_sign_second_msg.blind_factor,
        &party2_sign_first_msg.commitment
    ));

    let party1_key_pair: KeyPair = db::get(&state.db, &claim.sub, &id, &Party1KeyPair)
        .await
        .or(Err("Failed to get from db"))?
        .ok_or(format!("No data for such identifier {}", id))?;
    let mut party1_ephemeral_key: EphemeralKey =
        db::get(&state.db, &claim.sub, &id, &Party1EphemeralKey)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;
    let mut party1_sign_second_msg: SignSecondMsg =
        db::get(&state.db, &claim.sub, &id, &Party1SignSecondMsg)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;
    party1_ephemeral_key.R = party1_ephemeral_key.R * eight_inverse;
    party1_sign_second_msg.R = party1_sign_second_msg.R * eight_inverse;
    let mut key_agg: KeyAgg = db::get(&state.db, &claim.sub, &id, &AggregatedPublicKey)
        .await
        .or(Err("Failed to get from db"))?
        .ok_or(format!("No data for such identifier {}", id))?;
    key_agg.apk = key_agg.apk * eight_inverse;
    let message_struct: MessageStruct = db::get(&state.db, &claim.sub, &id, &Message)
        .await
        .or(Err("Failed to get from db"))?
        .ok_or(format!("No data for such identifier {}", id))?;
    let message: BigInt = message_struct.message;

    // compute R' = sum(Ri):
    let Ri: Vec<GE> = vec![party1_sign_second_msg.R, party2_sign_second_msg.R];
    // each party i should run this:
    let R_tot = Signature::get_R_tot(Ri);
    let k = Signature::k(&R_tot, &key_agg.apk, BigInt::to_bytes(&message).as_slice());
    let s1 = Signature::partial_sign(
        &party1_ephemeral_key.r,
        &party1_key_pair,
        &k,
        &key_agg.hash,
        &R_tot,
    );

    Ok(Json((party1_sign_second_msg, s1)))
}
