use std::str::FromStr;

use rocket::State;
use uuid::Uuid;

use super::super::auth::jwt::Claims;
use super::super::storage::db;
use super::super::Config;
use rocket::{post, serde::json::Json};

use self::EddsaStruct::*;

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
#[post("/eddsa/keygen", format = "json", data = "<party2_public_key_json>")]
pub async fn keygen(
    state: &State<Config>,
    claim: Claims,
    party2_public_key_json: String,
) -> Result<String, String> {
    // let id = Uuid::new_v4().to_string();
    // let party1_key_pair: KeyPair = KeyPair::create();
    // let eight: FE = ECScalar::from(&BigInt::from(8));
    // let eight_inverse: FE = eight.invert();
    // let party2_public_key = party2_public_key_json.0 * &eight_inverse;
    // db::insert(
    //     &state.db,
    //     &claim.sub,
    //     &id,
    //     &Party2PublicKey,
    //     &party2_public_key,
    // )?;

    // // compute apk:
    // let mut pks: Vec<GE> = Vec::new();
    // pks.push(party1_key_pair.public_key.clone());
    // pks.push(party2_public_key.clone());
    // let key_agg = KeyPair::key_aggregation_n(&pks, &PARTY1_INDEX);
    // db::insert(&state.db, &claim.sub, &id, &Party1KeyPair, &party1_key_pair)?;
    // db::insert(&state.db, &claim.sub, &id, &AggregatedPublicKey, &key_agg)?;

    // Ok(Json((id, party1_key_pair.public_key)))
    let default_id = Uuid::from_bytes([0u8; 16]);
    Ok("[\"d9876a6a-d135-40f0-bde7-e3c21ffb06aa\",{\"bytes_str\":\"52306ad4863fb676f9d9534629c3b89e5315114e76f719325a1172bc668de3bd\"}]".to_string())
}
