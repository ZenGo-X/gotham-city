use super::super::Result;
use rocket::State;
use rocket_contrib::json::Json;
use uuid::Uuid;

use super::super::auth::jwt::Claims;
use super::super::storage::db;
use super::super::Config;

use multi_party_eddsa::protocols::aggsig::*;
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
    Party1SignSecondMsg
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
pub fn keygen(
    state: State<Config>,
    claim: Claims,
    party2_public_key_json: Json<GE>,
) -> Result<Json<(String, GE)>> {
    let id = Uuid::new_v4().to_string();
    let party1_key_pair: KeyPair = KeyPair::create();
    let eight: FE = ECScalar::from(&BigInt::from(8));
    let eight_inverse: FE = eight.invert();
    let party2_public_key = party2_public_key_json.0 * &eight_inverse;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party2PublicKey,
        &party2_public_key,
    )?;

    // compute apk:
    let mut pks: Vec<GE> = Vec::new();
    pks.push(party1_key_pair.public_key.clone());
    pks.push(party2_public_key.clone());
    let key_agg = KeyPair::key_aggregation_n(&pks, &PARTY1_INDEX);
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party1KeyPair,
        &party1_key_pair,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &AggregatedPublicKey,
        &key_agg,
    )?;

    Ok(Json((id, party1_key_pair.public_key)))
}

#[post("/eddsa/sign/<id>/first", format = "json", data = "<party2_sign_first_msg_obj>")]
pub fn sign_first(
    state: State<Config>,
    claim: Claims,
    id: String,
    party2_sign_first_msg_obj: Json<(SignFirstMsg, BigInt)>,
) -> Result<Json<SignFirstMsg>> {
    let (party2_sign_first_msg, message): (SignFirstMsg, BigInt) =
        party2_sign_first_msg_obj.0;

    let party1_key_pair: KeyPair = db::get(
        &state.db,
        &claim.sub,
        &id,
        &Party1KeyPair)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let (party1_ephemeral_key, party1_sign_first_msg, party1_sign_second_msg) =
        Signature::create_ephemeral_key_and_commit(&party1_key_pair, &BigInt::to_vec(&message).as_slice());

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party2SignFirstMsg,
        &party2_sign_first_msg,
    )?;

    let message_struct = MessageStruct {
        message,
    };
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Message,
        &message_struct,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party1EphemeralKey,
        &party1_ephemeral_key,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party1SignFirstMsg,
        &party1_sign_first_msg,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party1SignSecondMsg,
        &party1_sign_second_msg,
    )?;

    Ok(Json(party1_sign_first_msg))
}

#[allow(non_snake_case)]
#[post("/eddsa/sign/<id>/second", format = "json", data = "<party2_sign_second_msg>")]
pub fn sign_second(
    state: State<Config>,
    claim: Claims,
    id: String,
    mut party2_sign_second_msg: Json<SignSecondMsg>,
) -> Result<Json<(SignSecondMsg, Signature)>> {
    let party2_sign_first_msg: SignFirstMsg = db::get(
        &state.db,
        &claim.sub,
        &id,
        &Party2SignFirstMsg)?
        .ok_or(format_err!("No data for such identifier {}", id))?;
    let eight: FE = ECScalar::from(&BigInt::from(8));
    let eight_inverse: FE = eight.invert();
    party2_sign_second_msg.R = party2_sign_second_msg.R * &eight_inverse;
    assert!(test_com(
        &party2_sign_second_msg.R,
        &party2_sign_second_msg.blind_factor,
        &party2_sign_first_msg.commitment
    ));

    let party1_key_pair: KeyPair = db::get(
        &state.db,
        &claim.sub,
        &id,
        &Party1KeyPair)?
        .ok_or(format_err!("No data for such identifier {}", id))?;
    let mut party1_ephemeral_key: EphemeralKey = db::get(
        &state.db,
        &claim.sub,
        &id,
        &Party1EphemeralKey)?
        .ok_or(format_err!("No data for such identifier {}", id))?;
    let mut party1_sign_second_msg: SignSecondMsg = db::get(
        &state.db,
        &claim.sub,
        &id,
        &Party1SignSecondMsg)?
        .ok_or(format_err!("No data for such identifier {}", id))?;
    party1_ephemeral_key.R = party1_ephemeral_key.R * &eight_inverse;
    party1_sign_second_msg.R = party1_sign_second_msg.R * &eight_inverse;
    let mut key_agg: KeyAgg = db::get(
        &state.db,
        &claim.sub,
        &id,
        &AggregatedPublicKey)?
        .ok_or(format_err!("No data for such identifier {}", id))?;
    key_agg.apk = key_agg.apk * &eight_inverse;
    let message_struct: MessageStruct = db::get(
        &state.db,
        &claim.sub,
        &id,
        &Message)?
        .ok_or(format_err!("No data for such identifier {}", id))?;
    let message: BigInt = message_struct.message;

    // compute R' = sum(Ri):
    let mut Ri: Vec<GE> = Vec::new();
    Ri.push(party1_sign_second_msg.R.clone());
    Ri.push(party2_sign_second_msg.R.clone());
    // each party i should run this:
    let R_tot = Signature::get_R_tot(Ri);
    let k = Signature::k(&R_tot, &key_agg.apk, &BigInt::to_vec(&message).as_slice());
    let s1 = Signature::partial_sign(
        &party1_ephemeral_key.r,
        &party1_key_pair,
        &k,
        &key_agg.hash,
        &R_tot,
    );

    Ok(Json((party1_sign_second_msg, s1)))
}