use rocket::serde::json::Json;
use rocket::State;

use super::super::auth::jwt::Claims;
use super::super::storage::db;
use super::super::Config;

use self::SchnorrStruct::*;
use multi_party_schnorr::protocols::thresholdsig::zilliqa_schnorr::*;
use uuid::Uuid;

use curv::elliptic::curves::secp256_k1::{FE, GE};

const PARTY1_INDEX: usize = 1;
const PARTY2_INDEX: usize = 2;
const PARAMS: Parameters = Parameters {
    threshold: 1,
    share_count: 2,
};

#[derive(Debug)]
pub enum SchnorrStruct {
    Party1Key,
    Party1KeyGenBroadcastMessage1,
    Party2KeyGenBroadcastMessage1,
    Party1KeyGenBroadcastMessage2,
    Party2KeyGenBroadcastMessage2,
    Party1VerifiableSecretShares,
    Party2VerifiableSecretShares,
    Party1SecretShares,
    Party1SharedKey,
}

impl db::MPCStruct for SchnorrStruct {
    fn to_string(&self) -> String {
        format!("Schnorr{:?}", self)
    }
}

#[post("/schnorr/keygen/first", format = "json", data = "<party2_msg1>")]
pub async fn keygen_first(
    state: &State<Config>,
    claim: Claims,
    party2_msg1: Json<KeyGenBroadcastMessage1>,
) -> Result<Json<(String, KeyGenBroadcastMessage1)>, String> {
    let id = Uuid::new_v4().to_string();
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party2KeyGenBroadcastMessage1,
        &party2_msg1.0,
    )
    .await
    .or(Err("Failed to insert to db"))?;

    let key: Keys = Keys::phase1_create(1);
    db::insert(&state.db, &claim.sub, &id, &Party1Key, &key)
        .await
        .or(Err("Failed to insert to db"))?;

    let (msg1, msg2) = key.phase1_broadcast();
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party1KeyGenBroadcastMessage1,
        &msg1,
    )
    .await
    .or(Err("Failed to insert to db"))?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party1KeyGenBroadcastMessage2,
        &msg2,
    )
    .await
    .or(Err("Failed to insert to db"))?;

    Ok(Json((id, msg1)))
}

#[post("/schnorr/keygen/<id>/second", format = "json", data = "<party2_msg2>")]
pub async fn keygen_second(
    state: &State<Config>,
    claim: Claims,
    id: String,
    party2_msg2: Json<KeyGenBroadcastMessage2>,
) -> Result<Json<KeyGenBroadcastMessage2>, String> {
    let key: Keys = db::get(&state.db, &claim.sub, &id, &Party1Key)
        .await
        .or(Err("Failed to get from db"))?
        .ok_or(format!("No data for such identifier {}", id))?;
    let msg1: KeyGenBroadcastMessage1 =
        db::get(&state.db, &claim.sub, &id, &Party1KeyGenBroadcastMessage1)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;
    let msg2: KeyGenBroadcastMessage2 =
        db::get(&state.db, &claim.sub, &id, &Party1KeyGenBroadcastMessage2)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;
    let party2_msg1: KeyGenBroadcastMessage1 =
        db::get(&state.db, &claim.sub, &id, &Party2KeyGenBroadcastMessage1)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;

    let (vss_scheme, secret_shares, _index) = key
        .phase1_verify_com_phase2_distribute(
            &PARAMS,
            &vec![msg2, party2_msg2.0.clone()],
            &vec![msg1, party2_msg1],
            &[PARTY1_INDEX, PARTY2_INDEX],
        )
        .map_err(|e| e.to_string())?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party2KeyGenBroadcastMessage2,
        &party2_msg2.0,
    )
    .await
    .or(Err("Failed to insert to db"))?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party1VerifiableSecretShares,
        &vss_scheme,
    )
    .await
    .or(Err("Failed to insert to db"))?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party1SecretShares,
        &secret_shares,
    )
    .await
    .or(Err("Failed to insert to db"))?;
    let msg2: KeyGenBroadcastMessage2 =
        db::get(&state.db, &claim.sub, &id, &Party1KeyGenBroadcastMessage2)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;

    Ok(Json(msg2))
}

#[post("/schnorr/keygen/<id>/third", format = "json", data = "<party2_msg3>")]
pub async fn keygen_third(
    state: &State<Config>,
    claim: Claims,
    id: String,
    party2_msg3: Json<KeyGenMessage3>,
) -> Result<Json<KeyGenMessage3>, String> {
    let key: Keys = db::get(&state.db, &claim.sub, &id, &Party1Key)
        .await
        .or(Err("failed to get from db"))?
        .ok_or(format!("No data for such identifier {}", id))?;
    let party2_msg2: KeyGenBroadcastMessage2 =
        db::get(&state.db, &claim.sub, &id, &Party2KeyGenBroadcastMessage2)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;
    let vss_scheme: VerifiableSS<GE> =
        db::get(&state.db, &claim.sub, &id, &Party1VerifiableSecretShares)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;
    let secret_shares: Vec<FE> = db::get(&state.db, &claim.sub, &id, &Party1SecretShares)
        .await
        .or(Err("Failed to get from db"))?
        .ok_or(format!("No data for such identifier {}", id))?;

    let shared_key: SharedKeys = key
        .phase2_verify_vss_construct_keypair(
            &PARAMS,
            &vec![key.y_i, party2_msg2.y_i],
            &vec![
                secret_shares[key.party_index - 1],
                party2_msg3.0.secret_share,
            ],
            &vec![vss_scheme.clone(), party2_msg3.0.vss_scheme.clone()],
            &(key.party_index),
        )
        .map_err(|e| e.to_string())?;

    db::insert(&state.db, &claim.sub, &id, &Party1SharedKey, &shared_key)
        .await
        .or(Err("Failed to insert into db"))?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party2VerifiableSecretShares,
        &party2_msg3.0.vss_scheme,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    let msg3: KeyGenMessage3 = KeyGenMessage3 {
        vss_scheme,
        secret_share: secret_shares[PARTY2_INDEX - 1],
    };

    Ok(Json(msg3))
}

#[post(
    "/schnorr/sign/<keygen_id>/<eph_keygen_id>",
    format = "json",
    data = "<party2_sign_msg1>"
)]
pub async fn sign(
    state: &State<Config>,
    claim: Claims,
    keygen_id: String,
    eph_keygen_id: String,
    party2_sign_msg1: Json<SignMessage1>,
) -> Result<Json<LocalSig>, String> {
    let shared_key: SharedKeys = db::get(&state.db, &claim.sub, &keygen_id, &Party1SharedKey)
        .await
        .or(Err("Failed to get from db"))?
        .ok_or(format!("No data for such identifier {}", keygen_id))?;
    let eph_shared_key: SharedKeys =
        db::get(&state.db, &claim.sub, &eph_keygen_id, &Party1SharedKey)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", eph_keygen_id))?;

    let local_sig = LocalSig::compute(
        BigInt::to_bytes(&party2_sign_msg1.message).as_slice(),
        &eph_shared_key,
        &shared_key,
    );

    let vss_scheme: VerifiableSS<GE> = db::get(
        &state.db,
        &claim.sub,
        &keygen_id,
        &Party1VerifiableSecretShares,
    )
    .await
    .or(Err("Failed to get from db"))?
    .ok_or(format!("No data for such identifier {}", keygen_id))?;
    let party2_vss_scheme: VerifiableSS<GE> = db::get(
        &state.db,
        &claim.sub,
        &keygen_id,
        &Party2VerifiableSecretShares,
    )
    .await
    .or(Err("Failed to get from db"))?
    .ok_or(format!("No data for such identifier {}", keygen_id))?;
    let eph_vss_scheme: VerifiableSS<GE> = db::get(
        &state.db,
        &claim.sub,
        &eph_keygen_id,
        &Party1VerifiableSecretShares,
    )
    .await
    .or(Err("Failed to get from db"))?
    .ok_or(format!("No data for such identifier {}", eph_keygen_id))?;
    let party2_eph_vss_scheme: VerifiableSS<GE> = db::get(
        &state.db,
        &claim.sub,
        &eph_keygen_id,
        &Party2VerifiableSecretShares,
    )
    .await
    .or(Err("Failed to get from db"))?
    .ok_or(format!("No data for such identifier {}", eph_keygen_id))?;

    LocalSig::verify_local_sigs(
        &vec![local_sig, party2_sign_msg1.local_sig],
        &[PARTY1_INDEX - 1, PARTY2_INDEX - 1],
        &vec![vss_scheme, party2_vss_scheme],
        &vec![eph_vss_scheme, party2_eph_vss_scheme],
    )
    .map_err(|e| e.to_string())
    .map(|_vss_scheme| Json(local_sig))
}
