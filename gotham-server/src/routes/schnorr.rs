use super::super::Result;
use rocket::State;
use rocket_contrib::json::Json;

use super::super::auth::jwt::Claims;
use super::super::storage::db;
use super::super::Config;

use uuid::Uuid;
use multi_party_schnorr::protocols::thresholdsig::zilliqa_schnorr::*;
use self::SchnorrStruct::*;

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
    Party1SharedKey
}

impl db::MPCStruct for SchnorrStruct {
    fn to_string(&self) -> String {
        format!("Schnorr{:?}", self)
    }
}

#[post("/schnorr/keygen/first", format = "json", data = "<party2_msg1>")]
pub fn keygen_first(
    state: State<Config>,
    claim: Claims,
    party2_msg1: Json<KeyGenBroadcastMessage1>,
) -> Result<Json<(String, KeyGenBroadcastMessage1)>> {
    let id = Uuid::new_v4().to_string();
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party2KeyGenBroadcastMessage1,
        &party2_msg1.0,
    )?;

    let key: Keys = Keys::phase1_create(1);
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party1Key,
        &key,
    )?;

    let (msg1, msg2) = key.phase1_broadcast();
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party1KeyGenBroadcastMessage1,
        &msg1,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party1KeyGenBroadcastMessage2,
        &msg2,
    )?;

    Ok(Json((id, msg1)))
}

#[post("/schnorr/keygen/<id>/second", format = "json", data = "<party2_msg2>")]
pub fn keygen_second(
    state: State<Config>,
    claim: Claims,
    id: String,
    party2_msg2: Json<KeyGenBroadcastMessage2>,
) -> Result<Json<KeyGenBroadcastMessage2>> {
    let key: Keys = db::get(
        &state.db,
        &claim.sub,
        &id,
        &Party1Key)?
        .ok_or(format_err!("No data for such identifier {}", id))?;
    let msg1: KeyGenBroadcastMessage1 = db::get(
        &state.db,
        &claim.sub,
        &id,
        &Party1KeyGenBroadcastMessage1)?
        .ok_or(format_err!("No data for such identifier {}", id))?;
    let msg2: KeyGenBroadcastMessage2 = db::get(
        &state.db,
        &claim.sub,
        &id,
        &Party1KeyGenBroadcastMessage2)?
        .ok_or(format_err!("No data for such identifier {}", id))?;
    let party2_msg1: KeyGenBroadcastMessage1 = db::get(
        &state.db,
        &claim.sub,
        &id,
        &Party2KeyGenBroadcastMessage1)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let (vss_scheme, secret_shares, _index) = key.phase1_verify_com_phase2_distribute(
        &PARAMS,
        &vec![msg2, party2_msg2.0.clone()],
        &vec![msg1, party2_msg1],
        &vec![PARTY1_INDEX, PARTY2_INDEX])
        .or_else(|e| Err(e))?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party2KeyGenBroadcastMessage2,
        &party2_msg2.0,
    )?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &Party1VerifiableSecretShares,
        &vss_scheme,
    )?;
    db::insert(
        &state.db,
&claim.sub,
        &id,
        &Party1SecretShares,
        &secret_shares,
    )?;
    let msg2: KeyGenBroadcastMessage2 = db::get(
        &state.db,
&claim.sub,
        &id,
        &Party1KeyGenBroadcastMessage2)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    Ok(Json(msg2))
}

#[post("/schnorr/keygen/<id>/third", format = "json", data = "<party2_msg3>")]
pub fn keygen_third(
    state: State<Config>,
    claim: Claims,
    id: String,
    party2_msg3: Json<KeyGenMessage3>,
) -> Result<Json<KeyGenMessage3>> {
    let key: Keys = db::get(
        &state.db,
&claim.sub,
        &id,
        &Party1Key)?
        .ok_or(format_err!("No data for such identifier {}", id))?;
    let party2_msg2: KeyGenBroadcastMessage2 = db::get(
        &state.db,
&claim.sub,
        &id,
        &Party2KeyGenBroadcastMessage2)?
        .ok_or(format_err!("No data for such identifier {}", id))?;
    let vss_scheme: VerifiableSS = db::get(
        &state.db,
&claim.sub,
        &id,
        &Party1VerifiableSecretShares)?
        .ok_or(format_err!("No data for such identifier {}", id))?;
    let secret_shares: Vec<FE> = db::get(
        &state.db,
&claim.sub,
        &id,
        &Party1SecretShares)?
        .ok_or(format_err!("No data for such identifier {}", id))?;

    let shared_key: SharedKeys = key.phase2_verify_vss_construct_keypair(
        &PARAMS,
        &vec![key.y_i, party2_msg2.y_i],
        &vec![secret_shares[key.party_index - 1], party2_msg3.0.secret_share],
        &vec![vss_scheme.clone(), party2_msg3.0.vss_scheme.clone()],
        &(key.party_index))
        .or_else(|e| Err(e))?;

    db::insert(
        &state.db,
&claim.sub,
        &id,
        &Party1SharedKey,
        &shared_key,
    )?;

    db::insert(
        &state.db,
&claim.sub,
        &id,
        &Party2VerifiableSecretShares,
        &party2_msg3.0.vss_scheme,
    )?;

    let msg3: KeyGenMessage3 = KeyGenMessage3 {
        vss_scheme,
        secret_share: secret_shares[PARTY2_INDEX - 1],
    };

    Ok(Json(msg3))
}

#[post("/schnorr/sign/<keygen_id>/<eph_keygen_id>", format = "json", data = "<party2_sign_msg1>")]
pub fn sign(
    state: State<Config>,
    claim: Claims,
    keygen_id: String,
    eph_keygen_id: String,
    party2_sign_msg1: Json<SignMessage1>,
) -> Result<Json<LocalSig>> {
    let shared_key: SharedKeys = db::get(
        &state.db,
&claim.sub,
        &keygen_id,
        &Party1SharedKey)?
        .ok_or(format_err!("No data for such identifier {}", keygen_id))?;
    let eph_shared_key: SharedKeys = db::get(
        &state.db,
&claim.sub,
        &eph_keygen_id,
        &Party1SharedKey)?
        .ok_or(format_err!("No data for such identifier {}", eph_keygen_id))?;

    let local_sig = LocalSig::compute(
        &BigInt::to_vec(&party2_sign_msg1.message).as_slice(),
        &eph_shared_key,
        &shared_key);

    let vss_scheme: VerifiableSS = db::get(
        &state.db,
&claim.sub,
        &keygen_id,
        &Party1VerifiableSecretShares)?
        .ok_or(format_err!("No data for such identifier {}", keygen_id))?;
    let party2_vss_scheme: VerifiableSS = db::get(
        &state.db,
&claim.sub,
        &keygen_id,
        &Party2VerifiableSecretShares)?
        .ok_or(format_err!("No data for such identifier {}", keygen_id))?;
    let eph_vss_scheme: VerifiableSS = db::get(
        &state.db,
        &claim.sub,
        &eph_keygen_id,
        &Party1VerifiableSecretShares)?
        .ok_or(format_err!("No data for such identifier {}", eph_keygen_id))?;
    let party2_eph_vss_scheme: VerifiableSS = db::get(
        &state.db,
        &claim.sub,
        &eph_keygen_id,
        &Party2VerifiableSecretShares)?
        .ok_or(format_err!("No data for such identifier {}", eph_keygen_id))?;

    LocalSig::verify_local_sigs(
        &vec![local_sig, party2_sign_msg1.local_sig],
        &vec![PARTY1_INDEX - 1, PARTY2_INDEX - 1],
        &vec![vss_scheme, party2_vss_scheme],
        &vec![eph_vss_scheme, party2_eph_vss_scheme])
        .or_else(|e| Err(format_err!("{}", e)))
        .and_then(|_vss_scheme| Ok(Json(local_sig)))
}