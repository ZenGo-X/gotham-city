use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use zk_paillier::zkproofs::*;
use curv::cryptographic_primitives::proofs::dlog_zk_protocol::*;

use rocket_contrib::json::{Json};
use uuid::Uuid;
use rocksdb::DB;
use serde_json;

use super::super::utilities::db;

#[post("/party1/first", format = "json")]
pub fn party1_first_message() -> Json<(
    String,
    party_one::KeyGenFirstMsg,
    party_one::CommWitness,
    party_one::EcKeyPair)>
{
    let DB : DB = DB::open_default("./db").unwrap();

    let keygen_id = Uuid::new_v4().to_string();

    let (keyGenFirstMsg, commWitness, ecKeyPair) =
        MasterKey1::key_gen_first_message();

    db::insert(&DB, &keygen_id, "keyGenFirstMsg", &keyGenFirstMsg);
    db::insert(&DB, &keygen_id, "commWitness", &commWitness);
    db::insert(&DB, &keygen_id, "ecKeyPair", &ecKeyPair);

    Json((keygen_id, keyGenFirstMsg, commWitness, ecKeyPair))
}

/*

#[post("/party1/second", format = "json", data = "<comm_witness>")]
pub fn party1_second_message(
    comm_witness: Json<party_one::CommWitness>,
    ec_key_pair_party1: Json<party_one::EcKeyPair>,
    proof: Json<DLogProof>,
) -> Json<(
    party_one::KeyGenSecondMsg,
    party_one::PaillierKeyPair,
    RangeProofNi,
    NICorrectKeyProof)>
{
    Json(MasterKey1::key_gen_second_message(
        comm_witness.0, &ec_key_pair_party1.0, proof.0))
}
*/