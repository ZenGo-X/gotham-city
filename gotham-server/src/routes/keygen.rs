use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use zk_paillier::zkproofs::*;
use curv::cryptographic_primitives::proofs::dlog_zk_protocol::*;

use rocket::State;
use rocket_contrib::json::{Json};
use uuid::Uuid;
use rocksdb::DB;
use serde_json;

use super::super::utilities::db;

pub struct Config {
    pub db : DB
}

#[post("/party1/first", format = "json")]
pub fn party1_first_message(state: State<Config>) -> Json<String> {
    let id = Uuid::new_v4().to_string();

    let (key_gen_first_msg, comm_witness, ec_key_pair) =
        MasterKey1::key_gen_first_message();

    db::insert(&state.db, &id, "key_gen_first_msg", &key_gen_first_msg);
    db::insert(&state.db, &id, "comm_witness", &comm_witness);
    db::insert(&state.db, &id, "ec_key_pair", &ec_key_pair);

    Json(id)
}


#[post("/party1/<id>/second", format = "json")]
pub fn party1_second_message(
    state: State<Config>,
    id: String
) -> Json<(party_one::KeyGenFirstMsg)>
{
    let db_key_gen_first_msg = db::get(&state.db, &id, "key_gen_first_msg");
    let key_gen_first_msg: party_one::KeyGenFirstMsg = match db_key_gen_first_msg {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    Json(key_gen_first_msg)
}