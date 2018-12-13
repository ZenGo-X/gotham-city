use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use zk_paillier::zkproofs::*;
use curv::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use curv::BigInt;

use rocket::State;
use rocket_contrib::json::{Json};
use uuid::Uuid;
use rocksdb::DB;
use serde_json;
use std::string::ToString;

use super::super::utilities::db;

#[derive(ToString, Debug)]
pub enum Share {
    KeyGenFirstMsg,
    CommWitness,
    EcKeyPair,
    PaillierKeyPair,
    PDLProver
}

pub struct Config {
    pub db : DB
}

#[post("/keygen/first", format = "json")]
pub fn first_message(
    state: State<Config>
) -> Json<(
    String,
    party_one::KeyGenFirstMsg,
)> {
    let id = Uuid::new_v4().to_string();

    let (key_gen_first_msg, comm_witness, ec_key_pair) =
        MasterKey1::key_gen_first_message();

    db::insert(&state.db, &id, &Share::KeyGenFirstMsg, &key_gen_first_msg);
    db::insert(&state.db, &id, &Share::CommWitness, &comm_witness);
    db::insert(&state.db, &id, &Share::EcKeyPair, &ec_key_pair);

    Json((id, key_gen_first_msg))
}


#[post("/keygen/<id>/second", format = "json", data = "<d_log_proof>")]
pub fn second_message(
    state: State<Config>,
    id: String,
    d_log_proof: Json<DLogProof>
) -> Json<(
    party_one::KeyGenSecondMsg,
    party_one::PaillierKeyPair,
    RangeProofNi,
    NICorrectKeyProof
)>
{
    let db_comm_witness = db::get(&state.db, &id, &Share::CommWitness);
    let comm_witness: party_one::CommWitness = match db_comm_witness {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let ec_key_pair = db::get(&state.db, &id, &Share::EcKeyPair);
    let ec_key_pair: party_one::EcKeyPair = match ec_key_pair {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let (kg_party_one_second_message, paillier_key_pair, range_proof, correct_key_proof) =
        MasterKey1::key_gen_second_message(comm_witness, &ec_key_pair, &d_log_proof.0);

    db::insert(&state.db, &id, &Share::PaillierKeyPair, &paillier_key_pair);

    Json((kg_party_one_second_message, paillier_key_pair, range_proof, correct_key_proof))
}

#[post("/keygen/<id>/third", format = "json", data = "<pdl_chal_c_tag>")]
pub fn third_message(
    state: State<Config>,
    id: String,
    pdl_chal_c_tag: Json<BigInt>
) -> Json<(
    party_one::PDL
)>
{
    let db_paillier_key_pair = db::get(&state.db, &id, &Share::PaillierKeyPair);
    let paillier_key_pair: party_one::PaillierKeyPair = match db_paillier_key_pair {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let pdl_prover = MasterKey1::key_gen_third_message(&paillier_key_pair, &pdl_chal_c_tag.0);

    db::insert(&state.db, &id, &Share::PDLProver, &pdl_prover);

    Json(pdl_prover)
}

// Added here because the attribute data takes only a single struct
#[derive(Serialize, Deserialize)]
pub struct FourthMsgRequest {
    pub pdl_decom_party2: party_two::PDLdecommit,
    pub pdl_chal_c_tag_tag: BigInt
}

#[post("/keygen/<id>/fourth", format = "json", data = "<request>")]
pub fn fourth_message(
    state: State<Config>,
    id: String,
    request: Json<FourthMsgRequest>
) -> Json<(
    party_one::PDLdecommit
)>
{
    let db_pdl_prover = db::get(&state.db, &id, &Share::PDLProver);
    let pdl_prover: party_one::PDL = match db_pdl_prover {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let ec_key_pair = db::get(&state.db, &id, &Share::EcKeyPair);
    let ec_key_pair: party_one::EcKeyPair = match ec_key_pair {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let res = MasterKey1::key_gen_fourth_message(
        &pdl_prover,
        &request.pdl_chal_c_tag_tag,
        ec_key_pair,
        &request.pdl_decom_party2.a,
        &request.pdl_decom_party2.b,
        &request.pdl_decom_party2.blindness);

    assert!(res.is_ok());

    Json(res.unwrap())
}