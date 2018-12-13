use kms::ecdsa::two_party::*;
use kms::chain_code::two_party as chain_code;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use zk_paillier::zkproofs::*;
use curv::cryptographic_primitives::proofs::dlog_zk_protocol::*;
use curv::cryptographic_primitives::twoparty::dh_key_exchange::*;
use curv::{BigInt, FE, GE};
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

    PDLProver,
    CCKeyGenFirstMsg,
    CCCommWitness,
    CCEcKeyPair,
    CC,

    MasterKey
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

#[post("/keygen/<id>/chaincode/first", format = "json")]
pub fn chain_code_first_message(
    state: State<Config>,
    id: String,
) -> Json<(
    Party1FirstMessage
)>
{
    let (cc_party_one_first_message, cc_comm_witness, cc_ec_key_pair1) =
        chain_code::party1::ChainCode1::chain_code_first_message();

    db::insert(&state.db, &id, &Share::CCKeyGenFirstMsg, &cc_party_one_first_message);
    db::insert(&state.db, &id, &Share::CCCommWitness, &cc_comm_witness);
    db::insert(&state.db, &id, &Share::CCEcKeyPair, &cc_ec_key_pair1);

    Json(cc_party_one_first_message)
}

#[post("/keygen/<id>/chaincode/second", format = "json", data = "<cc_party_two_first_message_d_log_proof>")]
pub fn chain_code_second_message(
    state: State<Config>,
    id: String,
    cc_party_two_first_message_d_log_proof: Json<DLogProof>
) -> Json<(
    Party1SecondMessage
)>
{
    let db_cc_comm_witness = db::get(&state.db, &id, &Share::CCCommWitness);
    let cc_comm_witness: CommWitness = match db_cc_comm_witness {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let party1_cc= chain_code::party1::ChainCode1::chain_code_second_message(
        cc_comm_witness,
        &cc_party_two_first_message_d_log_proof.0
    );

    Json(party1_cc)
}

#[post("/keygen/<id>/chaincode/compute", format = "json", data = "<cc_party_two_first_message_public_share>")]
pub fn chain_code_compute_message(
    state: State<Config>,
    id: String,
    cc_party_two_first_message_public_share: Json<GE>
) -> Json<(

)>
{
    let cc_ec_key_pair = db::get(&state.db, &id, &Share::CCEcKeyPair);
    let cc_ec_key_pair_party1:  EcKeyPair = match cc_ec_key_pair {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let party1_cc= chain_code::party1::ChainCode1::compute_chain_code(
        &cc_ec_key_pair_party1,
        &cc_party_two_first_message_public_share.0
    );

    db::insert(&state.db, &id, &Share::CC, &party1_cc);

    Json(())
}


#[post("/keygen/<id>/master_key", format = "json", data = "<kg_party_two_first_message_public_share>")]
pub fn master_key(
    state: State<Config>,
    id: String,
    kg_party_two_first_message_public_share: Json<GE>
) -> Json<(

)>
{
    let db_paillier_key_pair = db::get(&state.db, &id, &Share::PaillierKeyPair);
    let paillier_key_pair: party_one::PaillierKeyPair = match db_paillier_key_pair {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let db_party1_cc = db::get(&state.db, &id, &Share::CC);
    let party1_cc: chain_code::party1::ChainCode1 = match db_party1_cc {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let ec_key_pair = db::get(&state.db, &id, &Share::EcKeyPair);
    let kg_ec_key_pair_party1: party_one::EcKeyPair = match ec_key_pair {
        Some(v) => serde_json::from_str(v.to_utf8().unwrap()).unwrap(),
        None => panic!("No data for such identifier {}", id)
    };

    let masterKey = MasterKey1::set_master_key(
        &party1_cc.chain_code,
        &kg_ec_key_pair_party1,
        &kg_party_two_first_message_public_share.0,
        &paillier_key_pair,
    );

    db::insert(&state.db, &id, &Share::MasterKey, &masterKey);

    Json(())
}