use reqwest;
use serde_json;
use time::PreciseTime;

use std::fs;
use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use kms::chain_code::two_party as chain_code;
use curv::cryptographic_primitives::twoparty::dh_key_exchange::*;

use super::super::utilities::requests;
use super::super::wallet;

const KG_PATH_PRE: &str = "ecdsa/keygen";

#[derive(Serialize, Deserialize)]
pub struct FourthMsgRequest {
    pub party_2_pdl_first_message: party_two::PDLFirstMessage,
    pub party_2_pdl_second_message: party_two::PDLSecondMessage
}

pub fn get_master_key(client: &reqwest::Client) -> wallet::PrivateShares {
    let start = PreciseTime::now();

    let res_body = requests::post(
        client, &format!("{}/first", KG_PATH_PRE)).unwrap();

    let (id, kg_party_one_first_message) :
        (String, party_one::KeyGenFirstMsg) = serde_json::from_str(&res_body).unwrap();

    println!("(id: {}) Generating master key...", id);

    let (kg_party_two_first_message, kg_ec_key_pair_party2) =
        MasterKey2::key_gen_first_message();

    let body = &kg_party_two_first_message.d_log_proof;

    let res_body = requests::postb(
        client, &format!("{}/{}/second", KG_PATH_PRE, id), body).unwrap();

    // TODO: second param not needed
    let (kg_party_one_second_message, _paillier_key_pair) :
        (party1::KeyGenParty1Message2, party_one::PaillierKeyPair) =
            serde_json::from_str(&res_body).unwrap();

    let key_gen_second_message = MasterKey2::key_gen_second_message(
        &kg_party_one_first_message,
        &kg_party_one_second_message
    );

    let (party_two_second_message, party_two_paillier, party_two_pdl_chal) =
        key_gen_second_message.unwrap();

    let body = &party_two_second_message.pdl_first_message;

    let res_body = requests::postb(
        client, &format!("{}/{}/third", KG_PATH_PRE, id), body).unwrap();

    let party_one_third_message : party_one::PDLFirstMessage = serde_json::from_str(&res_body).unwrap();

    let pdl_decom_party2 = MasterKey2::key_gen_third_message(&party_two_pdl_chal);

    let request : FourthMsgRequest = FourthMsgRequest {
        party_2_pdl_first_message: party_two_second_message.pdl_first_message,
        party_2_pdl_second_message: pdl_decom_party2
    };

    let body = &request;

    let res_body = requests::postb(
        client, &format!("{}/{}/fourth", KG_PATH_PRE, id), body).unwrap();

    let party_one_pdl_second_message : party_one::PDLSecondMessage = serde_json::from_str(&res_body).unwrap();

    MasterKey2::key_gen_fourth_message(
        &party_two_pdl_chal,
        &party_one_third_message,
        &party_one_pdl_second_message
    ).expect("pdl error party1");

    let res_body = requests::post(
        client, &format!("{}/{}/chaincode/first", KG_PATH_PRE, id)).unwrap();

    let cc_party_one_first_message : Party1FirstMessage = serde_json::from_str(&res_body).unwrap();

    let (cc_party_two_first_message, cc_ec_key_pair2) =
        chain_code::party2::ChainCode2::chain_code_first_message();

    let body = &cc_party_two_first_message.d_log_proof;

    let res_body = requests::postb(
        client, &format!("{}/{}/chaincode/second", KG_PATH_PRE, id), body).unwrap();

    let cc_party_one_second_message : Party1SecondMessage = serde_json::from_str(&res_body).unwrap();

    let cc_party_two_second_message = chain_code::party2::ChainCode2::chain_code_second_message(
        &cc_party_one_first_message,
        &cc_party_one_second_message);

    assert!(cc_party_two_second_message.is_ok());

    let body = &cc_party_two_first_message.public_share;

    let _res_body = requests::postb(
        client, &format!("{}/{}/chaincode/compute", KG_PATH_PRE, id), body).unwrap();

    let party2_cc = chain_code::party2::ChainCode2::compute_chain_code(
        &cc_ec_key_pair2,
        &cc_party_one_second_message.comm_witness.public_share,
    );

    let body = &kg_party_two_first_message.public_share;

    let _res_body = requests::postb(
        client, &format!("{}/{}/master_key", KG_PATH_PRE, id), body).unwrap();

    let masterKey = MasterKey2::set_master_key(
        &party2_cc.chain_code,
        &kg_ec_key_pair_party2,
        &kg_party_one_second_message
            .ecdh_second_message
            .comm_witness
            .public_share,
        &party_two_paillier,
    );

    println!("(id: {}) Master key gen completed", id);

    let end = PreciseTime::now();
    println!("(id: {}) Took: {}", id, start.to(end));

    wallet::PrivateShares { id, masterKey }
}