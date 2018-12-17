use reqwest;
use serde_json;

use curv::{BigInt};
use zk_paillier::zkproofs::*;
use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use kms::chain_code::two_party as chain_code;
use curv::cryptographic_primitives::twoparty::dh_key_exchange::*;
use curv::arithmetic::traits::Converter;

use super::super::utilities::requests;

const kg_path_pre : &str = "ecdsa/keygen";

pub fn get_master_key(client: &reqwest::Client, verbose: bool) {
    println!("Generating master key...");

    let res_body = requests::post(
        client, &format!("{}/first", kg_path_pre)).unwrap();

    let (id, kg_party_one_first_message) :
        (String, party_one::KeyGenFirstMsg) = serde_json::from_str(&res_body).unwrap();

    let (kg_party_two_first_message, kg_ec_key_pair_party2) =
        MasterKey2::key_gen_first_message();

    let body = &kg_party_two_first_message.d_log_proof;

    let res_body = requests::postb(
        client, &format!("{}/{}/second", kg_path_pre, id), body).unwrap();

}
