#[cfg(test)]
use time::PreciseTime;

use rocket;
use rocket::local::Client;
use rocket::http::Status;
use rocket::http::ContentType;
use serde_json;
use super::server;
use super::routes::keygen;

use zk_paillier::zkproofs::*;
use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;

#[test]
fn key_gen() {
    time_test!();

    let client = Client::new(server::get_server())
        .expect("valid rocket instance");

    /*************** START: FIRST MESSAGE ***************/
    let start = PreciseTime::now();

    let mut response = client
        .post("/keygen/first")
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let end = PreciseTime::now();
    println!("{} Network/Server: party1 first message", start.to(end));

    let res_body = response.body_string().unwrap();
    let (id, kg_party_one_first_message) :
        (String, party_one::KeyGenFirstMsg) = serde_json::from_str(&res_body).unwrap();

    let start = PreciseTime::now();

    let (kg_party_two_first_message, _kg_ec_key_pair_party2) =
        MasterKey2::key_gen_first_message();

    let end = PreciseTime::now();
    println!("{} Client: party2 first message", start.to(end));
    /*************** END: FIRST MESSAGE ***************/

    /*************** START: SECOND MESSAGE ***************/
    let body =
        serde_json::to_string(&kg_party_two_first_message.d_log_proof).unwrap();

    let start = PreciseTime::now();

    let mut response = client
        .post(format!("/keygen/{}/second", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let end = PreciseTime::now();
    println!("{} Network/Server: party1 second message", start.to(end));

    let res_body = response.body_string().unwrap();
    let (kg_party_one_second_message, paillier_key_pair, range_proof, correct_key_proof) :
        (party_one::KeyGenSecondMsg,
         party_one::PaillierKeyPair,
         RangeProofNi,
         NICorrectKeyProof) = serde_json::from_str(&res_body).unwrap();

    let start = PreciseTime::now();

    let key_gen_second_message = MasterKey2::key_gen_second_message(
        &kg_party_one_first_message,
        &kg_party_one_second_message,
        &paillier_key_pair.ek,
        &paillier_key_pair.encrypted_share,
        &range_proof,
        &correct_key_proof,
    );
    assert!(key_gen_second_message.is_ok());

    let end = PreciseTime::now();
    println!("{} Client: party2 second message", start.to(end));

    let (party_two_second_message, _party_two_paillier, pdl_chal) =
        key_gen_second_message.unwrap();
    assert!(party_two_second_message.is_ok());

    /*************** END: SECOND MESSAGE ***************/

    /*************** START: THIRD MESSAGE ***************/
    let body =
        serde_json::to_string(&pdl_chal.c_tag).unwrap();

    let start = PreciseTime::now();

    let mut response = client
        .post(format!("/keygen/{}/third", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let end = PreciseTime::now();
    println!("{} Network/Server: party1 third message", start.to(end));

    let res_body = response.body_string().unwrap();
    let pdl_prover : party_one::PDL = serde_json::from_str(&res_body).unwrap();

    let start = PreciseTime::now();

    let pdl_decom_party2 = MasterKey2::key_gen_third_message(&pdl_chal);

    let end = PreciseTime::now();
    println!("{} Client: party2 third message", start.to(end));
    /*************** END: THIRD MESSAGE ***************/

    /*************** START: FOURTH MESSAGE ***************/
    let request : keygen::FourthMsgRequest = keygen::FourthMsgRequest {
        pdl_decom_party2,
        pdl_chal_c_tag_tag: pdl_chal.c_tag_tag.to_owned()
    };

    let body =
        serde_json::to_string(&request).unwrap();

    let start = PreciseTime::now();

    let mut response = client
        .post(format!("/keygen/{}/fourth", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let end = PreciseTime::now();
    println!("{} Network/Server: party1 fourth message", start.to(end));

    let res_body = response.body_string().unwrap();
    let pdl_decom_party1 : party_one::PDLdecommit = serde_json::from_str(&res_body).unwrap();

    let start = PreciseTime::now();

    MasterKey2::key_gen_fourth_message(
        &pdl_chal,
        &pdl_decom_party1.blindness,
        &pdl_decom_party1.q_hat,
        &pdl_prover.c_hat,
    ).expect("pdl error party1");

    let end = PreciseTime::now();
    println!("{} Client: party2 fourth message", start.to(end));

    /*************** END: FOURTH MESSAGE ***************/
}