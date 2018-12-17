use time::PreciseTime;
use rocket;
use rocket::local::Client;
use rocket::http::Status;
use rocket::http::ContentType;
use serde_json;
use super::server;
use super::routes::ecdsa;

use curv::{BigInt};
use zk_paillier::zkproofs::*;
use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use kms::chain_code::two_party as chain_code;
use curv::cryptographic_primitives::twoparty::dh_key_exchange::*;
use curv::arithmetic::traits::Converter;

fn key_gen(client: &Client) -> (String, MasterKey2) {
    time_test!();

    /*************** START: FIRST MESSAGE ***************/
    let start = PreciseTime::now();

    let mut response = client
        .post("/ecdsa/keygen/first")
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let end = PreciseTime::now();
    println!("{} Network/Server: party1 first message", start.to(end));

    let res_body = response.body_string().unwrap();
    let (id, kg_party_one_first_message) :
    (String, party_one::KeyGenFirstMsg) = serde_json::from_str(&res_body).unwrap();

    let start = PreciseTime::now();

    let (kg_party_two_first_message, kg_ec_key_pair_party2) =
        MasterKey2::key_gen_first_message();

    let end = PreciseTime::now();
    println!("{} Client: party2 first message", start.to(end));
    /*************** END: FIRST MESSAGE ***************/

    /*************** START: SECOND MESSAGE ***************/
    let body =
        serde_json::to_string(&kg_party_two_first_message.d_log_proof).unwrap();

    let start = PreciseTime::now();

    let mut response = client
        .post(format!("/ecdsa/keygen/{}/second", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let end = PreciseTime::now();
    println!("{} Network/Server: party1 second message", start.to(end));

    let res_body = response.body_string().unwrap();
    let (kg_party_one_second_message, paillier_key_pair) :
        (party1::KeyGenParty1Message2, party_one::PaillierKeyPair) =
        serde_json::from_str(&res_body).unwrap();

    let start = PreciseTime::now();

    let key_gen_second_message = MasterKey2::key_gen_second_message(
        &kg_party_one_first_message,
        &kg_party_one_second_message
    );
    assert!(key_gen_second_message.is_ok());

    let end = PreciseTime::now();
    println!("{} Client: party2 second message", start.to(end));

    let (party_two_second_message, party_two_paillier, party_two_pdl_chal) =
        key_gen_second_message.unwrap();
    /*************** END: SECOND MESSAGE ***************/

    /*************** START: THIRD MESSAGE ***************/
    let body =
        serde_json::to_string(&party_two_second_message.pdl_first_message).unwrap();

    let start = PreciseTime::now();

    let mut response = client
        .post(format!("/ecdsa/keygen/{}/third", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let end = PreciseTime::now();
    println!("{} Network/Server: party1 third message", start.to(end));

    let res_body = response.body_string().unwrap();
    let party_one_third_message : party_one::PDLFirstMessage = serde_json::from_str(&res_body).unwrap();

    let start = PreciseTime::now();

    let pdl_decom_party2 = MasterKey2::key_gen_third_message(&party_two_pdl_chal);

    let end = PreciseTime::now();
    println!("{} Client: party2 third message", start.to(end));
    /*************** END: THIRD MESSAGE ***************/

    /*************** START: FOURTH MESSAGE ***************/
    let request : ecdsa::FourthMsgRequest = ecdsa::FourthMsgRequest {
        party_2_pdl_first_message: party_two_second_message.pdl_first_message,
        party_2_pdl_second_message: pdl_decom_party2
    };

    let body =
        serde_json::to_string(&request).unwrap();

    let start = PreciseTime::now();

    let mut response = client
        .post(format!("/ecdsa/keygen/{}/fourth", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let end = PreciseTime::now();
    println!("{} Network/Server: party1 fourth message", start.to(end));

    let res_body = response.body_string().unwrap();
    let party_one_pdl_second_message : party_one::PDLSecondMessage = serde_json::from_str(&res_body).unwrap();

    let start = PreciseTime::now();

    MasterKey2::key_gen_fourth_message(
        &party_two_pdl_chal,
        &party_one_third_message,
        &party_one_pdl_second_message
    ).expect("pdl error party1");

    let end = PreciseTime::now();
    println!("{} Client: party2 fourth message", start.to(end));
    /*************** END: FOURTH MESSAGE ***************/

    /*************** START: CHAINCODE FIRST MESSAGE ***************/
    let start = PreciseTime::now();

    let mut response = client
        .post(format!("/ecdsa/keygen/{}/chaincode/first", id))
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let end = PreciseTime::now();
    println!("{} Network/Server: party1 chain code first message", start.to(end));

    let res_body = response.body_string().unwrap();
    let cc_party_one_first_message : Party1FirstMessage = serde_json::from_str(&res_body).unwrap();

    let start = PreciseTime::now();
    let (cc_party_two_first_message, cc_ec_key_pair2) =
        chain_code::party2::ChainCode2::chain_code_first_message();
    let end = PreciseTime::now();
    println!("{} Client: party2 chain code first message", start.to(end));
    /*************** END: CHAINCODE FIRST MESSAGE ***************/

    /*************** START: CHAINCODE SECOND MESSAGE ***************/
    let body =
        serde_json::to_string(&cc_party_two_first_message.d_log_proof).unwrap();

    let start = PreciseTime::now();

    let mut response = client
        .post(format!("/ecdsa/keygen/{}/chaincode/second", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let end = PreciseTime::now();
    println!("{} Network/Server: party1 chain code second message", start.to(end));

    let res_body = response.body_string().unwrap();
    let cc_party_one_second_message : Party1SecondMessage = serde_json::from_str(&res_body).unwrap();

    let start = PreciseTime::now();
    let cc_party_two_second_message = chain_code::party2::ChainCode2::chain_code_second_message(
        &cc_party_one_first_message,
        &cc_party_one_second_message);

    let end = PreciseTime::now();
    println!("{} Client: party2 chain code second message", start.to(end));
    /*************** END: CHAINCODE SECOND MESSAGE ***************/

    /*************** START: CHAINCODE COMPUTE MESSAGE ***************/
    let body =
        serde_json::to_string(&cc_party_two_first_message.public_share).unwrap();

    let start = PreciseTime::now();

    let mut response = client
        .post(format!("/ecdsa/keygen/{}/chaincode/compute", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let end = PreciseTime::now();
    println!("{} Network/Server: party1 chain code compute message", start.to(end));

    let start = PreciseTime::now();
    let party2_cc = chain_code::party2::ChainCode2::compute_chain_code(
        &cc_ec_key_pair2,
        &cc_party_one_second_message.comm_witness.public_share,
    );

    let end = PreciseTime::now();
    println!("{} Client: party2 chain code second message", start.to(end));
    /*************** END: CHAINCODE COMPUTE MESSAGE ***************/

    /*************** START: MASTER KEYS MESSAGE ***************/
    let body =
        serde_json::to_string(&kg_party_two_first_message.public_share).unwrap();

    let start = PreciseTime::now();

    let mut response = client
        .post(format!("/ecdsa/keygen/{}/master_key", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let end = PreciseTime::now();
    println!("{} Network/Server: party1 master key", start.to(end));

    let start = PreciseTime::now();
    let party_two_master_key = MasterKey2::set_master_key(
        &party2_cc.chain_code,
        &kg_ec_key_pair_party2,
        &kg_party_one_second_message
            .ecdh_second_message
            .comm_witness
            .public_share,
        &party_two_paillier,
    );

    let end = PreciseTime::now();
    println!("{} Client: party2 master_key", start.to(end));
    /*************** END: MASTER KEYS MESSAGE ***************/

    (id, party_two_master_key)
}

pub fn sign(client: &Client, id: String, master_key_2: MasterKey2, message: BigInt) -> party_one::Signature {
    time_test!();

    let start = PreciseTime::now();

    let mut response = client
        .post(format!("/ecdsa/sign/{}/first", id))
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let end = PreciseTime::now();
    println!("{} Network/Server: party1 sign first message", start.to(end));

    let res_body = response.body_string().unwrap();
    let sign_party_one_first_message : party_one::EphKeyGenFirstMsg = serde_json::from_str(&res_body).unwrap();

    let start = PreciseTime::now();
    let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
        MasterKey2::sign_first_message();

    let end = PreciseTime::now();
    println!("{} Client: party2 sign first message", start.to(end));

    let start = PreciseTime::now();
    let party_two_sign_message = master_key_2.sign_second_message(
        &eph_ec_key_pair_party2,
        eph_comm_witness.clone(),
        &sign_party_one_first_message,
        &message,
    );

    let end = PreciseTime::now();
    println!("{} Client: party2 sign second message", start.to(end));

    let request : ecdsa::SignSecondMsgRequest = ecdsa::SignSecondMsgRequest {
        message,
        party_two_sign_message,
        eph_key_gen_first_message_party_two
    };

    let body =
        serde_json::to_string(&request).unwrap();

    let start = PreciseTime::now();

    let mut response = client
        .post(format!("/ecdsa/sign/{}/second", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let end = PreciseTime::now();
    println!("{} Network/Server: party1 sign second message", start.to(end));

    let res_body = response.body_string().unwrap();
    let signatures : party_one::Signature = serde_json::from_str(&res_body).unwrap();

    signatures
}

#[test]
fn key_gen_and_sign() {
    time_test!();

    let client = Client::new(server::get_server())
        .expect("valid rocket instance");

    let (id, master_key_2) : (String, MasterKey2) = key_gen(&client);

    let message = BigInt::from(1234);

    let signatures : party_one::Signature = sign(&client, id, master_key_2, message);

    println!("s = (r: {}, s: {})", signatures.r.to_hex(), signatures.s.to_hex());
}