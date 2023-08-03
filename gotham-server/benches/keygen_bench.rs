use std::collections::HashMap;
use std::time::Instant;
use time_test::time_test;
use rocket::{http::ContentType, http::{Status}, local::blocking::Client};
use two_party_ecdsa::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::*;
use two_party_ecdsa::{party_one};
use floating_duration::TimeFormat;
use kms::chain_code::two_party as chain_code;
use kms::ecdsa::two_party::{MasterKey2, party1};
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use pprof::criterion::{Output, PProfProfiler};
use server_lib::*;

pub fn keygen(client: &Client) -> (String, MasterKey2) {

    /*************** START: FIRST MESSAGE ***************/

    let response = client
        .post("/ecdsa/keygen/first")
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let res_body = response.into_string().unwrap();

    let (id, kg_party_one_first_message): (String, party_one::KeyGenFirstMsg) =
        serde_json::from_str(&res_body).unwrap();


    let (kg_party_two_first_message, kg_ec_key_pair_party2) = MasterKey2::key_gen_first_message();

    /*************** END: FIRST MESSAGE ***************/

    /*************** START: SECOND MESSAGE ***************/
    let body = serde_json::to_string(&kg_party_two_first_message.d_log_proof).unwrap();


    let response = client
        .post(format!("/ecdsa/keygen/{}/second", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let res_body = response.into_string().unwrap();
    let kg_party_one_second_message: party1::KeyGenParty1Message2 =
        serde_json::from_str(&res_body).unwrap();


    let key_gen_second_message = MasterKey2::key_gen_second_message(
        &kg_party_one_first_message,
        &kg_party_one_second_message,
    );
    assert!(key_gen_second_message.is_ok());

    let (party_two_second_message, party_two_paillier, party_two_pdl_chal) =
        key_gen_second_message.unwrap();

    /*************** END: SECOND MESSAGE ***************/

    /*************** START: THIRD MESSAGE ***************/
    let body = serde_json::to_string(&party_two_second_message.pdl_first_message).unwrap();


    let response = client
        .post(format!("/ecdsa/keygen/{}/third", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);

    let res_body = response.into_string().unwrap();
    let party_one_third_message: party_one::PDLFirstMessage =
        serde_json::from_str(&res_body).unwrap();


    let pdl_decom_party2 = MasterKey2::key_gen_third_message(&party_two_pdl_chal);

    /*************** END: THIRD MESSAGE ***************/

    /*************** START: FOURTH MESSAGE ***************/

    let party_2_pdl_second_message = pdl_decom_party2;
    let request = party_2_pdl_second_message;
    let body = serde_json::to_string(&request).unwrap();


    let response = client
        .post(format!("/ecdsa/keygen/{}/fourth", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);


    let res_body = response.into_string().unwrap();
    let party_one_pdl_second_message: party_one::PDLSecondMessage =
        serde_json::from_str(&res_body).unwrap();


    MasterKey2::key_gen_fourth_message(
        &party_two_pdl_chal,
        &party_one_third_message,
        &party_one_pdl_second_message,
    )
    .expect("pdl error party1");

    /*************** END: FOURTH MESSAGE ***************/

    /*************** START: CHAINCODE FIRST MESSAGE ***************/

    let response = client
        .post(format!("/ecdsa/keygen/{}/chaincode/first", id))
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);


    let res_body = response.into_string().unwrap();
    let cc_party_one_first_message: Party1FirstMessage = serde_json::from_str(&res_body).unwrap();

    let (cc_party_two_first_message, cc_ec_key_pair2) =
        chain_code::party2::ChainCode2::chain_code_first_message();

    /*************** END: CHAINCODE FIRST MESSAGE ***************/

    /*************** START: CHAINCODE SECOND MESSAGE ***************/
    let body = serde_json::to_string(&cc_party_two_first_message.d_log_proof).unwrap();

    let response = client
        .post(format!("/ecdsa/keygen/{}/chaincode/second", id))
        .body(body)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);


    let res_body = response.into_string().unwrap();
    let cc_party_one_second_message: Party1SecondMessage = serde_json::from_str(&res_body).unwrap();

    let _cc_party_two_second_message = chain_code::party2::ChainCode2::chain_code_second_message(
        &cc_party_one_first_message,
        &cc_party_one_second_message,
    );

    /*************** END: CHAINCODE SECOND MESSAGE ***************/

    let party2_cc = chain_code::party2::ChainCode2::compute_chain_code(
        &cc_ec_key_pair2,
        &cc_party_one_second_message.comm_witness.public_share,
    )
    .chain_code;

    /*************** END: CHAINCODE COMPUTE MESSAGE ***************/


    let party_two_master_key = MasterKey2::set_master_key(
        &party2_cc,
        &kg_ec_key_pair_party2,
        &kg_party_one_second_message
            .ecdh_second_message
            .comm_witness
            .public_share,
        &party_two_paillier,
    );

    /*************** END: MASTER KEYS MESSAGE ***************/

    (id, party_two_master_key)
}

/// Benchmarks keygen phase from client side invoking gotham server endpoints
pub fn criterion_benchmark(c: &mut Criterion) {
    let settings = HashMap::<String, String>::from([
        ("db".to_string(), "local".to_string()),
        ("db_name".to_string(), "KeyGenAndSign".to_string()),
    ]);
    let server = server::get_server(settings);
    let client = Client::tracked(server).expect("valid rocket instance");

    c.bench_with_input(
        BenchmarkId::new("keygen_benchmark", 1),
        &client,
        |b, client| {
            b.iter(|| {
                let (_, _): (String, MasterKey2) = keygen(&client);
            })
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(10, Output::Flamegraph(None)));
    targets = criterion_benchmark
}
criterion_main!(benches);
