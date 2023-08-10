use crate::keygen_bench::keygen;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use kms::ecdsa::two_party::MasterKey2;
use pprof::criterion::{Output, PProfProfiler};
use rand::rngs::mock::StepRng;
use rand::Rng;
use rocket::{http::ContentType, http::Status, local::blocking::Client};
use std::collections::HashMap;
use two_party_ecdsa::{party_one, BigInt};
mod keygen_bench;
use server_lib::routes::ecdsa::SignSecondMsgRequest;
use server_lib::*;

pub fn sign(
    client: &Client,
    message: &BigInt,
    mk: &MasterKey2,
    x_pos: &BigInt,
    y_pos: &BigInt,
    id: &str,
) -> party_one::SignatureRecid {
    let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
        MasterKey2::sign_first_message();

    let body = serde_json::to_string(&eph_key_gen_first_message_party_two).unwrap();

    let response = client
        .post(format!("/ecdsa/sign/{}/first", id))
        .header(ContentType::JSON)
        .body(body)
        .dispatch();

    assert_eq!(response.status(), Status::Ok);

    let sign_party_one_first_message: party_one::EphKeyGenFirstMsg =
        serde_json::from_str(&response.into_string().unwrap()).unwrap();

    let child_party_two_master_key = mk.get_child(vec![x_pos.clone(), y_pos.clone()]);

    let party_two_sign_message = child_party_two_master_key.sign_second_message(
        &eph_ec_key_pair_party2,
        eph_comm_witness,
        &sign_party_one_first_message,
        &message,
    );

    let request: SignSecondMsgRequest = SignSecondMsgRequest {
        message: message.clone(),
        party_two_sign_message,
        x_pos_child_key: x_pos.clone(),
        y_pos_child_key: y_pos.clone(),
    };

    let body = serde_json::to_string(&request).unwrap();

    let response = client
        .post(format!("/ecdsa/sign/{}/second", id))
        .header(ContentType::JSON)
        .body(body)
        .dispatch();

    assert_eq!(response.status(), Status::Ok);

    let signature: party_one::SignatureRecid =
        serde_json::from_str(&response.into_string().unwrap()).unwrap();

    signature
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let settings = HashMap::<String, String>::from([
        ("db".to_string(), "local".to_string()),
        ("db_name".to_string(), "KeyGenAndSign".to_string()),
    ]);

    let server = server::get_server(settings);
    let client = Client::tracked(server).expect("valid rocket instance");

    let (id, mk) = keygen(&client);

    c.bench_with_input(
        BenchmarkId::new("sign_benchmark", 1),
        &(client, id, mk),
        |b, (client, id, mk)| {
            b.iter(|| {
                let x_pos = BigInt::from(1);
                let y_pos = BigInt::from(2);
                let mut rng = StepRng::new(0, 1);
                let mut msg_buf = [0u8; 32];
                rng.fill(&mut msg_buf);
                let msg: BigInt = BigInt::from(&msg_buf[..]);

                sign(&client, &msg, mk, &x_pos, &y_pos, id);
            });
        },
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(10, Output::Flamegraph(None)));
    targets = criterion_benchmark
}

criterion_main!(benches);
