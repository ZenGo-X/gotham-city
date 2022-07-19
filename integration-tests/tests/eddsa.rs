use client_lib::*;
use rocket::Config;
use server_lib::server;
use std::collections::HashMap;
use std::{thread, time};
use rand::Rng;
use ed25519_dalek::{PublicKey, Signature, Verifier};

#[rocket::async_test]
async fn test_eddsa() {
    rocket::tokio::spawn(spawn_server(8002, "eddsa"));

    let client_shim = ClientShim::new("http://localhost:8002".to_string(), None);

    let two_seconds = time::Duration::from_millis(2000);
    thread::sleep(two_seconds);

    let (key_pair, key_agg, id) = client_lib::eddsa::generate_key(&client_shim).unwrap();

    let mut rng = rand::thread_rng();
    let mut msg = [0u8; 32];
    for _ in 0..2_000 {
        let msg_len = rng.gen::<u8>() as usize / 8;
        let msg = &mut msg[0..msg_len];
        rng.fill(msg);
        let signature = client_lib::eddsa::sign(&client_shim, msg, &key_pair, &key_agg, &id)
        .expect("EdDSA signature failed");
        let pubkey = PublicKey::from_bytes(&key_agg.aggregated_pubkey()).unwrap();
        let sig = Signature::from_bytes(&signature.serialize()).unwrap();
        pubkey.verify(msg, &sig).unwrap();
    }
}

async fn spawn_server(port: u32, db_name: &str) {
    let settings = HashMap::<String, String>::from([
        ("db".to_string(), "local".to_string()),
        ("db_name".to_string(), db_name.to_string()),
    ]);
    let rocket = server::get_server(settings);
    let figment = rocket.figment().clone().merge((Config::PORT, port));
    rocket.configure(figment).launch().await.unwrap();
}
