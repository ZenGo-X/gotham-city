use client_lib::{ecdsa, ClientShim};
use rand::rngs::mock::StepRng;
use rand::Rng;
use rocket::serde::{DeserializeOwned, Serialize};
use rocket::{Config, Ignite, Rocket};
use secp256k1::{ecdsa::Signature, Message, SECP256K1};
use server_lib::server;
use std::collections::HashMap;
use std::{thread, time};
use two_party_ecdsa::curv::arithmetic::big_gmp::BigInt;
use two_party_ecdsa::curv::arithmetic::traits::Converter;
use two_party_ecdsa::curv::elliptic::curves::traits::ECPoint;

// #[rocket::async_test]
// async fn test_ecdsa_network() {
//     let mut rng = StepRng::new(0, 1);
//     rocket::tokio::spawn(spawn_server(8000, "ecdsa"));
//
//     let client_shim = ClientShim::new("http://localhost:8000".to_string(), None);
//
//     let two_seconds = time::Duration::from_millis(2000);
//     thread::sleep(two_seconds);
//
//     let ps: ecdsa::PrivateShare = ecdsa::get_master_key(&client_shim);
//
//     for y in 0..50i32 {
//         let x_pos = BigInt::from(y * 2 + 1);
//         let y_pos = BigInt::from(y);
//
//         let child_master_key = ps.master_key.get_child(vec![x_pos.clone(), y_pos.clone()]);
//         let pk = child_master_key.public.q.get_element();
//
//         let mut msg_buf = [0u8; 32];
//         rng.fill(&mut msg_buf);
//         let msg: BigInt = BigInt::from(&msg_buf[..]);
//
//         let signature = ecdsa::sign(
//             &client_shim,
//             msg.clone(),
//             &child_master_key,
//             x_pos,
//             y_pos,
//             &ps.id,
//         )
//         .expect("ECDSA signature failed");
//
//         let r = BigInt::to_vec(&signature.r);
//         let s = BigInt::to_vec(&signature.s);
//         let msg = Message::from_slice(&msg_buf).unwrap();
//
//         let mut sig = [0u8; 64];
//         sig[32 - r.len()..32].copy_from_slice(&r);
//         sig[32 + 32 - s.len()..].copy_from_slice(&s);
//
//         let sig = Signature::from_compact(&sig).unwrap();
//
//         SECP256K1.verify_ecdsa(&msg, &sig, &pk).unwrap();
//     }
// }

// async fn spawn_server(port: u32, db_name: &str) -> Rocket<Ignite> {
//     let settings = HashMap::<String, String>::from([
//         ("db".to_string(), "local".to_string()),
//         ("db_name".to_string(), db_name.to_string()),
//     ]);
//     let rocket = server::get_server(settings);
//     let figment = rocket.figment().clone().merge((Config::PORT, port));
//     rocket.configure(figment).launch().await.unwrap()
// }

// #[test]
// fn test_ecdsa_keygen() {
//     let settings = HashMap::<String, String>::from([
//         ("db".into(), "local".into()),
//         ("db_name".into(), "testEcdsaKeygen".into()),
//     ]);
//     let rocket = server::get_server(settings);
//     let client = RocketClient::new(rocket);
//
//     let client_shim =
//         ClientShim::new_with_client("http://localhost:8009".to_string(), None, client);
//     for _ in 0..10 {
//         let ps: ecdsa::PrivateShare = ecdsa::get_master_key(&client_shim);
//         let _ = ps.master_key.public.q.get_element();
//     }
// }

// #[test]
// fn test_ecdsa_key_derivation() {
//     let settings = HashMap::<String, String>::from([
//         ("db".into(), "local".into()),
//         ("db_name".into(), "testEcdsaDerivation".into()),
//     ]);
//     let rocket = server::get_server(settings);
//     let client = RocketClient::new(rocket);
//
//     let client_shim =
//         ClientShim::new_with_client("http://localhost:8009".to_string(), None, client);
//     let ps: ecdsa::PrivateShare = ecdsa::get_master_key(&client_shim);
//     for y in 0..1 {
//         let x_pos = BigInt::from(y * 2 + 1);
//         let y_pos = BigInt::from(y);
//         let child_master_key = ps.master_key.get_child(vec![x_pos.clone(), y_pos.clone()]);
//         let _ = child_master_key.public.q.get_element();
//     }
// }

#[test]
// #[rocket::async_test]
fn integration_test_ecdsa_key_signing() {
    let mut rng = StepRng::new(0, 1);
    let settings = HashMap::<String, String>::from([
        ("db_name".into(), "testEcdsaSigning".into()),
    ]);
    let rocket = server::get_server(settings);
    let client = RocketClient::new(rocket);

    let client_shim =
        ClientShim::new_with_client("http://localhost:8008".to_string(), None, client);
    let ps: ecdsa::PrivateShare = ecdsa::get_master_key(&client_shim);
    let x_pos = BigInt::from(1);
    let y_pos = BigInt::from(2);

    let child_master_key = ps.master_key.get_child(vec![x_pos.clone(), y_pos.clone()]);
    let pk = child_master_key.public.q.get_element();

    for _ in 0..10 {
        let mut msg_buf = [0u8; 32];
        rng.fill(&mut msg_buf);
        let msg: BigInt = BigInt::from(&msg_buf[..]);

        let signature = ecdsa::sign(
            &client_shim,
            msg,
            &child_master_key,
            x_pos.clone(),
            y_pos.clone(),
            &ps.id,
        )
        .expect("ECDSA signature failed");

        let r = BigInt::to_vec(&signature.r);
        let s = BigInt::to_vec(&signature.s);
        let msg = Message::from_slice(&msg_buf).unwrap();

        let mut sig = [0u8; 64];
        sig[32 - r.len()..32].copy_from_slice(&r);
        sig[32 + 32 - s.len()..].copy_from_slice(&s);

        let sig = Signature::from_compact(&sig).unwrap();

        SECP256K1.verify_ecdsa(&msg, &sig, &pk).unwrap();
    }
}

// #[test]
// fn integration_test_ecdsa_long() {
//     let mut rng = StepRng::new(0, 1);
//     let settings = HashMap::<String, String>::from([
//         ("db_name".into(), "testEcdsaLong".into()),
//     ]);
//     let rocket = server::get_server(settings);
//     let client = RocketClient::new(rocket);
//
//     let client_shim =
//         ClientShim::new_with_client("http://localhost:8009".to_string(), None, client);
//
//     let ps: ecdsa::PrivateShare = ecdsa::get_master_key(&client_shim);
//
//     for y in 0..1 {
//         let x_pos = BigInt::from(y * 2 + 1);
//         let y_pos = BigInt::from(y);
//
//         let child_master_key = ps.master_key.get_child(vec![x_pos.clone(), y_pos.clone()]);
//         let pk = child_master_key.public.q.get_element();
//
//         let mut msg_buf = [0u8; 32];
//         rng.fill(&mut msg_buf);
//         let msg: BigInt = BigInt::from(&msg_buf[..]);
//
//         let signature = ecdsa::sign(&client_shim, msg, &child_master_key, x_pos, y_pos, &ps.id)
//             .expect("ECDSA signature failed");
//
//         let r = BigInt::to_vec(&signature.r);
//         let s = BigInt::to_vec(&signature.s);
//         let msg = Message::from_slice(&msg_buf).unwrap();
//
//         let mut sig = [0u8; 64];
//         sig[32 - r.len()..32].copy_from_slice(&r);
//         sig[32 + 32 - s.len()..].copy_from_slice(&s);
//
//         let sig = Signature::from_compact(&sig).unwrap();
//
//         SECP256K1.verify_ecdsa(&msg, &sig, &pk).unwrap();
//     }
// }

struct RocketClient(pub rocket::local::blocking::Client);

impl RocketClient {
    fn new<P: rocket::Phase>(rocket: Rocket<P>) -> Self {
        Self(rocket::local::blocking::Client::untracked(rocket).unwrap())
    }
}

impl client_lib::Client for RocketClient {
    fn post<V: DeserializeOwned, T: Serialize>(
        &self,
        _: &str,
        uri: &str,
        _: Option<String>,
        body: T,
    ) -> Option<V> {
        self.0
            .post(["/", uri].concat())
            .json(&body)
            .dispatch()
            .into_string()
            .map(|s| serde_json::from_str(&s).ok())
            .flatten()
    }
}
