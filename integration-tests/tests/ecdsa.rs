use client_lib::{ecdsa, ClientShim};
use rand::rngs::mock::StepRng;
use rand::{Rng, thread_rng};
use rocket::http::Header;
use rocket::serde::{DeserializeOwned, Serialize};
use rocket::{Config, Ignite, Rocket};
use secp256k1::{ecdsa::Signature, Message, SECP256K1};
use server_lib::server;
use std::collections::HashMap;
use two_party_ecdsa::curv::arithmetic::big_gmp::BigInt;
use two_party_ecdsa::curv::arithmetic::traits::Converter;
use two_party_ecdsa::curv::elliptic::curves::traits::ECPoint;
use two_party_ecdsa::curv::PK;
use two_party_ecdsa::kms::ecdsa::two_party::MasterKey2;
use client_lib::ecdsa::PrivateShare;

#[test]
fn test_ecdsa_keygen() {
    let settings = HashMap::<String, String>::from([
        ("db".into(), "local".into()),
        ("db_name".into(), "IntegrationTestKeygen".into()),
    ]);

    let rocket = server::get_server(settings);
    let client = RocketClient::new(rocket);

    let client_shim =
        ClientShim::new_with_client("http://localhost:8009".to_string(), None, client);
    for _ in 0..10 {
        let ps: PrivateShare = ecdsa::get_master_key(&client_shim);
        let _ = ps.master_key.public.q.get_element();
    }
}

#[test]
fn integration_test_ecdsa_keygen_sign_rotate() {
    let mut rng = StepRng::new(0, 1);
    let settings = HashMap::<String, String>::from([
        ("db".into(), "local".into()),
        ("db_name".into(), "IntegrationTestKeygenSignRotate".into()),
    ]);


    let rocket = server::get_server(settings);
    let client = RocketClient::new(rocket);

    let client_shim =
        ClientShim::new_with_client("http://localhost:8008".to_string(), None, client);


    let mut private_share: ecdsa::PrivateShare = ecdsa::get_master_key(&client_shim);

    let mut derivation_path = Vec::new();

    for _ in 0..10 {
        derivation_path.push(BigInt::from(thread_rng().gen_range(0..100)));

        let child_master_key = private_share.master_key.get_child(derivation_path.clone());
        let public_key = child_master_key.public.q.get_element();

        sign_and_verify(&client_shim,
                        &child_master_key,
                        &private_share.id,
                        &public_key,
                        derivation_path.clone());

        private_share = ecdsa::rotate_master_key(&client_shim, &private_share.master_key, private_share.id.as_str());
    }
}

fn sign_and_verify(client_shim: &ClientShim<RocketClient>,
                   child_master_key: &MasterKey2,
                   id: &str,
                   pk: &PK,
                   derivation_path: Vec<BigInt>) {
    let mut msg_buf = [0u8; 32];
    thread_rng().fill(&mut msg_buf);
    let msg: BigInt = BigInt::from(&msg_buf[..]);

    println!("Message: {}", msg);

    let signature = ecdsa::sign(
        &client_shim,
        msg,
        &child_master_key,
        derivation_path,
        &id,
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

    println!("ECDSA signature verified: (r: {}, s: {}, recid: {})",
             signature.r.to_hex(),
             signature.s.to_hex(),
             signature.recid);
}

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
        let x_customer_header = Header::new("x-customer-id", "x-customer-id");
        self.0
            .post(["/", uri].concat())
            .header(x_customer_header.clone())
            .json(&body)
            .dispatch()
            .into_string()
            .map(|s| serde_json::from_str(&s).ok())
            .flatten()
    }
}
