#[cfg(test)]
mod tests {
    extern crate client_lib;
    extern crate server_lib;
    extern crate two_party_ecdsa;
    extern crate secp256k1;
    extern crate ed25519_dalek;

    use client_lib::*;
    use rocket::Config;
    use server_lib::server;
    use std::collections::HashMap;
    use std::{thread, time};
    use two_party_ecdsa::curv::elliptic::curves::traits::ECPoint;
    use two_party_ecdsa::curv::arithmetic::traits::{Samplable, Converter};

    #[rocket::async_test]
    async fn test_ecdsa() {
        use secp256k1::{Secp256k1, Signature, Message};

        rocket::tokio::spawn(spawn_server(8000, "ecdsa"));

        let client_shim = ClientShim::new("http://localhost:8000".to_string(), None);

        let two_seconds = time::Duration::from_millis(2000);
        thread::sleep(two_seconds);

        let ps: ecdsa::PrivateShare = ecdsa::get_master_key(&client_shim);
        let ctx = Secp256k1::verification_only();

        for y in 0..10i32 {
            let x_pos = BigInt::from(y*2+1);
            let y_pos = BigInt::from(y);
            println!("Deriving child_master_key at [x: {}, y:{}]", x_pos, y_pos);

            let child_master_key = ps.master_key.get_child(vec![x_pos.clone(), y_pos.clone()]);
            let pk = child_master_key.public.q.get_element();


            let msg: BigInt = BigInt::sample(256); // arbitrary message
            let signature = ecdsa::sign(&client_shim, msg.clone(), &child_master_key, x_pos, y_pos, &ps.id)
                .expect("ECDSA signature failed");

            let msg_int = BigInt::to_vec(&msg);
            let r = BigInt::to_vec(&signature.r);
            let s = BigInt::to_vec(&signature.s);
            let mut msg = [0u8; 32];
            msg[32-msg_int.len()..].copy_from_slice(&msg_int);
            let msg = Message::from_slice(&msg).unwrap();

            let mut sig = [0u8; 64];
            sig[32-r.len()..32].copy_from_slice(&r);
            sig[32+32-s.len()..].copy_from_slice(&s);

            let sig = Signature::from_compact(&sig).unwrap();

            ctx.verify(&msg, &sig, &pk).unwrap();
        }
    }

    #[rocket::async_test]
    async fn test_eddsa() {
        use rand::Rng;
        use ed25519_dalek::{PublicKey, Signature, Verifier};
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
}
