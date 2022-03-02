#[cfg(test)]
mod tests {
    extern crate client_lib;
    extern crate server_lib;

    use client_lib::*;
    use rocket::Config;
    use server_lib::server;
    use std::collections::HashMap;
    use std::{thread, time};

    #[rocket::async_test]
    async fn test_ecdsa() {
        rocket::tokio::spawn(spawn_server(8000, "ecdsa"));

        let five_seconds = time::Duration::from_millis(5000);
        thread::sleep(five_seconds);

        let client_shim = ClientShim::new("http://localhost:8000".to_string(), None);

        let ps: ecdsa::PrivateShare = ecdsa::get_master_key(&client_shim);

        for y in 0..10 {
            let x_pos = BigInt::from(0);
            let y_pos = BigInt::from(y);
            println!("Deriving child_master_key at [x: {}, y:{}]", x_pos, y_pos);

            let child_master_key = ps.master_key.get_child(vec![x_pos.clone(), y_pos.clone()]);

            let msg: BigInt = BigInt::from(y + 1); // arbitrary message
            let signature = ecdsa::sign(&client_shim, msg, &child_master_key, x_pos, y_pos, &ps.id)
                .expect("ECDSA signature failed");

            println!(
                "signature = (r: {}, s: {})",
                signature.r.to_hex(),
                signature.s.to_hex()
            );
        }
    }

    #[rocket::async_test]
    async fn test_eddsa() {
        rocket::tokio::spawn(spawn_server(8002, "eddsa"));

        let client_shim = ClientShim::new("http://localhost:8002".to_string(), None);

        let five_seconds = time::Duration::from_millis(5000);
        thread::sleep(five_seconds);

        let (key_pair, key_agg, id) = client_lib::eddsa::generate_key(&client_shim).unwrap();

        let message = [74u8, 24u8, 37u8, 20u8, 12u8, 3u8, 14u8];
        let signature = client_lib::eddsa::sign(&client_shim, &message, &key_pair, &key_agg, &id)
            .expect("EdDSA signature failed");

        println!(
            "signature = {:?}",
            signature
        );
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
