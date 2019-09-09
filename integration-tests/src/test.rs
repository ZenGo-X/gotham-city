#[cfg(test)]
mod tests {
    extern crate server_lib;
    extern crate client_lib;

    use client_lib::*;
    use server_lib::server;
    use std::{thread, time};

    #[test]
    fn test_ecdsa() {
        spawn_server();

        let client_shim = ClientShim::new("http://localhost:8000".to_string(), None);

        let ps: ecdsa::PrivateShare = ecdsa::get_master_key(&client_shim);

        for y in 0..10 {
            let x_pos = BigInt::from(0);
            let y_pos = BigInt::from(y);
            println!("Deriving child_master_key at [x: {}, y:{}]", x_pos, y_pos);

            let child_master_key = ps
                .master_key
                .get_child(vec![x_pos.clone(), y_pos.clone()]);

            let msg: BigInt = BigInt::from(y + 1);  // arbitrary message
            let signature =
                ecdsa::sign(&client_shim, msg, &child_master_key, x_pos, y_pos, &ps.id)
                    .expect("ECDSA signature failed");

            println!(
                "signature = (r: {}, s: {})",
                signature.r.to_hex(),
                signature.s.to_hex()
            );
        }
    }

    #[test]
    fn test_schnorr() {
        spawn_server();

        let client_shim = ClientShim::new("http://localhost:8000".to_string(), None);

        let share: schnorr::Share = schnorr::generate_key(&client_shim).unwrap();

        let msg: BigInt = BigInt::from(1234);  // arbitrary message
        let signature = schnorr::sign(&client_shim, msg, &share)
            .expect("Schnorr signature failed");

        println!(
            "signature = (e: {:?}, s: {:?})",
            signature.e,
            signature.s
        );
    }

    #[test]
    fn test_eddsa() {
        spawn_server();

        let client_shim = ClientShim::new("http://localhost:8000".to_string(), None);

        let five_seconds = time::Duration::from_millis(5000);
        thread::sleep(five_seconds);

        let (key_pair, key_agg, id) = client_lib::eddsa::generate_key(&client_shim).unwrap();

        let message = BigInt::from(1234);
        let signature =
            client_lib::eddsa::sign(&client_shim, message, &key_pair, &key_agg, &id)
            .expect("EdDSA signature failed");

        println!(
            "signature = (R: {}, s: {})",
            signature.R.bytes_compressed_to_big_int().to_hex(),
            signature.s.to_big_int().to_hex()
        );
    }

    fn spawn_server() {
        // Rocket server is blocking, so we spawn a new thread.
        thread::spawn(move || {
            server::get_server().launch();
        });

        let five_seconds = time::Duration::from_millis(5000);
        thread::sleep(five_seconds);
    }
}
