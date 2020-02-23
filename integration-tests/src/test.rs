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
                signature.s.to_hex(),
            );
        }
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
