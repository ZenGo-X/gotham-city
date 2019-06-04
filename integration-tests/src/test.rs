#[cfg(test)]
mod tests {
    extern crate server_lib;
    extern crate client_lib;
    extern crate bitcoin;
    extern crate kms;

    use client_lib::{ecdsa, ClientShim};
    use curv::arithmetic::traits::Converter;
    use curv::BigInt;
    use server_lib::server;
    use std::{thread, time};

    #[test]
    fn test_api() {
        // Rocket server is blocking, so we spawn a new thread.
        thread::spawn(move || {
            server::get_server().launch();
        });

        let client_shim = ClientShim::new("http://localhost:8000".to_string(), None);

        let five_seconds = time::Duration::from_millis(5000);
        thread::sleep(five_seconds);

        let ps: ecdsa::PrivateShare = ecdsa::get_master_key(&client_shim);

        let x_pos = BigInt::from(0);
        let y_pos = BigInt::from(0);
        let child_master_key = ps
            .master_key
            .get_child(vec![x_pos.clone(), y_pos.clone()]);

        let msg: BigInt = BigInt::from(1234);  // arbitrary message
        let signature = ecdsa::sign(&client_shim, msg, &child_master_key, x_pos, y_pos, &ps.id);
        println!(
            "signature = (r: {}, s: {})",
            signature.r.to_hex(),
            signature.s.to_hex()
        );
    }
}
