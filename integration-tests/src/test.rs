#[cfg(test)]
mod tests {
    extern crate server_lib;
    extern crate client_lib;
    extern crate bitcoin;
    extern crate kms;

    use client_lib::api::{PrivateShare, ClientShim};
    use bitcoin::util::hash::Sha256dHash;
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

        let client_shim = ClientShim::new("http://localhost:8000".to_string());

        let five_seconds = time::Duration::from_millis(5000);
        thread::sleep(five_seconds);

        let ps: PrivateShare = client_lib::api::get_master_key(&client_shim);

        let pos = 0;
        let child_master_key = ps
            .master_key
            .get_child(vec![BigInt::from(pos)]);

        let data : &[u8] = &[];
        let hash : Sha256dHash = Sha256dHash::from_data(data);
        let signature = client_lib::api::sign(&client_shim, hash, &child_master_key, pos, &ps.id);
        println!(
            "signature = (r: {}, s: {})",
            signature.r.to_hex(),
            signature.s.to_hex()
        );
    }
}
