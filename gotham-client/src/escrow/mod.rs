// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use curv::{GE, FE};
use curv::elliptic::curves::traits::ECScalar;
use curv::elliptic::curves::traits::ECPoint;
use kms::ecdsa::two_party::MasterKey2;

use serde_json;
use std::fs;

const ESCROW_CLIENT_FILENAME : &str = "escrow/client.backup";

const PK_FILENAME : &str = "escrow/pk.json";
const SK_FILENAME : &str = "escrow/sk.json";

const SEGMENT_SIZE : usize = 8;
const NUM_SEGMENTS : usize = 32;

pub struct Escrow {
    pub pk: GE,
    sk: FE
}

impl Escrow {
    pub fn new() -> Escrow {
        let pk_s = fs::read_to_string(PK_FILENAME)
            .expect("Unable to load pk!");

        let sk_s = fs::read_to_string(SK_FILENAME)
            .expect("Unable to load sk!");

        let pk : GE = serde_json::from_str(&pk_s).unwrap();
        let sk: FE = serde_json::from_str(&sk_s).unwrap();

        Escrow { pk, sk }
    }

    pub fn backup_shares(&self, master_key_2: &MasterKey2) {
        let g: GE = ECPoint::generator();
        let y = g.clone() * &self.sk;

        let (segments, encryptions) = master_key_2.private
            .to_encrypted_segment(&SEGMENT_SIZE, NUM_SEGMENTS, &y, &g);

        let client_backup_json = serde_json::to_string(&(segments, encryptions)).unwrap();

        fs::write(ESCROW_CLIENT_FILENAME, client_backup_json)
            .expect("Unable to save client backup!");
    }
}
