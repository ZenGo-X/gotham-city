// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use centipede::juggling::proof_system::Proof;
use centipede::juggling::proof_system::{Helgamalsegmented, Witness};
use centipede::juggling::segmentation::Msegmentation;
use curv::elliptic::curves::traits::ECPoint;
use curv::elliptic::curves::traits::ECScalar;
use curv::{FE, GE};
use kms::ecdsa::two_party::MasterKey2;

use serde_json;
use std::fs;

const ESCROW_CLIENT_FILENAME: &str = "escrow/client.backup";

const ESCROW_SK_FILENAME: &str = "escrow/escrow-sk.json";
const SK_REC_FILENAME: &str = "escrow/sk-recovered.json";

const SEGMENT_SIZE: usize = 8;
const NUM_SEGMENTS: usize = 32;

pub struct Escrow {
    secret: FE,
}

impl Escrow {
    pub fn new() -> Escrow {
        let secret: FE = ECScalar::new_random();
        fs::write(ESCROW_SK_FILENAME, serde_json::to_string(&secret).unwrap())
            .expect("Unable to save escrow secret!");

        Escrow { secret }
    }

    pub fn load() -> Escrow {
        let sec_data = fs::read_to_string(ESCROW_SK_FILENAME).expect("Unable to load wallet!");

        let secret: FE = serde_json::from_str(&sec_data).unwrap();

        Escrow { secret }
    }

    pub fn backup_shares(&self, master_key_2: &MasterKey2) {
        let g: GE = ECPoint::generator();
        let y = g.clone() * &self.secret;

        let (segments, encryptions) =
            master_key_2
                .private
                .to_encrypted_segment(&SEGMENT_SIZE, NUM_SEGMENTS, &y, &g);

        let proof = Proof::prove(&segments, &encryptions, &g, &y, &SEGMENT_SIZE);

        let client_backup_json = serde_json::to_string(&(segments, encryptions, proof)).unwrap();

        fs::write(ESCROW_CLIENT_FILENAME, client_backup_json)
            .expect("Unable to save client backup!");
    }

    pub fn recover_and_save_shares(&self) {
        let g: GE = ECPoint::generator();

        let data =
            fs::read_to_string(ESCROW_CLIENT_FILENAME).expect("Unable to load client backup!");

        let (_segments, encryptions, _proof): (Witness, Helgamalsegmented, Proof) =
            serde_json::from_str(&data).unwrap();

        let sk = Msegmentation::decrypt(&encryptions, &g, &self.secret, &SEGMENT_SIZE);

        fs::write(SK_REC_FILENAME, serde_json::to_string(&sk).unwrap())
            .expect("Unable to save client backup!");
    }
}
