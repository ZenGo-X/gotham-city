// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use two_party_ecdsa::curv::elliptic::curves::secp256_k1::{FE, GE};
use two_party_ecdsa::curv::elliptic::curves::traits::{ECPoint, ECScalar};

use std::fs;

const ESCROW_SK_FILENAME: &str = "escrow/escrow-sk.json";

pub const SEGMENT_SIZE: usize = 8;
pub const NUM_SEGMENTS: usize = 32;

pub struct Escrow {
    secret: FE,
    public: GE,
}

impl Default for Escrow {
    fn default() -> Self {
        Self::new()
    }
}

impl Escrow {
    pub fn new() -> Escrow {
        let secret: FE = ECScalar::new_random();
        let g: GE = ECPoint::generator();
        let public: GE = g * secret;
        fs::write(
            ESCROW_SK_FILENAME,
            serde_json::to_string(&(secret, public)).unwrap(),
        )
        .expect("Unable to save escrow secret!");

        Escrow { secret, public }
    }

    pub fn load() -> Escrow {
        let sec_data = fs::read_to_string(ESCROW_SK_FILENAME).expect("Unable to load wallet!");
        let (secret, public): (FE, GE) = serde_json::from_str(&sec_data).unwrap();
        Escrow { secret, public }
    }

    pub fn get_public_key(&self) -> GE {
        self.public
    }

    pub fn get_private_key(&self) -> FE {
        self.secret
    }
}
