// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

pub mod ecdsa;
pub mod eddsa;
pub mod escrow;

mod utilities;

type Result<T> = std::result::Result<T, failure::Error>;

#[derive(Debug)]
pub struct ClientShim {
    pub client: reqwest::Client,
    pub auth_token: Option<String>,
    pub endpoint: String,
}

impl ClientShim {
    pub fn new(endpoint: String, auth_token: Option<String>) -> ClientShim {
        let client = reqwest::Client::new();
        ClientShim {
            client,
            auth_token,
            endpoint,
        }
    }
}

pub use two_party_ecdsa::curv::{arithmetic::traits::Converter, BigInt};
// pub use multi_party_eddsa::protocols::aggsig::*;
