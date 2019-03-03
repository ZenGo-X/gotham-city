// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKey {
    pub kid: String,
    pub pem: String,
    pub der: String,
    pub alg: String,
    pub kty: String,
}

pub mod cognito;
pub mod jwt;
pub mod passthrough;
