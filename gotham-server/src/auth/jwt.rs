// Gotham-city 
// 
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//
use super::super::jwt::errors::ErrorKind;
use  super::super::jwt::{decode, encode, Header, Validation};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}

pub fn decode_token(&token: String, &secret: String) -> Claims {
    let token = decode::<Claims>(&token, secret, &Validation::default())?;

    token.claims
}