// Gotham-city 
// 
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use rocket::State;
use jwt::Algorithm;
use super::{PublicKey};
use super::jwt::{Claims, get_claims, decode_token};
use std::collections::HashMap;
use serde_json;
use hex;
use std::process::Command;
use rocket::Outcome;
use rocket::request::{self, Request, FromRequest};
use rocket::http::Status;

use super::passthrough;
use super::super::server::AuthConfig;

const ALGORITHM : Algorithm = Algorithm::RS256;
const TOKEN_TYPE : &str = "Bearer";

pub fn verify(issuer: &String,
              audience: &String,
              region: &String,
              pool_id: &String,
              authorization_header: &String) -> Result<Claims, ()>
{
    let mut header_parts = authorization_header.split_whitespace();
    let token_type = header_parts.next();
    assert_eq!(token_type, Some(TOKEN_TYPE));

    let token = header_parts.next().unwrap();
    let header = decode_token(token.to_string());

    let key_set = get_key_set(region, pool_id);
    let key = key_set.get(&header.kid.unwrap()).unwrap();

    let secret = hex::decode(&key.der).unwrap();
    let algorithms : Vec<Algorithm> = vec![ ALGORITHM ];

    get_claims(issuer, audience, &token.to_string(), &secret, algorithms)
}

fn get_key_set(region: &String, pool_id: &String) -> HashMap<String, PublicKey> {
    let key_set_json = get_jwt_to_pems(region, pool_id);
    let key_set : HashMap<String, PublicKey> = serde_json::from_str(&key_set_json).unwrap();

    key_set
}

fn get_jwt_to_pems(region: &String, pool_id: &String) -> String {
    let output = Command::new("node")
        .arg("jwt-to-pems.js")
        .arg(format!("--region={}", region))
        .arg(format!("--poolid={}", pool_id))
        .current_dir("../gotham-utilities/server/cognito")
        .output()
        .expect("jwt-to-pems.js command failed");

    String::from_utf8_lossy(&output.stdout).to_string()
}


impl<'a, 'r> FromRequest<'a, 'r> for Claims {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Claims, ()> {
        let auths: Vec<_> = request.headers().get("Authorization").collect();
        let config = request.guard::<State<AuthConfig>>()?;


        if config.issuer.is_empty() && config.audience.is_empty()
            && config.region.is_empty() && config.pool_id.is_empty() {
            info!("!!! Auth config empty, request in PASSTHROUGH mode !!! ");
            if auths.is_empty() { // No Authorization header
                info!("!!! No Authorization header, request accepted !!! ");
                return Outcome::Success(passthrough::get_empty_claim());
            } else {
                error!("!!! Auth config empty but authorization header, rejecting requests !!!");
                return Outcome::Failure((Status::Unauthorized, ()));
            }
        }

        let claim = match verify(&config.issuer, &config.audience, &config.region, &config.pool_id,
            &auths[0].to_string()
        ) {
            Ok(claim) => claim,
            Err(_) => {
                error!("!!! Token is invalid !!!");
                return Outcome::Failure((Status::Unauthorized, ()));
            }
        };

        Outcome::Success(claim)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER : &str = "issuer";
    const AUDIENCE : &str = "audience";
    const REGION: &str = "region";
    const POOL_ID : &str = "pool_id";

    #[test]
    #[should_panic] // Obviously hardcoded authorization_header become invalid/expired
    pub fn get_user_id_test() {
        let authorization_header = "Bearer .a.b-c-d-e-f-g-h-i".to_string();

        verify(
            &ISSUER.to_string(),
            &AUDIENCE.to_string(),
            &REGION.to_string(),
            &POOL_ID.to_string(),
            &authorization_header).is_ok();
    }

    #[test]
    #[should_panic] // Obviously the machine needs to be connected to an aws account
    pub fn get_jwt_to_pems_test() {
        let key_set_json = get_jwt_to_pems(&REGION.to_string(), &POOL_ID.to_string());
        assert_eq!(key_set_json.is_empty(), false);
    }
}