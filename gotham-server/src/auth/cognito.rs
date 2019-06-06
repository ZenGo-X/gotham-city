// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use super::jwt::{decode_header_from_token, get_claims, Claims};
use super::PublicKey;
use hex;
use jwt::Algorithm;
use rocket::http::Status;
use rocket::request::{self, FromRequest, Request};
use rocket::Outcome;
use rocket::State;
use serde_json;
use std::collections::HashMap;
use std::process::Command;

use super::super::server::AuthConfig;
use super::passthrough;

const ALGORITHM: Algorithm = Algorithm::RS256;
const TOKEN_TYPE: &str = "Bearer";

pub fn verify(
    issuer: &String,
    audience: &String,
    region: &String,
    pool_id: &String,
    authorization_header: &String,
) -> Result<Claims, ()> {
    let mut header_parts = authorization_header.split_whitespace();
    let token_type = header_parts.next();
    assert_eq!(token_type, Some(TOKEN_TYPE));

    let token = header_parts.next().unwrap();

    let header = match decode_header_from_token(token.to_string()) {
        Ok(h) => h,
        Err(_) => return Err(()),
    };

    let key_set_str: String = match get_jwt_to_pems(region, pool_id) {
        Ok(k) => k,
        Err(_) => return Err(()),
    };

    let key_set: HashMap<String, PublicKey> = match serde_json::from_str(&key_set_str) {
        Ok(k) => k,
        Err(_) => return Err(()),
    };

    let header_kid = header.kid.unwrap();

    if !key_set.contains_key(&header_kid) {
        return Err(());
    }

    let key = key_set.get(&header_kid).unwrap();

    let secret = hex::decode(&key.der).unwrap();
    let algorithms: Vec<Algorithm> = vec![ALGORITHM];

    get_claims(issuer, audience, &token.to_string(), &secret, algorithms)
}

fn get_jwt_to_pems(region: &String, pool_id: &String) -> Result<String, ()> {
    match Command::new("node")
        .arg("jwt-to-pems.js")
        .arg(format!("--region={}", region))
        .arg(format!("--poolid={}", pool_id))
        .current_dir("../gotham-utilities/server/cognito")
        .output()
    {
        Ok(o) => return Ok(String::from_utf8_lossy(&o.stdout).to_string()),
        Err(_) => return Err(()),
    };
}

impl<'a, 'r> FromRequest<'a, 'r> for Claims {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Claims, ()> {
        let auths: Vec<_> = request.headers().get("Authorization").collect();
        let config = request.guard::<State<AuthConfig>>()?;

        if config.issuer.is_empty()
            && config.audience.is_empty()
            && config.region.is_empty()
            && config.pool_id.is_empty()
        {
            debug!("!!! Auth config empty, request in PASSTHROUGH mode !!! ");
            if auths.is_empty() {
                // No Authorization header
                debug!("!!! No Authorization header, request accepted !!! ");
                return Outcome::Success(passthrough::get_empty_claim());
            } else {
                error!("!!! Auth config empty but authorization header, rejecting requests !!!");
                return Outcome::Failure((Status::Unauthorized, ()));
            }
        }

        if auths.is_empty() {
            return Outcome::Failure((Status::Unauthorized, ()));
        }

        let claim = match verify(
            &config.issuer,
            &config.audience,
            &config.region,
            &config.pool_id,
            &auths[0].to_string(),
        ) {
            Ok(claim) => claim,
            Err(_) => {
                error!("!!! Auth error: Unauthorized (401) !!!");
                return Outcome::Failure((Status::Unauthorized, ()));
            }
        };

        Outcome::Success(claim)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "issuer";
    const AUDIENCE: &str = "audience";
    const REGION: &str = "region";
    const POOL_ID: &str = "pool_id";

    #[test]
    pub fn get_user_id_test() {
        let authorization_header = "Bearer .a.b-c-d-e-f-g-h-i".to_string();

        assert!(verify(
            &ISSUER.to_string(),
            &AUDIENCE.to_string(),
            &REGION.to_string(),
            &POOL_ID.to_string(),
            &authorization_header
        )
        .is_err());
    }
}
