// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use log::info;
use rocket::{self, catch, catchers, routes, Build, Request, Rocket};
use rusoto_core::Region;
use rusoto_dynamodb::DynamoDbClient;
use serde::Deserialize;

use super::{storage::db, Config};

use std::collections::HashMap;
use std::str::FromStr;

#[derive(Deserialize)]
pub struct AuthConfig {
    pub issuer: String,
    pub audience: String,
    pub region: String,
    pub pool_id: String,
}

impl AuthConfig {
    pub fn load(settings: HashMap<String, String>) -> AuthConfig {
        let issuer = settings.get("issuer").unwrap_or(&"".to_string()).to_owned();
        let audience = settings
            .get("audience")
            .unwrap_or(&"".to_string())
            .to_owned();
        let region = settings.get("region").unwrap_or(&"".to_string()).to_owned();
        let pool_id = settings
            .get("pool_id")
            .unwrap_or(&"".to_string())
            .to_owned();

        AuthConfig {
            issuer,
            audience,
            region,
            pool_id,
        }
    }
}

#[catch(500)]
fn internal_error() -> &'static str {
    "Internal server error"
}

#[catch(400)]
fn bad_request() -> &'static str {
    "Bad request"
}

#[catch(404)]
fn not_found(req: &Request) -> String {
    format!("Unknown route '{}'.", req.uri())
}

pub fn get_server(settings: HashMap<String, String>) -> Rocket<Build> {
    // let settings = get_settings_as_map();
    let db_config = Config {
        db: get_db(settings.clone()),
    };

    let auth_config = AuthConfig::load(settings);

    rocket::Rocket::build()
        .register("/", catchers![internal_error, not_found, bad_request])
        .mount(
            "/",
            routes![
                crate::routes::ping::ping,
                crate::routes::ecdsa::first_message,
                crate::routes::ecdsa::second_message,
                crate::routes::ecdsa::third_message,
                crate::routes::ecdsa::fourth_message,
                crate::routes::ecdsa::chain_code_first_message,
                crate::routes::ecdsa::chain_code_second_message,
                crate::routes::ecdsa::sign_first,
                crate::routes::ecdsa::sign_second,
                crate::routes::ecdsa::recover,
            ],
        )
        .manage(db_config)
        .manage(auth_config)
}

fn get_settings_as_map() -> HashMap<String, String> {
    info!(
        "FAIL_KEYGEN_IF_ACTIVE_SHARE_EXISTS = {:?}",
        std::env::var("FAIL_KEYGEN_IF_ACTIVE_SHARE_EXISTS")
    );

    let config_file = include_str!("../Settings.toml");
    let mut settings = config::Config::default();
    settings
        .merge(config::File::from_str(
            config_file,
            config::FileFormat::Toml,
        ))
        .unwrap()
        .merge(config::Environment::new())
        .unwrap();

    settings.try_into::<HashMap<String, String>>().unwrap()
}

fn get_db(settings: HashMap<String, String>) -> db::DB {
    let db_type_string = settings
        .get("db")
        .unwrap_or(&"local".to_string())
        .to_uppercase();
    let db_name = settings.get("db_name").unwrap_or(&"db".to_string()).clone();
    if !db_name.chars().all(|e| char::is_ascii_alphanumeric(&e)) {
        panic!("DB name is illegal, may only contain alphanumeric characters");
    }
    let db_type = db_type_string.as_str();
    let env = settings
        .get("env")
        .unwrap_or(&"dev".to_string())
        .to_string();

    match db_type {
        "AWS" => {
            let region_option = settings.get("aws_region");
            match region_option {
                Some(s) => {
                    let region_res = Region::from_str(s);
                    match region_res {
                        Ok(region) => db::DB::AWS(DynamoDbClient::new(region), env),
                        Err(_e) => panic!("Set 'DB = AWS' but 'region' is not a valid value"),
                    }
                }
                None => panic!("Set 'DB = AWS' but 'region' is empty"),
            }
        }
        _ => db::DB::Local(rocksdb::DB::open_default(format!("./{}", db_name)).unwrap()),
    }
}
