// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use config;
use rocket;
use rocket::{Request, Rocket};
use rocksdb;

use rusoto_core::Region;
use rusoto_dynamodb::DynamoDbClient;

use super::routes::ecdsa;
use super::storage::db;

use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;

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

pub fn get_server() -> Rocket {
    let config = ecdsa::Config { db: get_db() };

    match db::init(&config.db) {
        Err(_e) => panic!("Error while initializing DB."),
        _ => {}
    };

    rocket::ignite()
        .register(catchers![internal_error, not_found, bad_request])
        .mount(
            "/",
            routes![
                ecdsa::first_message,
                ecdsa::second_message,
                ecdsa::third_message,
                ecdsa::fourth_message,
                ecdsa::chain_code_first_message,
                ecdsa::chain_code_second_message,
                ecdsa::sign_first,
                ecdsa::sign_second,
                ecdsa::rotate_first,
                ecdsa::rotate_second,
                ecdsa::rotate_third,
                ecdsa::rotate_fourth,
                ecdsa::recover,
            ],
        )
        .manage(config)
}

fn get_db() -> db::DB {
    println!("exists? {}", Path::new("../Settings.toml").exists());
    println!("exists? {}", Path::new("Settings.toml").exists());

    if !Path::new("Settings.toml").exists() {
        // ignore settings file if no settings file found (e.g. when running integration tests)
        db::DB::Local(rocksdb::DB::open_default("./db").unwrap())
    } else {
        let mut settings = config::Config::default();
        settings
            .merge(config::File::with_name("Settings"))
            .unwrap()
            .merge(config::Environment::new())
            .unwrap();
        let hm = settings.try_into::<HashMap<String, String>>().unwrap();
        let db_type_string = hm.get("db").unwrap_or(&"local".to_string()).to_uppercase();
        let db_type = db_type_string.as_str();
        let env = hm.get("env").unwrap_or(&"dev".to_string()).to_string();
        match db_type {
            "AWS" => {
                let region_option = hm.get("aws_region");
                match region_option {
                    Some(s) => {
                        let region_res = Region::from_str(&s);
                        match region_res {
                            Ok(region) => db::DB::AWS(DynamoDbClient::new(region), env),
                            Err(_e) => panic!("Set 'DB = AWS' but 'region' is not a valid value"),
                        }
                    }
                    None => panic!("Set 'DB = AWS' but 'region' is empty"),
                }
            }
            _ => db::DB::Local(rocksdb::DB::open_default("./db").unwrap()),
        }
    }
}
