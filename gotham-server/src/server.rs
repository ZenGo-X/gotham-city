// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use rocket;
use rocket::{Request, Rocket};
use rocksdb;

use rusoto_core::Region;
use rusoto_dynamodb::DynamoDbClient;

use super::routes::ecdsa;
use super::storage::db;

use std::env;

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
    let is_aws_db = match env::var("DB") {
        Ok(v) => v == "AWS",
        _ => false,
    };
    if is_aws_db {
        db::DB::AWS(DynamoDbClient::new(Region::UsWest2))
    } else {
        db::DB::Local(rocksdb::DB::open_default("./db").unwrap())
    }
}
