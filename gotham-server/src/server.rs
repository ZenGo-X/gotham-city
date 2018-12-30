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
use rocksdb::DB;

use super::routes::ecdsa;

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
    let config = ecdsa::Config {
        db: DB::open_default("./db").unwrap(),
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
                ecdsa::chain_code_compute_message,
                ecdsa::master_key,
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
