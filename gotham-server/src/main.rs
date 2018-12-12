#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
extern crate server_lib;
extern crate rocksdb;

use rocket::Request;
use rocksdb::DB;

use server_lib::routes::keygen;


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

fn main() {
    let config = keygen::Config {
        db: DB::open_default("./db").unwrap()
    };

    rocket::ignite()
        .register(catchers![internal_error, not_found, bad_request])
        .mount("/", routes![
                keygen::party1_first_message,
                keygen::party1_second_message
            ])
        .manage(config)
        .launch();
}
