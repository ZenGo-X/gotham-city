use rocket::{Request, Rocket};
use rocket;
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
        db: DB::open_default("./db").unwrap()
    };

    rocket::ignite()
        .register(catchers![internal_error, not_found, bad_request])
        .mount("/", routes![
                ecdsa::first_message,
                ecdsa::second_message,
                ecdsa::third_message,
                ecdsa::fourth_message,
                ecdsa::chain_code_first_message,
                ecdsa::chain_code_second_message,
                ecdsa::chain_code_compute_message,
                ecdsa::master_key,
                ecdsa::sign_first,
                ecdsa::sign_second
            ])
        .manage(config)
}