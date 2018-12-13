use rocket::{Request, Rocket};
use rocket;
use rocksdb::DB;

use super::routes::keygen;

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
    let config = keygen::Config {
        db: DB::open_default("./db").unwrap()
    };

    rocket::ignite()
        .register(catchers![internal_error, not_found, bad_request])
        .mount("/", routes![
                keygen::first_message,
                keygen::second_message,
                keygen::third_message,
                keygen::fourth_message
            ])
        .manage(config)
}