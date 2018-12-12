#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
extern crate server_lib;

use rocket::Request;

use server_lib::routes::keygen;

#[catch(500)]
fn internal_error() -> &'static str {
    "Internal server error"
}

#[catch(404)]
fn not_found(req: &Request) -> String {
    format!("Unknown route '{}'.", req.uri())
}

fn main() {
    rocket::ignite()
        .register(catchers![internal_error, not_found])
        .mount("/", routes![keygen::world])
        .launch();
}
