use crate::public_gotham::PublicGotham;
use rocket::{self, catch, catchers, routes, Build, Request, Rocket};
use std::collections::HashMap;
use tokio::sync::Mutex;

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

pub fn get_server() -> Rocket<Build> {
    let x = PublicGotham::new();
    rocket::Rocket::build()
        .register("/", catchers![internal_error, not_found, bad_request])
        .mount(
            "/",
            routes![
                gotham_engine::routes::wrap_keygen_first,
                gotham_engine::routes::wrap_keygen_second,
                gotham_engine::routes::wrap_keygen_third,
                gotham_engine::routes::wrap_keygen_fourth,
                gotham_engine::routes::wrap_chain_code_first_message,
                gotham_engine::routes::wrap_chain_code_second_message,
                gotham_engine::routes::wrap_sign_first,
                gotham_engine::routes::wrap_sign_second,
                gotham_engine::routes::wrap_sign_first_v2,
                gotham_engine::routes::wrap_sign_second_v2,
                gotham_engine::routes::wrap_sign_first_v3,
                gotham_engine::routes::wrap_sign_second_v3,
                gotham_engine::routes::wrap_rotate_first,
                gotham_engine::routes::wrap_rotate_second,
                gotham_engine::routes::wrap_rotate_third,
                gotham_engine::routes::wrap_rotate_forth,
            ],
        )
        .manage(Mutex::new(Box::new(x) as Box<dyn gotham_engine::traits::Db>))
}
