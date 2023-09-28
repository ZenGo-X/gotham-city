use crate::public_gotham::{Config, PublicGotham, DB};
use rocket::{self, catch, routes, Build, Request, Rocket, catchers};
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

pub fn get_server(settings: HashMap<String, String>) -> Rocket<Build> {

    // let settings = get_settings_as_map();
    let db_config = Config {
        db: get_db(settings.clone()),
    };
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
            ],
        )
        .manage(Mutex::new(Box::new(x) as Box<dyn gotham_engine::traits::Db>))
        .manage(db_config)
}

fn get_db(settings: HashMap<String, String>) -> DB {
    let db_name = settings.get("db_name").unwrap_or(&"db".to_string()).clone();
    if !db_name.chars().all(|e| char::is_ascii_alphanumeric(&e)) {
        panic!("DB name is illegal, may only contain alphanumeric characters");
    }

    DB::Local(rocksdb::DB::open_default(format!("./{}", db_name)).unwrap())
}
