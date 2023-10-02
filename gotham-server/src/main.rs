mod public_gotham;
mod server;

use std::collections::HashMap;

#[rocket::launch]
fn rocket() -> _ {
    crate::server::get_server()
}
