// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use log::LevelFilter;
use server_lib::server;
use std::collections::HashMap;

#[rocket::launch]
fn rocket() -> _ {
    let settings = get_settings_as_map();
    server::get_server(settings)
}

fn get_settings_as_map() -> HashMap<String, String> {
    let config_file = include_str!("../Settings.toml");
    let mut settings = config::Config::default();
    settings
        .merge(config::File::from_str(
            config_file,
            config::FileFormat::Toml,
        ))
        .unwrap()
        .merge(config::Environment::new())
        .unwrap();

    settings.try_into::<HashMap<String, String>>().unwrap()
}
