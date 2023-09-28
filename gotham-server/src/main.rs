mod server;
mod public_gotham;

use std::collections::HashMap;

#[rocket::launch]
fn rocket() -> _ {
    let settings = get_settings_as_map();
    crate::server::get_server(settings)
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
