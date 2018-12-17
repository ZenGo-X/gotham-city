use rocket;
use rocket::local::Client;
use rocket::http::ContentType;
use time::PreciseTime;

pub fn post(client: &Client, path: &str, body: Option<String>) -> Option<String> {
    let req = client.post(path);

    if let Some(b) = body {
        req.set_body(b);
    }

    req.header(ContentType::JSON);

    let start = PreciseTime::now();
    let res =
        req.dispatch().body_string();
    let end = PreciseTime::now();

    info!("(req {}, took: {})", path, start.to(end));

    res
}