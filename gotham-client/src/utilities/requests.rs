use reqwest;
use time::PreciseTime;
use serde;

pub fn post(client: &reqwest::Client, path: &str) -> Option<String> {
    let start = PreciseTime::now();

    let res = client
        .post(&format!("http://127.0.0.1:8000/{}", path))
        .json("{}")
        .send();

    let end = PreciseTime::now();

    info!("(req {}, took: {})", path, start.to(end));

    Some(res.unwrap().text().unwrap())
}


pub fn postb<T>(client: &reqwest::Client, path: &str, body: T) -> Option<String>
    where
        T: serde::ser::Serialize,
{
    let start = PreciseTime::now();

    let res = client
        .post(&format!("http://127.0.0.1:8000/{}", path))
        .json(&body)
        .send();

    let end = PreciseTime::now();

    info!("(req {}, took: {})", path, start.to(end));

    Some(res.unwrap().text().unwrap())
}