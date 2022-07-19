// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//
use crate::ClientShim;
use floating_duration::TimeFormat;
use serde;
use std::time::Instant;

pub fn post<V>(client_shim: &ClientShim, path: &str) -> Option<V>
where
    V: serde::de::DeserializeOwned,
{
    _postb(client_shim, path, "{}")
}

pub fn postb<T, V>(client_shim: &ClientShim, path: &str, body: T) -> Option<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    _postb(client_shim, path, body)
}

fn _postb<T, V>(client_shim: &ClientShim, path: &str, body: T) -> Option<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    let start = PreciseTime::now();

    let mut b = client_shim
        .client
        .post(&format!("{}/{}", client_shim.endpoint, path));

    if client_shim.auth_token.is_some() {
        b = b.bearer_auth(client_shim.auth_token.clone().unwrap());
    }

    let res = b.json(&body).send();

    let end = PreciseTime::now();

    info!("(req {}, took: {:?})", path, start.to(end));

    let value = match res {
        Ok(mut v) => v.text().unwrap(),
        Err(_) => return None,
    };

    Some(serde_json::from_str(value.as_str()).unwrap())
}
