// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//
use floating_duration::TimeFormat;
use log::info;
use serde::{de::DeserializeOwned, Serialize};
use std::time::Instant;
pub mod ecdsa;
pub mod escrow;
pub mod wallet;

mod utilities;

type Result<T> = std::result::Result<T, failure::Error>;

#[derive(Debug)]
pub struct ClientShim<C: Client> {
    pub client: C,
    pub auth_token: Option<String>,
    pub endpoint: String,
}

impl ClientShim<reqwest::Client> {
    pub fn new(endpoint: String, auth_token: Option<String>) -> ClientShim<reqwest::Client> {
        let client = reqwest::Client::new();
        ClientShim {
            client,
            auth_token,
            endpoint,
        }
    }
}

impl<C: Client> ClientShim<C> {
    pub fn new_with_client(endpoint: String, auth_token: Option<String>, client: C) -> Self {
        Self {
            client,
            auth_token,
            endpoint,
        }
    }
    pub fn post<V>(&self, path: &str) -> Option<V>
    where
        V: serde::de::DeserializeOwned,
    {
        let start = Instant::now();
        let res = self
            .client
            .post(&self.endpoint, path, self.auth_token.clone(), "{}");
        info!("(req {}, took: {:?})", path, TimeFormat(start.elapsed()));
        res
    }

    pub fn postb<T, V>(&self, path: &str, body: T) -> Option<V>
    where
        T: serde::ser::Serialize,
        V: serde::de::DeserializeOwned,
    {
        let start = Instant::now();
        let res = self
            .client
            .post(&self.endpoint, path, self.auth_token.clone(), body);
        info!("(req {}, took: {:?})", path, TimeFormat(start.elapsed()));
        res
    }
}

pub trait Client: Sized {
    fn post<V: DeserializeOwned, T: Serialize>(
        &self,
        endpoint: &str,
        uri: &str,
        bearer_token: Option<String>,
        body: T,
    ) -> Option<V>;
}

impl Client for reqwest::Client {
    fn post<V: DeserializeOwned, T: Serialize>(
        &self,
        endpoint: &str,
        uri: &str,
        bearer_token: Option<String>,
        body: T,
    ) -> Option<V> {
        let mut b = self.post(&format!("{}/{}", endpoint, uri));
        if let Some(token) = bearer_token {
            b = b.bearer_auth(token);
        }
        let value = b.json(&body).send().ok()?.text().ok()?;
        serde_json::from_str(value.as_str()).ok()
    }
}

pub use two_party_ecdsa::curv::{arithmetic::traits::Converter, BigInt};
// pub use multi_party_eddsa::protocols::aggsig::*;
