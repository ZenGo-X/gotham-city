#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
extern crate rocket_contrib;
extern crate kms;
extern crate multi_party_ecdsa;
extern crate zk_paillier;
extern crate curv;
extern crate rocksdb;
extern crate uuid;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

extern crate strum;

#[macro_use]
extern crate strum_macros;

#[macro_use]
extern crate log;

#[macro_use]
extern crate time_test;

pub mod utilities;
pub mod routes;
pub mod server;
pub mod tests;


