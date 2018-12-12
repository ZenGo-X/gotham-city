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
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate log;

pub mod utilities;
pub mod routes;


