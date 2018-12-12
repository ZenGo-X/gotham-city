#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
extern crate rocket_contrib;
extern crate kms;
extern crate multi_party_ecdsa;

pub mod routes;

