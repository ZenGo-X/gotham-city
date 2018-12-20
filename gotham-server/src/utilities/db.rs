// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use rocksdb::DB;
use rocksdb::DBVector;
use super::super::routes::ecdsa;
use serde;

fn idify(id: &String, name: &ecdsa::Share) -> String {
    format!("{}_{}", id, name.to_string())
}

pub fn insert<T>(db: &DB, id: &String, name: &ecdsa::Share, v: &T)
    where
        T: serde::ser::Serialize,
{
    let identifier = idify(id, name);
    let v : String = serde_json::to_string(&v).unwrap();
    info!("Inserting into db ({}, {})", identifier, v);

    let r = db.put(identifier.as_ref(), v.as_ref());
    if r.is_err() {
        panic!("Error while writing to db for identifier {}", identifier);
    }
}

pub fn get(db: &DB, id: &String, name: &ecdsa::Share) ->  Option<DBVector>
{
    let identifier = idify(id, name);
    info!("Getting from db ({})", identifier);

    let r = db.get(identifier.as_ref());
    if r.is_err() {
        panic!("Error while reading from db for identifier {}", identifier)
    }

    r.unwrap()
}