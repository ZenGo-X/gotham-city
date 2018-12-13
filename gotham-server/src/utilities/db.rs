use rocksdb::DB;
use rocksdb::DBVector;
use super::super::routes::keygen;
use serde;

fn idify(id: &String, name: &keygen::Share) -> String {
    format!("{}_{}", id, name.to_string())
}

pub fn insert<T>(db: &DB, id: &String, name: &keygen::Share, v: &T)
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

pub fn get(db: &DB, id: &String, name: &keygen::Share) ->  Option<DBVector>
{
    let identifier = idify(id, name);
    info!("Getting from db ({})", identifier);

    let r = db.get(identifier.as_ref());
    if r.is_err() {
        panic!("Error while reading from db for identifier {}", identifier)
    }

    r.unwrap()
}