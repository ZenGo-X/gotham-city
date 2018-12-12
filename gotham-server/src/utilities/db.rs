use rocksdb::DB;
use serde;
use serde_json;

pub fn insert<T>(db: &DB, id: &String, name: &str, v: &T)
    where
        T: serde::ser::Serialize,
{
    let identifier = format!("{}_{}", id, name);
    let v : String = serde_json::to_string(&v).unwrap();

    info!("Inserting into db ({}, {})", identifier, v);

    let r = db.put(identifier.as_ref(), v.as_ref());

    if r.is_err() {
        error!("Error while writing to db for identifier {}", identifier);
    }
}