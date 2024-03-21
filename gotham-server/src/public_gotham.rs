//!Public gotham implementation

use rocket::async_trait;
use std::collections::HashMap;
use std::string::String;

use two_party_ecdsa::typetags::Value;

use gotham_engine::keygen::KeyGen;
use gotham_engine::sign::Sign;
use gotham_engine::traits::*;
use gotham_engine::types::*;

pub struct PublicGotham {
    rocksdb_client: rocksdb::DB,
}
pub struct Authorizer {}


impl PublicGotham {
    pub fn new(settings: HashMap<String, String>) -> Self {
        let db_name = settings.get("db_name").unwrap_or(&"db".to_string()).clone();
        if !db_name.chars().all(|e| char::is_ascii_alphanumeric(&e)) {
            panic!("DB name is illegal, may only contain alphanumeric characters");
        }

        let rocksdb_client = rocksdb::DB::open_default(format!("./{}", db_name)).unwrap();

        PublicGotham { rocksdb_client }
    }
}

impl KeyGen for PublicGotham {}

impl Sign for PublicGotham {}

#[inline(always)]
fn idify(user_id: String, id: String, name: &dyn MPCStruct) -> String {
    format!("{}_{}_{}", user_id, id, name.to_string())
}

#[async_trait]
impl Db for PublicGotham {
    async fn insert(
        &self,
        key: &DbIndex,
        table_name: &dyn MPCStruct,
        value: &dyn Value,
    ) -> Result<(), String> {
        let identifier = idify(key.clone().customerId, key.clone().id, table_name);
        let v_string = serde_json::to_string(&value).unwrap();
        println!("Inserting into db ({})", identifier);

        let _ = self.rocksdb_client.put(identifier, v_string.clone());
        Ok(())
    }

    async fn get(
        &self,
        key: &DbIndex,
        table_name: &dyn MPCStruct,
    ) -> Result<Option<Box<dyn Value>>, String> {
        let identifier = idify(key.clone().customerId, key.clone().id, table_name);
        println!("Getting from db ({})", identifier);
        match self.rocksdb_client.get(identifier.clone()) {
            Ok(Some(vec)) => {
                let final_val: Box<dyn Value> = serde_json::from_str(
                    String::from_utf8(vec)
                        .expect("Found invalid UTF-8")
                        .as_str()).expect("Invalid JSON");
                Ok(Option::from(final_val))
            },
            Ok(None) => {
                Ok(Option::from(None))
            }
            Err(err) => {
                Err(format!("Error retrieving {}: {}", identifier, err))
            }
        }
    }
    /// the granted function implements the logic of tx authorization. If no tx authorization is needed the function returns always true
    fn granted(&self, message: &str, customer_id: &str) -> Result<bool, String> {
        Ok(true)
    }
    async fn has_active_share(&self, _user_id: &str) -> Result<bool, String> {
        Ok(false)
    }
}