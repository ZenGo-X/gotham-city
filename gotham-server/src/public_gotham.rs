//!Public gotham implementation

use rocket::async_trait;
use std::collections::HashMap;
use std::string::String;

use two_party_ecdsa::party_one::v;
use two_party_ecdsa::typetags::Value;

use gotham_engine::keygen::KeyGen;
use gotham_engine::sign::Sign;
use gotham_engine::traits::*;
use gotham_engine::types::*;

pub struct PublicGotham {
    rocksdb_client: rocksdb::DB,
}
pub struct Authorizer {}

fn get_settings_as_map() -> HashMap<String, String> {
    let config_file = include_str!("../Settings.toml");
    let mut settings = config::Config::default();
    settings
        .merge(config::File::from_str(
            config_file,
            config::FileFormat::Toml,
        ))
        .unwrap()
        .merge(config::Environment::new())
        .unwrap();

    settings.try_into::<HashMap<String, String>>().unwrap()
}

impl PublicGotham {
    pub fn new() -> Self {
        let settings = get_settings_as_map();
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
    ) -> Result<(), DatabaseError> {
        let identifier = idify(key.clone().customerId, key.clone().id, table_name);
        let v_string = serde_json::to_string(&value).unwrap();
        let _ = self.rocksdb_client.put(identifier, v_string.clone());
        Ok(())
    }

    async fn get(
        &self,
        key: &DbIndex,
        table_name: &dyn MPCStruct,
    ) -> Result<Option<Box<dyn Value>>, DatabaseError> {
        let identifier = idify(key.clone().customerId, key.clone().id, table_name);
        println!("Getting from db ({})", identifier);
        let result = self.rocksdb_client.get(identifier.clone()).unwrap();
        let vec_option: Option<Vec<u8>> = result.map(|v| v.to_vec());
        match vec_option {
            Some(vec) => {
                let final_val: Box<dyn Value> = serde_json::from_str(
                    String::from_utf8(vec.clone())
                        .expect("Found invalid UTF-8")
                        .as_str(),
                )
                .unwrap();
                Ok(Option::from(final_val))
            }
            None => {
                println! {"ok none"}
                let value = v {
                    value: "false".parse().unwrap(),
                };
                let final_val: Box<dyn Value> = Box::new(value);
                Ok(Option::from(final_val))
            }
        }
    }
    /// the granted function implements the logic of tx authorization. If no tx authorization is needed the function returns always true
    fn granted(&self, message: &str, customer_id: &str) -> Result<bool, DatabaseError> {
        Ok(true)
    }
    async fn has_active_share(&self, _user_id: &str) -> Result<bool, String> {
        Ok(false)
    }
}
