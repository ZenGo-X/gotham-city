// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use super::super::routes::ecdsa;
use super::super::Result;
use rocksdb;
use serde;

use super::aws;

pub enum DB {
    Local(rocksdb::DB),
    AWS(rusoto_dynamodb::DynamoDbClient, String),
}

fn idify(user_id: &str, id: &str, name: &ecdsa::Share) -> String {
    format!("{}_{}_{}", user_id, id, name.to_string())
}

pub fn init(db: &DB) -> Result<()> {
    match db {
        DB::AWS(_dynamodb_client, _env) => {
            // !!! Keep this code commented unless you are willing to risk an implicit table
            // creation which can lead to data corruption. This needs disciplines and tables
            // Schema would better live in a cloud formation !!!

            /*
            println!("Creating tables if necessary...");
            for share_field in ecdsa::Share::iterator() {
                let name = format!("{}", share_field.to_string());
                let table_name = calculate_table_name(&name.to_string(), &env);

                match aws::dynamodb::create_table_if_needed(&dynamodb_client, &table_name, 1, 1) {
                    Err(e) => return Err(format_err!("{}", e)),
                    _ => {}
                };
                match aws::dynamodb::wait_for_table(&dynamodb_client, &table_name) {
                    Err(e) => return Err(format_err!("{}", e)),
                    _ => {}
                }
            }
            */
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn insert<T>(db: &DB, user_id: &str, id: &str, name: &ecdsa::Share, v: T) -> Result<()>
where
    T: serde::ser::Serialize,
{
    match db {
        DB::AWS(dynamodb_client, env) => {
            let table_name = calculate_table_name(&name.to_string(), &env);
            aws::dynamodb::insert(&dynamodb_client, user_id, id, &table_name, v)?;
            Ok(())
        }
        DB::Local(rocksdb_client) => {
            let identifier = idify(user_id, id, name);
            let v_string = serde_json::to_string(&v).unwrap();
            rocksdb_client.put(identifier.as_ref(), v_string.as_ref())?;
            Ok(())
        }
    }
}

pub fn get<T>(db: &DB, user_id: &str, id: &str, name: &ecdsa::Share) -> Result<Option<T>>
where
    T: serde::de::DeserializeOwned,
{
    match db {
        DB::AWS(dynamodb_client, env) => {
            let table_name = calculate_table_name(&name.to_string(), &env);
            let res: Option<T> = aws::dynamodb::get(&dynamodb_client, user_id, id, table_name)?;
            Ok(res)
        }
        DB::Local(rocksdb_client) => {
            let identifier = idify(user_id, id, name);
            info!("Getting from db ({})", identifier);

            let db_option = rocksdb_client.get(identifier.as_ref())?;
            let vec_option: Option<Vec<u8>> = db_option.map(|v| v.to_vec());
            match vec_option {
                Some(vec) => Ok(serde_json::from_slice(&vec).unwrap()),
                None => Ok(None),
            }
        }
    }
}

fn calculate_table_name(name: &str, env: &str) -> String {
    if !name.contains(&ecdsa::Share::Party1MasterKey.to_string()) {
        return format!("{}-gotham-{}", env, name);
    }

    // This is ugly, TODO: handle this properly in a configuration (when or not to use 'gotham' in the table name)
    return format!("{}_{}", env, name);
}
