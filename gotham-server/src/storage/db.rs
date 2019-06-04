// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//
use super::super::Result;
use super::super::routes::ecdsa;
use rocksdb;
use serde;

use super::aws;

pub enum DB {
    Local(rocksdb::DB),
    AWS(rusoto_dynamodb::DynamoDbClient, String),
}

fn idify(user_id: &str, id: &str, name: &ToString) -> String {
    format!("{}_{}_{}", user_id, id, name.to_string())
}

pub fn insert<T>(db: &DB, user_id: &str, id: &str, name: &ToString, v: T) -> Result<()>
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

pub fn get<T>(db: &DB, user_id: &str, id: &str, name: &ToString) -> Result<Option<T>>
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
    if !name.contains(&ecdsa::EcdsaStruct::Party1MasterKey.to_string()) {
        return format!("{}-gotham-{}", env, name);
    }

    // This is ugly, TODO: handle this properly in a configuration (when or not to use 'gotham' in the table name)
    return format!("{}_{}", env, name);
}
