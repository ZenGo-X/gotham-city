use std::thread;
use std::time::Duration;
use std::default::Default;
use serde_json;
use serde;
use rusoto_dynamodb::*;
use super::error::*;
use super::*;
use std::string::*;
use std::collections::HashMap;
use failure;
use std;

#[derive(Serialize, Deserialize)]
struct DBItem<T> {
    id: String,
    v: T,
}

pub fn insert<T>(dynamodb_client: &DynamoDbClient, id: &str, table_name: &str, v: T)
    -> std::result::Result<PutItemOutput, failure::Error> where T: serde::ser::Serialize {
    let wrapper_item = DBItem {id: id.to_string(), v};
    let item = serde_dynamodb::to_hashmap(&wrapper_item).unwrap();
    let put_item_input = PutItemInput {
        item: item,
        table_name: table_name.to_string(),
        ..Default::default()
    };
    // Put item
    dynamodb_client.put_item(put_item_input)
        .sync()
        .map_err(|e| format_err!("DynamoDB error while inserting item: {}", e))
}

pub fn get<'a, T>(dynamodb_client: &rusoto_dynamodb::DynamoDbClient, id: &str, table_name: String)
    -> std::result::Result<Option<T>, failure::Error> where T: serde::de::Deserialize<'a> {
    let mut query_key: HashMap<String, AttributeValue> = HashMap::new();
    query_key.insert(
        "id".to_string(),
        AttributeValue {
            s: Some(id.to_string()),
            ..Default::default()
        },
    );
    let query_item = GetItemInput {
        key: query_key,
        table_name: table_name.to_string(),
        ..Default::default()
    };

    match dynamodb_client.get_item(query_item).sync() {
        Ok(item_from_dynamo) => {
            match item_from_dynamo.item {
                None => {
                    info!("nothing received from Dynamo, item may not exist");
                    Ok(None)
                },
                Some(attributes_map) => {
                    let raw_item: serde_dynamodb::error::Result<DBItem<T>> = serde_dynamodb::from_hashmap(attributes_map);
                    match raw_item {
                        Ok(s) => {
                            Ok(Some(s.v))
                        },
                        Err(_e) => {
                            Ok(None)
                        }
                    }
                },
            }
        },
        Err(err) => {
            info!("Error retrieving object: {:?}", err);
            Err(failure::err_msg(format!("{:?}", err)))
        }
    }
}

pub fn list_tables(client: &DynamoDbClient) ->Result<Vec<String>> {
    let list_tables_input: ListTablesInput = Default::default();

    let result = client.list_tables(list_tables_input).sync();

    if let Ok(output) = result {
        Ok(output.table_names.unwrap())
    } else {
        Ok(vec![])
    }
}

pub fn wait_for_table(client: &DynamoDbClient, name: &str) -> Result<TableDescription> {
    loop {
        let table_desc = describe_table(client, name)?;

        match table_desc.table_status.as_ref().map(|s| &s[..]) {
            Some("ACTIVE") => {
                info!("table {} state ACTIVE", name);
                return Ok(table_desc);
            },
            Some(_) => {
                info!("table {} state {}", name, table_desc.table_status.unwrap());
            },
            None => {
                info!("table {} no state available", name);
            }
        }

        thread::sleep(Duration::from_secs(1));
    }
}

pub fn create_table_if_needed(client: &DynamoDbClient, name: &str, read_capacity: i64, write_capacity: i64) -> Result<TableDescription> {
    loop {
        match describe_table(client, name).map_err(Error::from) {
            Err(Error(ErrorKind::TableNotFound(_), _)) => {
                info!("table {} not found. creating..", name);
            },
            Err(e) => {
                bail!(e);
            },
            Ok(table) => {
                return Ok(table);
            }
        }


        info!("Continuing to create...");
        match create_table(client, name, read_capacity, write_capacity) {
            Err(Error(ErrorKind::TableAlreadyExists(_), _)) => {
                info!("table {} already exists. getting info..", name);
            },
            Err(e) => {
                bail!(e);
            },
            Ok(()) => {
                // pass
            }
        }
    }
}

pub fn describe_table(client: &DynamoDbClient, name: &str) -> Result<TableDescription> {
    let describe_table_input = DescribeTableInput {
        table_name: name.to_owned(),
        ..Default::default()
    };

    match client.describe_table(describe_table_input).sync() {
        Err(DescribeTableError::ResourceNotFound(s)) => {
            if s.starts_with("Requested resource not found: Table:") {
                bail!(ErrorKind::TableNotFound(name.to_string()))
            }

            bail!(ErrorKind::DescribeTable(DescribeTableError::ResourceNotFound(s)))
        },
        Err(e) => {
            bail!(ErrorKind::DescribeTable(e))
        },
        Ok(table) => {
            if let Some(table_desc) = table.table {
                info!("table created at {:?}", table_desc.creation_date_time);
                Ok(table_desc)
            } else {
                bail!(ErrorKind::NoTableInfo)
            }
        }
    }
}

#[macro_export]
macro_rules! attributes {
    ($($val:expr => $attr_type:expr),*) => {
        {
            let mut temp_vec = Vec::new();
            $(
                temp_vec.push(AttributeDefinition { attribute_name: String::from($val), attribute_type: String::from($attr_type) });
            )*
            temp_vec
        }
    }
}

#[macro_export]
macro_rules! key_schema {
    ($($name:expr => $key_type:expr),*) => {
        {
            let mut temp_vec = Vec::new();
            $(
                temp_vec.push(KeySchemaElement { key_type: String::from($key_type), attribute_name: String::from($name) });
            )*
            temp_vec
        }
    }
}

pub fn create_table(client: &DynamoDbClient, name: &str, read_capacity: i64, write_capacity: i64) -> Result<()> {
    let create_table_input = CreateTableInput {
        table_name: name.to_string(),
        attribute_definitions: attributes!("id" => "S"),
        key_schema: key_schema!("id" => "HASH"),
        provisioned_throughput: ProvisionedThroughput {
            read_capacity_units: read_capacity,
            write_capacity_units: write_capacity,
        },
        ..Default::default()
    };

    match client.create_table(create_table_input).sync() {
        Err(CreateTableError::ResourceInUse(s)) => {
            let maybe_value = serde_json::from_str::<AWSError>(&s);

            if let Ok(value) = maybe_value {
                if value.message.starts_with("Table already exists:") {
                    bail!(ErrorKind::TableAlreadyExists(name.to_string()))
                }
            }

            bail!(ErrorKind::CreateTable(CreateTableError::ResourceInUse(s)))
        },
        Err(e) => {
            bail!(ErrorKind::CreateTable(e))
        },
        Ok(table) => {
            if let Some(table_desc) = table.table_description {
                info!("table created at {:?}", table_desc.creation_date_time);
                Ok(())
            } else {
                bail!(ErrorKind::NoTableInfo)
            }
        }
    }
}