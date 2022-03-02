use failure;
use rusoto_dynamodb::*;
use serde;
use std;
use std::collections::HashMap;
use std::default::Default;
use std::string::*;

const CUSTOMER_ID_IDENTIFIER: &str = "customerId";
const ID_IDENTIFIER: &str = "id";

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[allow(non_snake_case)]
struct DBItemIdentifier {
    customerId: String,
    id: String,
}

pub async fn insert<T>(
    dynamodb_client: &DynamoDbClient,
    user_id: &str,
    id: &str,
    table_name: &str,
    v: T,
) -> std::result::Result<PutItemOutput, failure::Error>
where
    T: serde::ser::Serialize,
{
    let identifier = DBItemIdentifier {
        customerId: user_id.to_string(),
        id: id.to_string(),
    };
    println!("identifier = {:?}", identifier);

    let mut item = serde_dynamodb::to_hashmap(&identifier).unwrap();
    println!("item #1 = {:?}", item);
    item.extend(serde_dynamodb::to_hashmap(&v).unwrap());
    println!("item #2 = {:?}", item);

    let put_item_input = PutItemInput {
        item,
        table_name: table_name.to_string(),
        ..Default::default()
    };

    // Put item
    dynamodb_client
        .put_item(put_item_input)
        .await
        .map_err(|e| format_err!("DynamoDB error while inserting item: {}", e))
}

pub async fn get<'a, T>(
    dynamodb_client: &rusoto_dynamodb::DynamoDbClient,
    user_id: &str,
    id: &str,
    table_name: String,
    require_customer_id: bool,
) -> std::result::Result<Option<T>, failure::Error>
where
    T: serde::de::Deserialize<'a>,
{
    let mut query_key: HashMap<String, AttributeValue> = HashMap::new();

    if require_customer_id {
        query_key.insert(
            "customerId".to_string(),
            AttributeValue {
                s: Some(user_id.to_string()),
                ..Default::default()
            },
        );
    }

    query_key.insert(
        "id".to_string(),
        AttributeValue {
            s: Some(id.to_string()),
            ..Default::default()
        },
    );

    println!("Querying table {}, key: {:?}", table_name, query_key);

    let query_item = GetItemInput {
        key: query_key,
        table_name: table_name.to_string(),
        ..Default::default()
    };

    match dynamodb_client.get_item(query_item).await {
        Ok(item_from_dynamo) => match item_from_dynamo.item {
            None => {
                println!("nothing received from Dynamo, item may not exist");
                Ok(None)
            }
            Some(mut attributes_map) => {
                // This is not the best we can do but if you look at the DBItemIdentifier above
                // we augment it with the ser/de of the actual object, so we remove extra fields
                // here. TODO: Is there something cleaner?
                println!("#1");
                attributes_map.remove(CUSTOMER_ID_IDENTIFIER);
                attributes_map.remove(ID_IDENTIFIER);
                println!("#2, attributes_map = {:?}", attributes_map);

                let raw_item: serde_dynamodb::error::Result<T> =
                    serde_dynamodb::from_hashmap(attributes_map);
                println!("#3");

                match raw_item {
                    Ok(s) => {
                        println!("#4");
                        Ok(Some(s))
                    }
                    Err(_e) => {
                        println!("#5, {}", _e);
                        Ok(None)
                    }
                }
            }
        },
        Err(err) => {
            println!("Error retrieving object: {:?}", err);
            Err(failure::err_msg(format!("{:?}", err)))
        }
    }
}

#[macro_export]
macro_rules! attributes {
    ($($val:expr => $attr_type:expr),*) => {
        {
            $(
                let temp_vec = vec![AttributeDefinition { attribute_name: String::from($val), attribute_type: String::from($attr_type) }];
            )*
            temp_vec
        }
    }
}

#[macro_export]
macro_rules! key_schema {
    ($($name:expr => $key_type:expr),*) => {
        {
            $(
                let temp_vec = vec![(KeySchemaElement { key_type: String::from($key_type), attribute_name: String::from($name) })];
            )*
            temp_vec
        }
    }
}
