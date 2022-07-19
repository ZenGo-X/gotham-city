use serde::{Deserialize, Serialize};
pub mod dynamodb;

#[derive(Debug, Serialize, Deserialize)]
pub struct AWSError {
    #[serde(rename = "__type")]
    pub typ: String,
    pub message: String,
}
