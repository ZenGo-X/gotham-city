pub mod dynamodb;
#[allow(deprecated)]
pub mod error;

#[derive(Debug, Serialize, Deserialize)]
pub struct AWSError {
    #[serde(rename = "__type")]
    pub typ: String,
    pub message: String,
}
