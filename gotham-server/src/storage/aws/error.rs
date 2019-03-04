use rusoto_dynamodb;
use serde_json;
use std::num;

error_chain! {
    foreign_links {
        DescribeTable(rusoto_dynamodb::DescribeTableError);
        ListTables(rusoto_dynamodb::ListTablesError);
        CreateTable(rusoto_dynamodb::CreateTableError);
        GetItem(rusoto_dynamodb::GetItemError);
        PutItem(rusoto_dynamodb::PutItemError);
        DeleteItem(rusoto_dynamodb::DeleteItemError);
        ParseError(num::ParseIntError);
        Json(serde_json::Error);
    }

    errors {
        NoTableInfo {
            description("no table info returned")
            display("no table info returned")
        }

        TableAlreadyExists(t: String) {
            description("table already exists")
            display("table already exists: {}", t)
        }

        TableNotFound(t: String) {
            description("table not found")
            display("table not found: {}", t)
        }

        ConditionalUpdateFailed {
            description("conditional update failed")
            display("conditional update failed")
        }

        MissingAttribute {
            description("missing attribute")
            display("missing attribute")
        }
    }
}
