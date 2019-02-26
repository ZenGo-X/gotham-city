// Gotham-city 
// 
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use jwt::Algorithm;
use super::jwt::{Claims, get_claims, decode_token};
use std::collections::HashMap;
use serde_json;
use hex;

const ALGORITHM : Algorithm = Algorithm::RS256;
const TOKEN_TYPE : &str = "Bearer";

#[derive(Debug, Serialize, Deserialize)]
pub struct CognitoPubKey {
    pub kid: String,
    pub pem: String,
    pub der: String,
    pub alg: String,
    pub kty: String
}

pub struct CognitoClient  {
    pub issuer: String,
    pub audience: String,
    pub region: String,
    pub poolid: String
}

impl CognitoClient {
    pub fn new(issuer: String, audience: String, region: String, poolid: String) -> CognitoClient {
        CognitoClient { issuer, audience, region, poolid }
    }

    pub fn get_user_id(&self, authorization_header: &String, key_set: &HashMap<String, CognitoPubKey>) -> String {
        let mut header_parts = authorization_header.split_whitespace();
        let token_type = header_parts.next();
        assert_eq!(token_type, Some(TOKEN_TYPE));

        let token = header_parts.next().unwrap();
        let header = decode_token(token.to_string());
        let key = key_set.get(&header.kid.unwrap()).unwrap();
        let secret = hex::decode(&key.der).unwrap();
        let algorithms : Vec<Algorithm> = vec![ ALGORITHM ];

        let claims : Claims = get_claims(&self.issuer, &self.audience, &token.to_string(), &secret, algorithms);

        claims.sub
    }

    pub fn get_key_set() -> HashMap<String, CognitoPubKey> {
        // node jwt-to-pems.js --region=us-west-2 --poolid=us-west-2_g9jSlEaCG
        let key_set_json = "";
        let key_set : HashMap<String, CognitoPubKey> = serde_json::from_str(key_set_json).unwrap();

        key_set
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use serde_json;
    use std::fs;

    const KEY_SET_JSON_FILENAME: &str = "test-data/key-set.json";

    #[test]
    pub fn get_user_id_test() {
        let region : String = "us-west-2".to_string();
        let poolid : String = "us-west-2_g9jSlEaCG".to_string();
        let issuer : String = "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_g9jSlEaCG".to_string();
        let audience : String = "4pmciu1ahrf5svmgm1hm5elbup".to_string();

        let cognito_client = CognitoClient::new(issuer, audience, region, poolid);

        let authorization_header = "Bearer eyJraWQiOiJZeEdoUlhsTytZSWpjU2xWZFdVUFA1dHhWd\
        FRSTTNmTndNZTN4QzVnXC9YZz0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjNDAz\
        ZTBlNy1jM2QwLTRhNDUtODI2Mi01MTM5OTIyZjc5NTgiLCJhdWQiOiI0cG1jaXUx\
        YWhyZjVzdm1nbTFobTVlbGJ1cCIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJjdXN0\
        b206ZGV2aWNlUEsiOiJbXCItLS0tLUJFR0lOIFBVQkxJQyBLRVktLS0tLVxcbk1G\
        a3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUdDNmQ1SnV6OUNPUVVZ\
        K08rUUV5Z0xGaGxSOHpcXHJsVjRRTTV1ZUhsQjVOTVQ2dm04c1dFMWtpak5udnpP\
        WDl0cFRZUEVpTEIzbHZORWNuUmszTXRRZVNRPT1cXG4tLS0tLUVORCBQVUJMSUMg\
        S0VZLS0tLS1cIl0iLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTU0NjUz\
        MzM2NywiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLXdlc3QtMi5hbWF6\
        b25hd3MuY29tXC91cy13ZXN0LTJfZzlqU2xFYUNHIiwiY29nbml0bzp1c2VybmFt\
        ZSI6ImM0MDNlMGU3LWMzZDAtNGE0NS04MjYyLTUxMzk5MjJmNzk1OCIsImV4cCI6\
        MTU0NzEwNzI0OSwiaWF0IjoxNTQ3MTAzNjQ5LCJlbWFpbCI6ImdhcnkrNzgyODJA\
        a3plbmNvcnAuY29tIn0.WLo9fiDiovRqC1RjR959aD8O1E3lqi5Iwnsq4zobqPU5\
        yZHW2FFIDwnEGf3UmQWMLgscKcuy0-NoupMUCbTvG52n5sPvOrCyeIpY5RkOk3mH\
        enH3H6jcNRA7UhDQwhMu_95du3I1YHOA173sPqQQvmWwYbA8TtyNAKOq9k0QEOuq\
        PWRBXldmmp9pxivbEYixWaIRtsJxpK02ODtOUR67o4RVeVLfthQMR4wiANO_hKLH\
        rt76DEkAntM0KIFODS6o6PBZw2IP4P7x21IgcDrTO3yotcc-RVEq0X1N3wI8clr8\
        DaVVZgolenGlERVMfD5i0YWIM1j7GgQ1fuQ8J_LYiQ".to_string();


        let key_set_json = fs::read_to_string(KEY_SET_JSON_FILENAME).expect("Unable to load wallet!");;
        let key_set : HashMap<String, CognitoPubKey> = serde_json::from_str(&key_set_json).unwrap();

        cognito_client.get_user_id(&authorization_header, &key_set);
    }
}