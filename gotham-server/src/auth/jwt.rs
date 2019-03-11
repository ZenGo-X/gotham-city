// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//
use super::super::jwt::{decode, decode_header, Algorithm, Header, Validation};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub fn get_claims(
    issuer: &String,
    audience: &String,
    token: &String,
    secret: &[u8],
    algorithms: Vec<Algorithm>,
) -> Result<Claims, ()> {
    let mut validation = Validation {
        iss: Some(issuer.to_string()),
        ..Validation::default()
    };

    validation.algorithms = algorithms;

    // Setting audience
    validation.set_audience(audience);

    let token_data = match decode::<Claims>(token, secret, &validation) {
        Ok(c) => c,
        Err(_) => return Err(()),
    };

    Ok(token_data.claims)
}

pub fn decode_header_from_token(token: String) -> Result<Header, ()> {
    let header = match decode_header(&token) {
        Ok(h) => h,
        Err(_) => return Err(()),
    };

    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::{decode_header_from_token, get_claims};
    use hex;
    use jwt::{Algorithm, Header};
    use std::str;

    #[test]
    #[should_panic] // Obviously hardcoded authorization_header become invalid
    fn get_claims_test() {
        let der_hex : &str = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100dd5a02e27e4d48e77fa7fba44de5963a4952850df2d89750408665ac9e814ca58d961348693c424cf884a5f44c377fced421ef3070eb974e7ec76fed861d9c4ff777aefcbb4a1c7396d35dde8feba2476dd42d3a38f73f2f4547d1b35e1cd9d3da9bf7341dc00bd543a97c890f5dfa2f2d800b5ecb44a2a679e8a5848123dd7a8087ec094c503b92dddd027e609e4f61caf5452344be6a401bf1b01a198967b526b13d9e9c2c0e6712e5b3359348135a48a936027d4c2a5c54b4d31eca1f94c00c02be82a91b4ef01498b58b652508110d06105c986750502e1b243fb69b05ad34e3eb1a86cc7cdaf69c4b29d3c00aa97a6055b293797017f1b59a998d2ade970203010001";

        let token: String = "eyJraWQiOiJZeEdoUlhsTytZSWpjU2xWZFdVUFA1dHhWd\
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
                             DaVVZgolenGlERVMfD5i0YWIM1j7GgQ1fuQ8J_LYiQ"
            .to_string();

        let der = hex::decode(der_hex).unwrap();
        let issuer: String = "issuer".to_string();
        let audience: String = "audience".to_string();
        let algorithms = vec![Algorithm::RS256];
        assert!(get_claims(&issuer, &audience, &token, der.as_ref(), algorithms).is_ok());
    }

    #[test]
    fn decode_token_test() {
        let token: String = "eyJraWQiOiJZeEdoUlhsTytZSWpjU2xWZFdVUFA1dHhWd\
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
                             DaVVZgolenGlERVMfD5i0YWIM1j7GgQ1fuQ8J_LYiQ"
            .to_string();

        let header: Header = decode_header_from_token(token).unwrap();
        assert_eq!(
            header.kid.unwrap(),
            "YxGhRXlO+YIjcSlVdWUPP5txVtTRM3fNwMe3xC5g/Xg="
        );
    }
}
