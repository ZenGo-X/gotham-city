// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use super::jwt::Claims;

pub fn get_empty_claim() -> Claims {
    Claims {
        sub: "pass_through_guest_user".to_string(),
        exp: 0,
    }
}
