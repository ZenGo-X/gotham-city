// Gotham-city 
// 
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

trait AuthClient {
    fn connect(&self);
    fn get_user_id(&self) -> String;
}

pub mod cognito;
pub mod jwt;