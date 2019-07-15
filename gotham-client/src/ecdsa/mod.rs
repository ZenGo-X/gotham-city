// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//
pub mod keygen;
pub mod rotate;
pub mod sign;
pub mod types;
pub mod recover;

pub use keygen::get_master_key;
pub use rotate::rotate_master_key;
pub use sign::sign;
pub use types::PrivateShare;