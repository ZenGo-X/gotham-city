// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use std::ffi::CString;
use std::os::raw::c_char;

pub mod requests;

pub fn error_to_c_string(e: failure::Error) -> *mut c_char {
    CString::new(format!("Error: {}", e.to_string())).unwrap().into_raw()
}
