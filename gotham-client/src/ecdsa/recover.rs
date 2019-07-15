// Gotham-city 
// 
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use curv::{FE, BigInt, GE};
use kms::ecdsa::two_party::{MasterKey1, MasterKey2};
use serde_json;
use centipede::juggling::segmentation::Msegmentation;
use centipede::juggling::proof_system::Helgamalsegmented;
use curv::elliptic::curves::traits::{ECScalar, ECPoint};
use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Converter;
use serde_json::Error;
// iOS bindings
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn decrypt_party_one_master_key(
    c_master_key_two_json: *const c_char,
    c_helgamal_segmented_json: *const c_char,
    c_private_key: *const c_char
) -> *mut c_char {
    let segment_size = 8; // This is hardcoded on both client and server side

    let G: GE = GE::generator();

    let party_two_master_key: MasterKey2 = serde_json::from_str(
        &get_str_from_c_char(c_master_key_two_json)).unwrap();

    let encryptions_secret_party1 : Helgamalsegmented = serde_json::from_str(
        &get_str_from_c_char(c_helgamal_segmented_json)).unwrap();

    let y_b : Result<BigInt, Error> = serde_json::from_str(&get_str_from_c_char(c_private_key));
    if y_b.is_err() {
        // Invalid BigInt Private key
        return CString::new("").unwrap().into_raw();
    }

    let y: FE = ECScalar::from(&y_b.unwrap());

    let r = Msegmentation::decrypt(
        &encryptions_secret_party1, &G, &y, &segment_size);

    if r.is_ok() {
        let party_one_master_key_recovered = party_two_master_key
            .counter_master_key_from_recovered_secret(r.unwrap().clone());

        let s = serde_json::to_string(&party_one_master_key_recovered).unwrap();
        return CString::new(s).unwrap().into_raw();
    } else {
        return CString::new("").unwrap().into_raw();
    }
}

#[no_mangle]
pub extern "C" fn get_child_mk1(
    c_master_key_one_json: *const c_char,
    c_x_pos: i32,
    c_y_pos: i32
) -> *mut c_char {
    let party_one_master_key: MasterKey1 = serde_json::from_str(
        &get_str_from_c_char(c_master_key_one_json)).unwrap();

    let x: BigInt = BigInt::from(c_x_pos);

    let y: BigInt = BigInt::from(c_y_pos);

    let derived_mk1 = party_one_master_key.get_child(vec![x, y]);

    let derived_mk1_json = match serde_json::to_string(&derived_mk1) {
        Ok(share) => share,
        Err(_) => panic!("Error while get_child_mk1"),
    };

    CString::new(derived_mk1_json.to_owned()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn get_child_mk2(
    c_master_key_two_json: *const c_char,
    c_x_pos: i32,
    c_y_pos: i32
) -> *mut c_char {
    let party_two_master_key: MasterKey2 = serde_json::from_str(
        &get_str_from_c_char(c_master_key_two_json)).unwrap();

    let x: BigInt = BigInt::from(c_x_pos);

    let y: BigInt = BigInt::from(c_y_pos);

    let derived_mk2 = party_two_master_key.get_child(vec![x, y]);

    let derived_mk2_json = match serde_json::to_string(&derived_mk2) {
        Ok(share) => share,
        Err(_) => panic!("Error while get_child_mk1"),
    };

    CString::new(derived_mk2_json.to_owned()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn construct_single_private_key(
    c_mk1_x1: *const c_char,
    c_mk2_x2: *const c_char
) -> *mut c_char {
    let mk1_x1: BigInt = BigInt::from_hex(&get_str_from_c_char(c_mk1_x1));

    let mk2_x2: BigInt =  BigInt::from_hex(&get_str_from_c_char(c_mk2_x2));

    let sk = BigInt::mod_mul(&mk1_x1, &mk2_x2, &FE::q());

    let sk_json = match serde_json::to_string(&sk) {
        Ok(share) => share,
        Err(_) => panic!("Error while construct_single_private_key"),
    };

    CString::new(sk_json.to_owned()).unwrap().into_raw()
}

fn get_str_from_c_char(c: *const c_char) -> String {
    let raw = unsafe { CStr::from_ptr(c) };
    let s = match raw.to_str() {
        Ok(s) => s,
        Err(_) => panic!("Error while decoding c_char to string"),
    };

    s.to_string()
}