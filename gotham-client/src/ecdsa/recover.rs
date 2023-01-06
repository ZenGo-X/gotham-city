// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use kms::ecdsa::two_party::{MasterKey1, MasterKey2};
use serde_json::Error;
use two_party_ecdsa::centipede::juggling::proof_system::Helgamalsegmented;
use two_party_ecdsa::centipede::juggling::segmentation::Msegmentation;
use two_party_ecdsa::curv::arithmetic::traits::{Converter, Modulo};
use two_party_ecdsa::curv::elliptic::curves::secp256_k1::{FE, GE};
use two_party_ecdsa::curv::elliptic::curves::traits::{ECPoint, ECScalar};
use two_party_ecdsa::curv::BigInt;
// iOS bindings
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ops::Deref;
//Android bindings
#[cfg(target_os = "android")]
use jni::{
    objects::{JClass, JString},
    strings::JavaStr,
    sys::{jint, jstring},
    JNIEnv,
};

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn decrypt_party_one_master_key(
    c_master_key_two_json: *const c_char,
    c_helgamal_segmented_json: *const c_char,
    c_private_key: *const c_char,
) -> *mut c_char {
    let segment_size = 8; // This is hardcoded on both client and server side

    let G: GE = GE::generator();

    let party_two_master_key: MasterKey2 =
        serde_json::from_str(&get_str_from_c_char(c_master_key_two_json)).unwrap();

    let encryptions_secret_party1: Helgamalsegmented =
        serde_json::from_str(&get_str_from_c_char(c_helgamal_segmented_json)).unwrap();

    let y_b: Result<BigInt, Error> = serde_json::from_str(&get_str_from_c_char(c_private_key));
    if y_b.is_err() {
        // Invalid BigInt Private key
        return CString::new("").unwrap().into_raw();
    }

    let y: FE = ECScalar::from(&y_b.unwrap());

    let r = Msegmentation::decrypt(&encryptions_secret_party1, &G, &y, &segment_size);

    if let Ok(v) = r {
        let party_one_master_key_recovered =
            party_two_master_key.counter_master_key_from_recovered_secret(v);

        let s = serde_json::to_string(&party_one_master_key_recovered).unwrap();
        CString::new(s).unwrap().into_raw()
    } else {
        CString::new("").unwrap().into_raw()
    }
}

#[no_mangle]
pub extern "C" fn get_child_mk1(
    c_master_key_one_json: *const c_char,
    c_x_pos: i32,
    c_y_pos: i32,
) -> *mut c_char {
    let party_one_master_key: MasterKey1 =
        serde_json::from_str(&get_str_from_c_char(c_master_key_one_json)).unwrap();

    let x: BigInt = BigInt::from(c_x_pos);

    let y: BigInt = BigInt::from(c_y_pos);

    let derived_mk1 = party_one_master_key.get_child(vec![x, y]);

    let derived_mk1_json = match serde_json::to_string(&derived_mk1) {
        Ok(share) => share,
        Err(_) => panic!("Error while get_child_mk1"),
    };

    CString::new(derived_mk1_json).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn get_child_mk2(
    c_master_key_two_json: *const c_char,
    c_x_pos: i32,
    c_y_pos: i32,
) -> *mut c_char {
    let party_two_master_key: MasterKey2 =
        serde_json::from_str(&get_str_from_c_char(c_master_key_two_json)).unwrap();

    let x: BigInt = BigInt::from(c_x_pos);

    let y: BigInt = BigInt::from(c_y_pos);

    let derived_mk2 = party_two_master_key.get_child(vec![x, y]);

    let derived_mk2_json = match serde_json::to_string(&derived_mk2) {
        Ok(share) => share,
        Err(_) => panic!("Error while get_child_mk1"),
    };

    CString::new(derived_mk2_json).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn construct_single_private_key(
    c_mk1_x1: *const c_char,
    c_mk2_x2: *const c_char,
) -> *mut c_char {
    let mk1_x1: BigInt = BigInt::from_hex(&get_str_from_c_char(c_mk1_x1));

    let mk2_x2: BigInt = BigInt::from_hex(&get_str_from_c_char(c_mk2_x2));

    let sk = BigInt::mod_mul(&mk1_x1, &mk2_x2, &FE::q());

    let sk_json = match serde_json::to_string(&sk) {
        Ok(share) => share,
        Err(_) => panic!("Error while construct_single_private_key"),
    };

    CString::new(sk_json).unwrap().into_raw()
}

fn get_str_from_c_char(c: *const c_char) -> String {
    let raw = unsafe { CStr::from_ptr(c) };
    let s = match raw.to_str() {
        Ok(s) => s,
        Err(_) => panic!("Error while decoding c_char to string"),
    };

    s.to_string()
}

//Android extern functions

#[cfg(target_os = "android")]
#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn Java_com_zengo_components_kms_gotham_ECDSA_decryptPartyOneMasterKey(
    env: JNIEnv,
    _class: JClass,
    j_master_key_two_json: JString,
    j_helgamal_segmented_json: JString,
    j_private_key: JString,
) -> jstring {
    let segment_size = 8; // This is hardcoded on both client and server side

    let G: GE = GE::generator();

    let master_key_two = match get_String_from_JString(&env, j_master_key_two_json) {
        Ok(s) => s,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in decryptPartyOneMasterKey: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };

    let party_two_master_key: MasterKey2 = serde_json::from_str(&master_key_two).unwrap();

    let helgamal_segmented = match get_String_from_JString(&env, j_helgamal_segmented_json) {
        Ok(s) => s,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in decryptPartyOneMasterKey: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };

    let encryptions_secret_party1: Helgamalsegmented =
        serde_json::from_str(&helgamal_segmented).unwrap();

    let private_key = match get_String_from_JString(&env, j_private_key) {
        Ok(s) => s.to_owned(),
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in decryptPartyOneMasterKey: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };

    let y_b: Result<BigInt, Error> = serde_json::from_str(&private_key);
    if y_b.is_err() {
        // Invalid BigInt Private key
        return env
            .new_string(format!("Error from Rust in decryptPartyOneMasterKey: "))
            .unwrap()
            .into_inner();
    }

    let y: FE = ECScalar::from(&y_b.unwrap());

    let r = Msegmentation::decrypt(&encryptions_secret_party1, &G, &y, &segment_size);

    if r.is_ok() {
        let party_one_master_key_recovered =
            party_two_master_key.counter_master_key_from_recovered_secret(r.unwrap().clone());

        let s = serde_json::to_string(&party_one_master_key_recovered).unwrap();
        return env.new_string(s).unwrap().into_inner();
    } else {
        return env
            .new_string(format!("Error from Rust in decryptPartyOneMasterKey: "))
            .unwrap()
            .into_inner();
    }
}

#[cfg(target_os = "android")]
#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn Java_com_zengo_components_kms_gotham_ECDSA_getChildMk2(
    env: JNIEnv,
    _class: JClass,
    j_master_key_two_json: JString,
    j_x_pos: jint,
    j_y_pos: jint,
) -> jstring {
    let master_key_two = match get_String_from_JString(&env, j_master_key_two_json) {
        Ok(s) => s,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in get_child_mk2: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };

    let party_two_master_key: MasterKey2 = serde_json::from_str(&master_key_two).unwrap();

    let x: BigInt = BigInt::from(j_x_pos);

    let y: BigInt = BigInt::from(j_y_pos);

    let derived_mk2 = party_two_master_key.get_child(vec![x, y]);

    let derived_mk2_json = match serde_json::to_string(&derived_mk2) {
        Ok(share) => share,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in get_child_mk2: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };

    env.new_string(derived_mk2_json).unwrap().into_inner()
}

#[cfg(target_os = "android")]
#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn Java_com_zengo_components_kms_gotham_ECDSA_getChildMk1(
    env: JNIEnv,
    _class: JClass,
    j_master_key_one_json: JString,
    j_x_pos: jint,
    j_y_pos: jint,
) -> jstring {
    let master_key_one = match get_String_from_JString(&env, j_master_key_one_json) {
        Ok(s) => s,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in get_child_mk1: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };

    let party_one_master_key: MasterKey1 = serde_json::from_str(&master_key_one).unwrap();

    let x: BigInt = BigInt::from(j_x_pos);

    let y: BigInt = BigInt::from(j_y_pos);

    let derived_mk1 = party_one_master_key.get_child(vec![x, y]);

    let derived_mk1_json = match serde_json::to_string(&derived_mk1) {
        Ok(share) => share,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in get_child_mk1: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };

    env.new_string(derived_mk1_json).unwrap().into_inner()
}

#[cfg(target_os = "android")]
#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn Java_com_zengo_components_kms_gotham_ECDSA_constructSinglePrivateKey(
    env: JNIEnv,
    _class: JClass,
    j_mk1_x1: JString,
    j_mk2_x2: JString,
) -> jstring {
    let mk1_x1_string = match get_String_from_JString(&env, j_mk1_x1) {
        Ok(s) => s,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in constructSinglePrivateKey: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };
    let mk2_x2_string = match get_String_from_JString(&env, j_mk2_x2) {
        Ok(s) => s,
        Err(e) => {
            return env
                .new_string(format!(
                    "Error from Rust in constructSinglePrivateKey: {}",
                    e.to_string()
                ))
                .unwrap()
                .into_inner()
        }
    };
    let mk1_x1 = BigInt::from_hex(&mk1_x1_string);
    let mk2_x2 = BigInt::from_hex(&mk2_x2_string);
    let sk = BigInt::mod_mul(&mk1_x1, &mk2_x2, &FE::q());

    let sk_json = match serde_json::to_string(&sk) {
        Ok(share) => share,
        Err(e) => format!(
            "Error from Rust in constructSinglePrivateKey: {}",
            e.to_string()
        ),
    };

    env.new_string(sk_json).unwrap().into_inner()
}

#[cfg(target_os = "android")]
#[allow(non_snake_case)]
fn get_String_from_JString(env: &JNIEnv, j_string: JString) -> Result<String, Error> {
    let java_str_string = match env.get_string(j_string) {
        Ok(java_string) => java_string,
        Err(e) => unimplemented!(),
    };

    let string_ref = match JavaStr::deref(&java_str_string).to_str() {
        Ok(string_ref) => string_ref,
        Err(e) => unimplemented!(),
    };

    Ok(string_ref.to_string())
}
