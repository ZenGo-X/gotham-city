use curv::BigInt;
use kms::ecdsa::two_party::party2;
use kms::ecdsa::two_party::MasterKey2;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two;

use super::super::utilities::requests;
use super::super::utilities::error_to_c_string;
use super::super::Result;
use super::super::ClientShim;

// iOS bindings
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two::Party2Private;
use kms::ecdsa::two_party::MasterKey1;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one::Party1Private;
use curv::elliptic::curves::secp256_k1::FE;
use curv::arithmetic::traits::Modulo;
use crate::curv::elliptic::curves::traits::ECScalar;


#[derive(Serialize, Deserialize)]
pub struct Party2PrivateLocal {
    pub x2: FE,
}

/// Private decryption key.
#[derive(Clone, Debug, PartialEq,  Serialize, Deserialize,)]
pub struct DecryptionKey {
    pub p: BigInt, // first prime
    pub q: BigInt, // second prime
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Party1PrivateLocal {
    pub x1: FE,
    paillier_priv: DecryptionKey,
    c_key_randomness: BigInt,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LocationXY {
    pub x_pos: BigInt,
    pub y_pos: BigInt,
}

pub fn get_secret_at_location(
    client_shim: &ClientShim,
    mk: MasterKey2,
    x_pos: BigInt,
    y_pos: BigInt,
    id: &String,
) -> Result<BigInt> {

    let location = LocationXY{
        x_pos,
        y_pos,
    };

    let request: LocationXY = location;
    let party_one_secret: MasterKey1 =
        match requests::postb(client_shim, &format!("/ecdsa/get_secret/{}/first", id), &request) {
            Some(s) => s,
            None => return Err(failure::err_msg("party1 get secret request failed"))
        };



    let party_2_secret = unsafe { std::mem::transmute::<Party2Private, Party2PrivateLocal>(mk.private) };
    let party_1_secret = unsafe { std::mem::transmute::<Party1Private, Party1PrivateLocal>(party_one_secret.private) };


    let x2 = party_2_secret.x2;
    let x1 = party_1_secret.x1;
    let x = x1 * x2;

    Ok(x.to_big_int())
}
