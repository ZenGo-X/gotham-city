use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use rocket_contrib::json::{Json};

#[get("/party1/first", format = "json")]
pub fn party1_first_message() -> Json<(
    party_one::KeyGenFirstMsg,
    party_one::CommWitness,
    party_one::EcKeyPair)>
{
    Json(MasterKey1::key_gen_first_message())
}