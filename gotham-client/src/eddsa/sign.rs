// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use super::super::utilities::requests;
use super::super::Result;
use super::super::ClientShim;

use multi_party_ed25519::protocols::aggsig::*;

#[allow(non_snake_case)]
pub fn sign(
    client_shim: &ClientShim,
    message: BigInt,
    party2_key_pair: &KeyPair,
    key_agg: &KeyAgg,
    id: &String
) -> Result<Signature> {
    // round 1: send commitments to ephemeral public keys
    let (party2_ephemeral_key, party2_sign_first_msg, party2_sign_second_msg) =
        Signature::create_ephemeral_key_and_commit(&party2_key_pair, BigInt::to_vec(&message).as_slice());

    let party1_sign_first_msg: SignFirstMsg = requests::postb(
        client_shim,
        &format!("eddsa/sign/{}/first", id),
        &(party2_sign_first_msg, message.clone()))
        .unwrap();

    // round 2: send ephemeral public keys and check commitments.
    // in the two-party setting, the counterparty can immediately return its local signature.
    let (mut party1_sign_second_msg, mut s1): (SignSecondMsg, Signature) = requests::postb(
        client_shim,
        &format!("eddsa/sign/{}/second", id),
        &party2_sign_second_msg)
        .unwrap();
    let eight: FE = ECScalar::from(&BigInt::from(8));
    let eight_inverse: FE = eight.invert();
    party1_sign_second_msg.R = party1_sign_second_msg.R * &eight_inverse;
    s1.R = s1.R * &eight_inverse;
    assert!(test_com(
        &party1_sign_second_msg.R,
        &party1_sign_second_msg.blind_factor,
        &party1_sign_first_msg.commitment
    ));

    // round 3:
    // compute R' = sum(Ri):
    let mut Ri: Vec<GE> = Vec::new();
    Ri.push(party1_sign_second_msg.R.clone());
    Ri.push(party2_sign_second_msg.R.clone());
    // each party i should run this:
    let R_tot = Signature::get_R_tot(Ri);
    let k = Signature::k(&R_tot, &key_agg.apk, BigInt::to_vec(&message).as_slice());
    let s2 = Signature::partial_sign(
        &party2_ephemeral_key.r,
        &party2_key_pair,
        &k,
        &key_agg.hash,
        &R_tot,
    );

    let mut s: Vec<Signature> = Vec::new();
    s.push(s1);
    s.push(s2);
    let signature = Signature::add_signature_parts(s);

    // verify:
    verify(&signature, BigInt::to_vec(&message).as_slice(), &key_agg.apk)
        .or_else(|e| Err(format_err!("{}", e)))
        .and_then(|_| Ok(signature))
}
