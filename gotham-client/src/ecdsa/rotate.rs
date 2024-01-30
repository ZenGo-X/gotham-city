// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use two_party_ecdsa::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use two_party_ecdsa::kms::ecdsa::two_party::MasterKey2;
use two_party_ecdsa::kms::ecdsa::two_party::party1::RotationParty1Message1;
use two_party_ecdsa::kms::rotation::two_party::party2::Rotation2;
use two_party_ecdsa::party_one;
use crate::{Client, ClientShim};
use crate::ecdsa::PrivateShare;

const ROT_PATH_PRE: &str = "ecdsa/rotate";

pub fn rotate_master_key<C: Client>(client_shim: &ClientShim<C>,
                                    master_key_2: &MasterKey2,
                                    id: &str) -> PrivateShare {
    let mut coin_flip_party1_first_message: Option<coin_flip_optimal_rounds::Party1FirstMessage> = None;
    let mut coin_flip_party2_first_message: Option<coin_flip_optimal_rounds::Party2FirstMessage> = None;

    let mut second_message: Option<(
        coin_flip_optimal_rounds::Party1SecondMessage,
        RotationParty1Message1,
    )> = None;

    // None values mean that the check_rotated_key_bounds of the server failed
    // and the second request needs to be repeated
    while second_message.is_none() {
        let coin_flip_party1_first_message_temp: coin_flip_optimal_rounds::Party1FirstMessage =
            client_shim.post(&format!("{}/{}/first", ROT_PATH_PRE, id)).unwrap();

        let coin_flip_party2_first_message_temp =
            Rotation2::key_rotate_first_message(&coin_flip_party1_first_message_temp);

        let body = &coin_flip_party2_first_message_temp;

        second_message = client_shim.postb(
            &format!("{}/{}/second", ROT_PATH_PRE, id),
            body,
        ).unwrap();
    }

    let (coin_flip_party1_second_message, rotation_party1_first_message) = second_message.unwrap();

    let random2 = Rotation2::key_rotate_second_message(
        &coin_flip_party1_second_message,
        &coin_flip_party2_first_message.unwrap(),
        &coin_flip_party1_first_message.unwrap()
    );

    let result_rotate_party_one_first_message =
        master_key_2.rotate_first_message(&random2, &rotation_party1_first_message);

    if result_rotate_party_one_first_message.is_err() {
        panic!("rotation failed");
    }

    let (rotation_party_two_first_message, party_two_pdl_chal, party_two_paillier) =
         result_rotate_party_one_first_message.unwrap();

    let body = &rotation_party_two_first_message;

    let rotation_party1_second_message: party_one::Party1PDLFirstMessage = client_shim.postb(
        &format!("{}/{}/third", ROT_PATH_PRE, id),
        body,
    ).unwrap();

    let rotation_party_two_second_message = MasterKey2::rotate_second_message(&party_two_pdl_chal);

    let body = &rotation_party_two_second_message;

    let rotation_party1_third_message: party_one::Party1PDLSecondMessage = client_shim.postb(
        &format!("{}/{}/fourth", ROT_PATH_PRE, id),
        body,
    )
    .unwrap();

    let result_rotate_party_one_third_message = master_key_2.rotate_third_message(
        &random2,
        &party_two_paillier,
        &party_two_pdl_chal,
        &rotation_party1_second_message,
        &rotation_party1_third_message,
    );

    if result_rotate_party_one_third_message.is_err() {
        panic!("rotation failed");
    }

    let rotated_mk = result_rotate_party_one_third_message.unwrap();

    PrivateShare { id : id.to_string(), master_key: rotated_mk }
}
