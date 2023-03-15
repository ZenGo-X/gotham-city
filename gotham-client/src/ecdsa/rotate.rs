// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//
use super::types::PrivateShare;
use super::super::wallet;
use super::super::ClientShim;
use two_party_ecdsa::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
use kms::ecdsa::two_party::MasterKey2;
use kms::ecdsa::two_party::*;
use two_party_ecdsa::*;
use std::collections::HashMap;
use two_party_ecdsa::party_one;
use crate::Client;

const ROT_PATH_PRE: &str = "ecdsa/rotate";

pub fn rotate_master_key<C: Client>(wallet: wallet::Wallet, client_shim: &ClientShim<C>) -> wallet::Wallet {
    let id = &wallet.private_share.id.clone();
    let coin_flip_party1_first_message: coin_flip_optimal_rounds::Party1FirstMessage =
        client_shim.post(&format!("{}/{}/first", ROT_PATH_PRE, id)).unwrap();

    let coin_flip_party2_first_message =
        Rotation2::key_rotate_first_message(&coin_flip_party1_first_message);

    let body = &coin_flip_party2_first_message;

    let (coin_flip_party1_second_message, rotation_party1_first_message): (
        coin_flip_optimal_rounds::Party1SecondMessage,
        party1::RotationParty1Message1,
    ) = client_shim.postb(
        &format!("{}/{}/second", ROT_PATH_PRE, id),
        body,
    )
    .unwrap();

    let random2 = Rotation2::key_rotate_second_message(
        &coin_flip_party1_second_message,
        &coin_flip_party2_first_message,
        &coin_flip_party1_first_message,
    );

    let result_rotate_party_one_first_message = wallet
        .private_share
        .master_key
        .rotate_first_message(&random2, &rotation_party1_first_message);
    if result_rotate_party_one_first_message.is_err() {
        panic!("rotation failed");
    }

    let (rotation_party_two_first_message, party_two_pdl_chal, party_two_paillier) =
        result_rotate_party_one_first_message.unwrap();

    let body = &rotation_party_two_first_message;

    let rotation_party1_second_message: party_one::PDLFirstMessage = client_shim.postb(
        &format!("{}/{}/third", ROT_PATH_PRE, id),
        body,
    )
    .unwrap();

    let rotation_party_two_second_message = MasterKey2::rotate_second_message(&party_two_pdl_chal);

    let body = &rotation_party_two_second_message;

    let rotation_party1_third_message: party_one::PDLSecondMessage = client_shim.postb(
        &format!("{}/{}/fourth", ROT_PATH_PRE, id),
        body,
    )
    .unwrap();

    let result_rotate_party_one_third_message =
        wallet.private_share.master_key.rotate_third_message(
            &random2,
            &party_two_paillier,
            &party_two_pdl_chal,
            &rotation_party1_second_message,
            &rotation_party1_third_message,
        );
    if result_rotate_party_one_third_message.is_err() {
        panic!("rotation failed");
    }

    let party_two_master_key_rotated = result_rotate_party_one_third_message.unwrap();

    let private_share = PrivateShare {
        id: wallet.private_share.id.clone(),
        master_key: party_two_master_key_rotated,
    };

    let addresses_derivation_map = HashMap::new();
    let mut wallet_after_rotate = wallet::Wallet {
        id: wallet.id.clone(),
        network: wallet.network.clone(),
        private_share,
        last_derived_pos: wallet.last_derived_pos,
        addresses_derivation_map,
    };
    wallet_after_rotate.derived();

    wallet_after_rotate
}
