// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use serde_json;

use super::super::api;
use super::super::utilities::requests;
use super::super::wallet;
use curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds::Party1SecondMessage as RotParty1SecondMessage;
use curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds::Party2FirstMessage as RotParty2FirstMessage;

use api::PrivateShareGG;
use kms::ecdsa::two_party_gg18::*;
use kms::rotation::two_party::party1::Rotation1;
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub struct RotCfParty1 {
    pub party1_message1: KeyGenMessage1,
    pub cf_party1_message2: RotParty1SecondMessage,
}

const ROT_PATH_PRE: &str = "ecdsa/rotate";

pub fn rotate_master_key(
    wallet: wallet::WalletNew,
    client_shim: &api::ClientShim,
) -> wallet::WalletNew {
    let id = &wallet.private_share.id.clone();
    let master_key1: MasterKey1 = wallet.private_share.master_key;

    let (cf_party1_message1, m1, r1) = Rotation1::key_rotate_first_message();

    let body = &cf_party1_message1;

    let res_body =
        requests::postb(client_shim, &format!("{}/{}/zero", ROT_PATH_PRE, id), body).unwrap();

    let cf_party2_message1: RotParty2FirstMessage = serde_json::from_str(&res_body).unwrap();

    let (cf_party1_message2, random1) =
        Rotation1::key_rotate_second_message(&cf_party2_message1, &m1, &r1);

    let (party1_message1, party1_additive_key, party1_decom1) =
        master_key1.rotation_first_message(&random1);

    let party1_message1 = RotCfParty1 {
        party1_message1,
        cf_party1_message2,
    };

    ////
    let body = &party1_message1;

    let res_body =
        requests::postb(client_shim, &format!("{}/{}/first", ROT_PATH_PRE, id), body).unwrap();

    let party2_message1: KeyGenMessage1 = serde_json::from_str(&res_body).unwrap();

    /////
    let party1_message2 = MasterKey1::rotation_second_message(party1_decom1);

    ////
    let body = &party1_message2;

    let res_body = requests::postb(
        client_shim,
        &format!("{}/{}/second", ROT_PATH_PRE, id),
        body,
    )
    .unwrap();

    let party2_message2: KeyGenMessage2 = serde_json::from_str(&res_body).unwrap();

    /////

    let (party1_message3, ss1_to_self, party1_y_vec, party1_ek_vec) = master_key1
        .rotation_third_message(
            &party1_additive_key,
            party1_message1.party1_message1,
            party2_message1.clone(),
            party1_message2.clone(),
            party2_message2.clone(),
        );

    ////
    let body = &party1_message3;

    let res_body =
        requests::postb(client_shim, &format!("{}/{}/third", ROT_PATH_PRE, id), body).unwrap();

    let party2_message3: KeyGenMessage3 = serde_json::from_str(&res_body).unwrap();

    /////

    let (party1_message4, party1_linear_key, party1_vss_vec) = MasterKey1::rotation_fourth_message(
        &party1_additive_key,
        party1_message3.clone(),
        party2_message3.clone(),
        ss1_to_self,
        &party1_y_vec,
    );

    ////
    let body = &party1_message4;

    let res_body = requests::postb(
        client_shim,
        &format!("{}/{}/fourth", ROT_PATH_PRE, id),
        body,
    )
    .unwrap();

    let party2_message4: KeyGenMessage4 = serde_json::from_str(&res_body).unwrap();

    /////

    let master_key1_rotated = master_key1.rotate_master_key(
        party1_message4,
        party2_message4,
        party1_y_vec.clone(),
        party1_additive_key,
        party1_linear_key,
        party1_vss_vec,
        party1_ek_vec,
    );

    let private_share = PrivateShareGG {
        id: id.clone(),
        master_key: master_key1_rotated,
    };

    let addresses_derivation_map = HashMap::new();
    let mut wallet_after_rotate = wallet::WalletNew {
        id: wallet.id.clone(),
        network: wallet.network.clone(),
        private_share,
        last_derived_pos: wallet.last_derived_pos.clone(),
        addresses_derivation_map,
    };
    wallet_after_rotate.derived();

    wallet_after_rotate
}
