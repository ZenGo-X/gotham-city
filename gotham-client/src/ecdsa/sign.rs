#![allow(non_snake_case)]

use curv::BigInt;

use kms::ecdsa::two_party_gg18::*;

use super::super::api;
use super::super::utilities::requests;
use kms::ecdsa::two_party_gg18::party1::KeyGenMessage0Party1Transform;
use kms::ecdsa::two_party_lindell17::MasterKey2 as MasterKey2L;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2018::party_i::Signature;
use serde_json;
use time::PreciseTime;

#[derive(Serialize, Deserialize)]
pub struct TransformFirstMessage {
    pub message: BigInt,
    pub party1_message1: KeyGenMessage0Party1Transform,
    pub x_pos_child_key: BigInt,
    pub y_pos_child_key: BigInt,
}

#[derive(Serialize, Deserialize)]
pub struct SignSecondMsgRequest {
    pub message: BigInt,
    pub party1_message1: SignMessage1,
    pub x_pos_child_key: BigInt,
    pub y_pos_child_key: BigInt,
}

pub fn sign_gg(
    client_shim: &api::ClientShim,
    message: BigInt,
    mk: &MasterKey1,
    x_pos: BigInt,
    y_pos: BigInt,
    id: &String,
) -> Signature {
    let start = PreciseTime::now();
    let (party1_message1, party1_decommit_phase1, party1_sign_keys) = mk.sign_first_message();

    let sign_first = SignSecondMsgRequest {
        message: message.clone(),
        party1_message1: party1_message1.clone(),
        x_pos_child_key: x_pos,
        y_pos_child_key: y_pos,
    };
    //////////////////////////////////////////////////////////////////////////////////////////
    let body = &sign_first;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/first", id), body).unwrap();

    let party2_message1: SignMessage1 = serde_json::from_str(&res_body).unwrap();

    //////////////////////////////////////////////////////////////////////////////////////////
    let (party1_message2, party1_beta, party1_ni) =
        mk.sign_second_message(&party2_message1, &party1_sign_keys);

    let body = &party1_message2;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/second", id), body).unwrap();

    let party2_message2: SignMessage2 = serde_json::from_str(&res_body).unwrap();
    //////////////////////////////////////////////////////////////////////////////////////////
    let (party1_message3, party1_sigma) =
        mk.sign_third_message(&party2_message2, &party1_sign_keys, party1_beta, party1_ni);

    let body = &party1_message3;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/third", id), body).unwrap();

    let party2_message3: SignMessage3 = serde_json::from_str(&res_body).unwrap();

    //////////////////////////////////////////////////////////////////////////////////////////
    let party1_message4 = MasterKey1::sign_fourth_message(party1_decommit_phase1);

    let body = &party1_message4;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/fourth", id), body).unwrap();

    let party2_message4: SignMessage4 = serde_json::from_str(&res_body).unwrap();
    //////////////////////////////////////////////////////////////////////////////////////////
    let (party1_message5, party1_phase5a_decom1, party1_elgamal_proof, party1_local_sig, party1_R) =
        mk.sign_fifth_message(
            message.clone(),
            party1_sigma,
            &party1_sign_keys,
            party1_message4.clone(),
            party1_message3.clone(),
            party2_message3.clone(),
            party2_message4.clone(),
            party2_message2,
            party2_message1,
        );

    let body = &party1_message5;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/fifth", id), body).unwrap();
    let party2_message5: SignMessage5 = serde_json::from_str(&res_body).unwrap();
    //////////////////////////////////////////////////////////////////////////////////////////

    let party1_message6 =
        MasterKey1::sign_sixth_message(party1_phase5a_decom1, party1_elgamal_proof);

    let body = &party1_message6;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/sixth", id), body).unwrap();
    let party2_message6: SignMessage6 = serde_json::from_str(&res_body).unwrap();
    //////////////////////////////////////////////////////////////////////////////////////////

    let (party1_message7, party1_phase5d_decom2) = MasterKey1::sign_seventh_message(
        party1_message6.clone(),
        party2_message6.clone(),
        party2_message5,
        &party1_local_sig,
        party1_R,
    );

    let body = &party1_message7;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/seventh", id), body).unwrap();
    let party2_message7: SignMessage7 = serde_json::from_str(&res_body).unwrap();
    //////////////////////////////////////////////////////////////////////////////////////////

    let party1_message8 = MasterKey1::sign_eighth_message(party1_phase5d_decom2);

    let body = &party1_message8;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/eighth", id), body).unwrap();
    let party2_message8: SignMessage8 = serde_json::from_str(&res_body).unwrap();
    //////////////////////////////////////////////////////////////////////////////////////////

    let party1_message9 = MasterKey1::sign_ninth_message(
        party1_message6.clone(),
        party2_message6.clone(),
        party1_message7.clone(),
        party2_message7.clone(),
        party1_message8.clone(),
        party2_message8.clone(),
        &party1_local_sig,
    );

    let body = &party1_message9;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/nineth", id), body).unwrap();

    let party2_message9: SignMessage9 = serde_json::from_str(&res_body).unwrap();
    //////////////////////////////////////////////////////////////////////////////////////////

    let sig1 = MasterKey1::output_signature(party2_message9, party1_local_sig);
    let end = PreciseTime::now();
    println!("(id: {}) Took: {}", id, start.to(end));

    sig1
}

// signing using GG18 use Lindell Keys
pub fn sign(
    client_shim: &api::ClientShim,
    message: BigInt,
    master_key_l: &MasterKey2L,
    x_pos: BigInt,
    y_pos: BigInt,
    id: &String,
) -> Signature {
    let start = PreciseTime::now();
    let (party1_message1, party1_additive_key, party1_decom1) =
        MasterKey1::key_gen_zero_message_transform(&master_key_l);

    let transform_first = TransformFirstMessage {
        message: message.clone(),
        party1_message1: party1_message1.clone(),
        x_pos_child_key: x_pos,
        y_pos_child_key: y_pos,
    };

    ////
    let body = &transform_first;

    let res_body = requests::postb(
        client_shim,
        &format!("/ecdsa/sign_keygen_lindell/{}/first", id),
        body,
    )
    .unwrap();

    let party2_message1: KeyGenMessage1 = serde_json::from_str(&res_body).unwrap();

    /////
    let party1_message2 = MasterKey1::keygen_second_message(party1_decom1);

    ////
    let body = &party1_message2;

    let res_body = requests::postb(
        client_shim,
        &format!("/ecdsa/sign_keygen_lindell/{}/second", id),
        body,
    )
    .unwrap();

    let party2_message2: KeyGenMessage2 = serde_json::from_str(&res_body).unwrap();

    /////

    let (party1_message3, ss1_to_self, party1_y_vec, party1_ek_vec) =
        MasterKey1::key_gen_third_message(
            &party1_additive_key,
            party1_message1.p1m1,
            party2_message1.clone(),
            party1_message2.clone(),
            party2_message2.clone(),
        );
    ////
    let body = &party1_message3;

    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/keygen/{}/third", id), body).unwrap();

    let party2_message3: KeyGenMessage3 = serde_json::from_str(&res_body).unwrap();
    /////
    let (party1_message4, party1_linear_key, party1_vss_vec) = MasterKey1::key_gen_fourth_message(
        &party1_additive_key,
        party1_message3.clone(),
        party2_message3.clone(),
        ss1_to_self,
        &party1_y_vec,
    );
    ////
    let body = &party1_message4;

    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/keygen/{}/fourth", id), body).unwrap();

    let party2_message4: KeyGenMessage4 = serde_json::from_str(&res_body).unwrap();
    /////
    let mk = MasterKey1::set_master_key(
        party1_message4,
        party2_message4,
        party1_y_vec.clone(),
        party1_additive_key,
        party1_linear_key,
        party1_vss_vec,
        party1_ek_vec,
        &master_key_l.chain_code,
    );

    let (party1_message1, party1_decommit_phase1, party1_sign_keys) = mk.sign_first_message();

    let sign_first = SignSecondMsgRequest {
        message: message.clone(),
        party1_message1: party1_message1.clone(),
        x_pos_child_key: BigInt::zero(),
        y_pos_child_key: BigInt::zero(),
    };
    //////////////////////////////////////////////////////////////////////////////////////////
    let body = &sign_first;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/first", id), body).unwrap();

    let party2_message1: SignMessage1 = serde_json::from_str(&res_body).unwrap();
    //////////////////////////////////////////////////////////////////////////////////////////
    let (party1_message2, party1_beta, party1_ni) =
        mk.sign_second_message(&party2_message1, &party1_sign_keys);

    let body = &party1_message2;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/second", id), body).unwrap();

    let party2_message2: SignMessage2 = serde_json::from_str(&res_body).unwrap();
    //////////////////////////////////////////////////////////////////////////////////////////
    let (party1_message3, party1_sigma) =
        mk.sign_third_message(&party2_message2, &party1_sign_keys, party1_beta, party1_ni);
    let body = &party1_message3;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/third", id), body).unwrap();

    let party2_message3: SignMessage3 = serde_json::from_str(&res_body).unwrap();
    //////////////////////////////////////////////////////////////////////////////////////////
    let party1_message4 = MasterKey1::sign_fourth_message(party1_decommit_phase1);

    let body = &party1_message4;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/fourth", id), body).unwrap();
    let party2_message4: SignMessage4 = serde_json::from_str(&res_body).unwrap();
    //////////////////////////////////////////////////////////////////////////////////////////
    let (party1_message5, party1_phase5a_decom1, party1_elgamal_proof, party1_local_sig, party1_R) =
        mk.sign_fifth_message(
            message.clone(),
            party1_sigma,
            &party1_sign_keys,
            party1_message4.clone(),
            party1_message3.clone(),
            party2_message3.clone(),
            party2_message4.clone(),
            party2_message2,
            party2_message1,
        );

    let body = &party1_message5;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/fifth", id), body).unwrap();

    let party2_message5: SignMessage5 = serde_json::from_str(&res_body).unwrap();
    //////////////////////////////////////////////////////////////////////////////////////////
    let party1_message6 =
        MasterKey1::sign_sixth_message(party1_phase5a_decom1, party1_elgamal_proof);
    let body = &party1_message6;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/sixth", id), body).unwrap();
    let party2_message6: SignMessage6 = serde_json::from_str(&res_body).unwrap();
    //////////////////////////////////////////////////////////////////////////////////////////

    let (party1_message7, party1_phase5d_decom2) = MasterKey1::sign_seventh_message(
        party1_message6.clone(),
        party2_message6.clone(),
        party2_message5,
        &party1_local_sig,
        party1_R,
    );

    let body = &party1_message7;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/seventh", id), body).unwrap();
    let party2_message7: SignMessage7 = serde_json::from_str(&res_body).unwrap();
    //////////////////////////////////////////////////////////////////////////////////////////

    let party1_message8 = MasterKey1::sign_eighth_message(party1_phase5d_decom2);

    let body = &party1_message8;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/eighth", id), body).unwrap();
    let party2_message8: SignMessage8 = serde_json::from_str(&res_body).unwrap();
    //////////////////////////////////////////////////////////////////////////////////////////
    let party1_message9 = MasterKey1::sign_ninth_message(
        party1_message6.clone(),
        party2_message6.clone(),
        party1_message7.clone(),
        party2_message7.clone(),
        party1_message8.clone(),
        party2_message8.clone(),
        &party1_local_sig,
    );

    let body = &party1_message9;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/nineth", id), body).unwrap();

    let party2_message9: SignMessage9 = serde_json::from_str(&res_body).unwrap();
    //////////////////////////////////////////////////////////////////////////////////////////

    let sig1 = MasterKey1::output_signature(party2_message9, party1_local_sig);
    let end = PreciseTime::now();
    println!("(id: {}) Took: {}", id, start.to(end));

    sig1
}
