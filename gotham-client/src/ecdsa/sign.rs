use curv::BigInt;
use kms::ecdsa::two_party::party2;
use kms::ecdsa::two_party::MasterKey2;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two;

use super::super::api;
use super::super::utilities::requests;

#[derive(Serialize, Deserialize, Debug)]
pub struct SignSecondMsgRequest {
    pub message: BigInt,
    pub party_two_sign_message: party2::SignMessage,
    pub x_pos_child_key: u32,
    pub y_pos_child_key: u32,
}

pub fn sign(
    client_shim: &api::ClientShim,
    message: BigInt,
    mk: &MasterKey2,
    x_pos: u32,
    y_pos: u32,
    id: &String,
) -> party_one::Signature {
    let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
        MasterKey2::sign_first_message();

    let request: party_two::EphKeyGenFirstMsg = eph_key_gen_first_message_party_two;
    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/first", id), &request).unwrap();

    let sign_party_one_first_message: party_one::EphKeyGenFirstMsg =
        serde_json::from_str(&res_body).unwrap();

    let party_two_sign_message = mk.sign_second_message(
        &eph_ec_key_pair_party2,
        eph_comm_witness.clone(),
        &sign_party_one_first_message,
        &message,
    );

    let signature: party_one::Signature = get_signature(
        client_shim,
        message,
        party_two_sign_message,
        x_pos,
        y_pos,
        &id,
    );

    signature
}

fn get_signature(
    client_shim: &api::ClientShim,
    message: BigInt,
    party_two_sign_message: party2::SignMessage,
    x_pos_child_key: u32,
    y_pos_child_key: u32,
    id: &String,
) -> party_one::Signature {
    let request: SignSecondMsgRequest = SignSecondMsgRequest {
        message,
        party_two_sign_message,
        x_pos_child_key,
        y_pos_child_key,
    };

    let res_body =
        requests::postb(client_shim, &format!("/ecdsa/sign/{}/second", id), &request).unwrap();

    let signature: party_one::Signature = serde_json::from_str(&res_body).unwrap();
    signature
}
