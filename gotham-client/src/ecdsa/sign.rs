use bitcoin;
use reqwest;
use kms::ecdsa::two_party::party2;
use kms::ecdsa::two_party::MasterKey2;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_one;
use curv::BigInt;

use super::super::utilities::requests;
use curv::arithmetic::traits::Converter;

#[derive(Serialize, Deserialize)]
pub struct SignSecondMsgRequest {
    pub message: BigInt,
    pub party_two_sign_message: party2::SignMessage,
    pub pos_child_key: u32,
}

pub fn sign(
    client: &reqwest::Client,
    message: bitcoin::util::hash::Sha256dHash,
    mk: &MasterKey2,
    pos: u32,
    id: &String
) -> party_one::Signature {
    let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
        MasterKey2::sign_first_message();

    let request: party_two::EphKeyGenFirstMsg = eph_key_gen_first_message_party_two;
    let res_body = requests::postb(
        client,
        &format!("/ecdsa/sign/{}/first", id),
        &request,
    ).unwrap();

    let sign_party_one_first_message: party_one::EphKeyGenFirstMsg =
        serde_json::from_str(&res_body).unwrap();

    let party_two_sign_message = mk.sign_second_message(
        &eph_ec_key_pair_party2,
        eph_comm_witness.clone(),
        &sign_party_one_first_message,
        &BigInt::from_hex(&message.le_hex_string()),
    );

    let signature: party_one::Signature = get_signature(client, message, party_two_sign_message, pos, &id);

    signature
}

fn get_signature(
    client: &reqwest::Client,
    message: bitcoin::util::hash::Sha256dHash,
    party_two_sign_message: party2::SignMessage,
    pos_child_key: u32,
    id: &String
) -> party_one::Signature {
    let request: SignSecondMsgRequest = SignSecondMsgRequest {
        message: BigInt::from_hex(&message.le_hex_string()),
        party_two_sign_message,
        pos_child_key,
    };

    let res_body = requests::postb(
        client,
        &format!("/ecdsa/sign/{}/second", id),
        &request,
    ).unwrap();

    let signature: party_one::Signature = serde_json::from_str(&res_body).unwrap();
    signature
}