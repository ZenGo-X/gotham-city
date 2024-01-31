#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::env;
    use std::time::Instant;
    use floating_duration::TimeFormat;
    use crate::server;
    use rocket::{http::ContentType, http::{Status}, local::blocking::Client};
    use two_party_ecdsa::{BigInt, party_one, party_two};
    use two_party_ecdsa::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::{Party1FirstMessageDHPoK, Party1SecondMessageDHPoK};
    use two_party_ecdsa::kms::ecdsa::two_party::{MasterKey2, party1};
    use two_party_ecdsa::kms::chain_code::two_party::party2::ChainCode2;
    use two_party_ecdsa::kms::ecdsa;
    use gotham_engine::types::SignSecondMsgRequest;
    use rocket::http::Header;
    use two_party_ecdsa::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
    use two_party_ecdsa::kms::ecdsa::two_party::party1::RotationParty1Message1;
    use two_party_ecdsa::kms::rotation::two_party::party2::Rotation2;
    use two_party_ecdsa::party_one::Converter;
    use uuid::Uuid;

    fn key_gen(client: &Client, customer_id: String) -> (String, MasterKey2) {
        let x_customer_header = Header::new("x-customer-id", customer_id);

        let response = client
            .post("/ecdsa/keygen_v2/first")
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let res_body = response.into_string().unwrap();

        let (id, kg_party_one_first_message): (String, party_one::KeyGenFirstMsg) =
            serde_json::from_str(&res_body).unwrap();

        let (kg_party_two_first_message, kg_ec_key_pair_party2) =
            MasterKey2::key_gen_first_message();

        /*************** END: FIRST MESSAGE ***************/

        /*************** START: SECOND MESSAGE ***************/
        let body = serde_json::to_string(&kg_party_two_first_message.d_log_proof).unwrap();
        let response = client
            .post(format!("/ecdsa/keygen_v2/{}/second", id))
            .body(body)
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let res_body = response.into_string().unwrap();
        let kg_party_one_second_message: party1::KeyGenParty1Message2 =
            serde_json::from_str(&res_body).unwrap();

        let key_gen_second_message = MasterKey2::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_one_second_message,
        );
        assert!(key_gen_second_message.is_ok());

        let (party_two_second_message, party_two_paillier, party_two_pdl_chal) =
            key_gen_second_message.unwrap();

        /*************** END: SECOND MESSAGE ***************/

        /*************** START: THIRD MESSAGE ***************/
        let body = serde_json::to_string(&party_two_second_message.pdl_first_message).unwrap();

        let response = client
            .post(format!("/ecdsa/keygen_v2/{}/third", id))
            .body(body)
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let res_body = response.into_string().unwrap();
        let party_one_third_message: party_one::Party1PDLFirstMessage =
            serde_json::from_str(&res_body).unwrap();

        let start = Instant::now();

        let pdl_decom_party2 = MasterKey2::key_gen_third_message(&party_two_pdl_chal);

        /*************** END: THIRD MESSAGE ***************/

        /*************** START: FOURTH MESSAGE ***************/

        let party_2_pdl_second_message = pdl_decom_party2;
        let request = party_2_pdl_second_message;
        let body = serde_json::to_string(&request).unwrap();

        let response = client
            .post(format!("/ecdsa/keygen_v2/{}/fourth", id))
            .body(body)
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let res_body = response.into_string().unwrap();
        let party_one_pdl_second_message: party_one::Party1PDLSecondMessage =
            serde_json::from_str(&res_body).unwrap();

        MasterKey2::key_gen_fourth_message(
            &party_two_pdl_chal,
            &party_one_third_message,
            &party_one_pdl_second_message,
        )
        .expect("pdl error party1");

        /*************** START: CHAINCODE FIRST MESSAGE ***************/

        let response = client
            .post(format!("/ecdsa/keygen_v2/{}/chaincode/first", id))
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let res_body = response.into_string().unwrap();
        let cc_party_one_first_message: Party1FirstMessageDHPoK =
            serde_json::from_str(&res_body).unwrap();

        let (cc_party_two_first_message, cc_ec_key_pair2) = ChainCode2::chain_code_first_message();

        /*************** END: CHAINCODE FIRST MESSAGE ***************/

        /*************** START: CHAINCODE SECOND MESSAGE ***************/
        let body = serde_json::to_string(&cc_party_two_first_message.d_log_proof).unwrap();

        let response = client
            .post(format!("/ecdsa/keygen_v2/{}/chaincode/second", id))
            .body(body)
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let res_body = response.into_string().unwrap();
        let cc_party_one_second_message: Party1SecondMessageDHPoK =
            serde_json::from_str(&res_body).unwrap();

        let _cc_party_two_second_message = ChainCode2::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_one_second_message,
        );

        /*************** END: CHAINCODE SECOND MESSAGE ***************/

        let party2_cc = ChainCode2::compute_chain_code(
            &cc_ec_key_pair2,
            &cc_party_one_second_message.comm_witness.public_share,
        )
        .chain_code;

        /*************** END: CHAINCODE COMPUTE MESSAGE ***************/

        let party_two_master_key = MasterKey2::set_master_key(
            &party2_cc,
            &kg_ec_key_pair_party2,
            &kg_party_one_second_message
                .ecdh_second_message
                .comm_witness
                .public_share,
            &party_two_paillier,
        );

        /*************** END: MASTER KEYS MESSAGE ***************/

        (id, party_two_master_key)
    }

    fn sign(
        client: &Client,
        id: String,
        customer_id: String,
        master_key_2: &MasterKey2,
        message: BigInt,
    ) -> party_one::SignatureRecid {
        let x_customer_header = Header::new("x-customer-id", customer_id);

        let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
            MasterKey2::sign_first_message();

        let request: party_two::EphKeyGenFirstMsg = eph_key_gen_first_message_party_two;

        let body = serde_json::to_string(&request).unwrap();

        let response = client
            .post(format!("/ecdsa/sign/{}/first", id))
            .body(body)
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let res_body = response.into_string().unwrap();
        let sign_party_one_first_message: party_one::EphKeyGenFirstMsg =
            serde_json::from_str(&res_body).unwrap();

        let x_pos = BigInt::from(0u32);
        let y_pos = BigInt::from(21u32);

        let child_party_two_master_key = master_key_2.get_child(vec![x_pos.clone(), y_pos.clone()]);

        let start = Instant::now();

        let party_two_sign_message = child_party_two_master_key.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness.clone(),
            &sign_party_one_first_message,
            &message,
        );

        let request: SignSecondMsgRequest = SignSecondMsgRequest {
            message,
            party_two_sign_message,
            x_pos_child_key: x_pos,
            y_pos_child_key: y_pos,
        };

        let body = serde_json::to_string(&request).unwrap();

        let response = client
            .post(format!("/ecdsa/sign/{}/second", id))
            .body(body)
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let res_body = response.into_string().unwrap();
        let signature_recid: party_one::SignatureRecid = serde_json::from_str(&res_body).unwrap();

        signature_recid
    }

    fn rotate(
        client: &Client,
        customer_id: String,
        id: String,
        master_key_2: &MasterKey2
    ) ->  MasterKey2 {
        let x_customer_header = Header::new("x-customer-id", customer_id);

        let mut coin_flip_party1_first_message: Option<coin_flip_optimal_rounds::Party1FirstMessage> = None;
        let mut coin_flip_party2_first_message: Option<coin_flip_optimal_rounds::Party2FirstMessage> = None;


        let mut second_message: Option<(
            coin_flip_optimal_rounds::Party1SecondMessage,
            RotationParty1Message1,
        )> = None;

        while second_message.is_none() {
            /*************** START: FIRST MESSAGE ***************/

            let response = client
                .post(format!("/ecdsa/rotate/{}/first", id))
                .header(ContentType::JSON)
                .header(x_customer_header.clone())
                .dispatch();
            assert_eq!(response.status(), Status::Ok);
            let res_body = response.into_string().unwrap();

            let coin_flip_party1_first_message_temp: coin_flip_optimal_rounds::Party1FirstMessage =
                serde_json::from_str(&res_body).unwrap();

            coin_flip_party1_first_message = Some(coin_flip_party1_first_message_temp.clone());

            let coin_flip_party2_first_message_temp =
                Rotation2::key_rotate_first_message(&coin_flip_party1_first_message_temp);

            coin_flip_party2_first_message = Some(coin_flip_party2_first_message_temp.clone());

            /*************** END: FIRST MESSAGE ***************/

            /*************** START: SECOND MESSAGE ***************/
            let body = serde_json::to_string(&coin_flip_party2_first_message_temp).unwrap();

            let response = client
                .post(format!("/ecdsa/rotate/{}/second", id))
                .body(body)

                .header(ContentType::JSON)
                .header(x_customer_header.clone())
                .dispatch();
            assert_eq!(response.status(), Status::Ok);
            let res_body = response.into_string().unwrap();
            second_message = serde_json::from_str(&res_body).unwrap();
        }

        let (coin_flip_party1_second_message, rotation_party1_first_message) = second_message.unwrap();

        let random2 = Rotation2::key_rotate_second_message(
            &coin_flip_party1_second_message,
            &coin_flip_party2_first_message.unwrap(),
            &coin_flip_party1_first_message.unwrap()
        );

        let result_rotate_party_one_first_message =
            master_key_2.rotate_first_message(&random2, &rotation_party1_first_message);

        assert!(result_rotate_party_one_first_message.is_ok());

        let (rotation_party_two_first_message, party_two_pdl_chal, party_two_paillier) =
            result_rotate_party_one_first_message.unwrap();


        /*************** END: SECOND MESSAGE ***************/

        /*************** START: THIRD MESSAGE ***************/

        let body = serde_json::to_string(&rotation_party_two_first_message).unwrap();

        let response = client
            .post(format!("/ecdsa/rotate/{}/third", id))
            .body(body)
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let res_body = response.into_string().unwrap();

        let rotation_party1_second_message: party_one::Party1PDLFirstMessage =
            serde_json::from_str(&res_body).unwrap();

        let rotation_party_two_second_message = MasterKey2::rotate_second_message(&party_two_pdl_chal);

        /*************** END: THIRD MESSAGE ***************/

        /*************** START: FORTH MESSAGE ***************/

        let body = serde_json::to_string(&rotation_party_two_second_message).unwrap();

        let response = client
            .post(format!("/ecdsa/rotate/{}/forth", id))
            .body(body)
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let res_body = response.into_string().unwrap();

        let rotation_party1_third_message: party_one::Party1PDLSecondMessage =
            serde_json::from_str(&res_body).unwrap();

        let result_rotate_party_one_third_message = master_key_2.rotate_third_message(
            &random2,
            &party_two_paillier,
            &party_two_pdl_chal,
            &rotation_party1_second_message,
            &rotation_party1_third_message,
        );

        assert!(result_rotate_party_one_third_message.is_ok());

        let rotated_mk = result_rotate_party_one_third_message.unwrap();

        /*************** END: FORTH MESSAGE ***************/
        rotated_mk
    }

    #[test]
    fn unit_test_keygen_sign_rotate() {
        let server = server::get_server();
        let client = Client::tracked(server).expect("valid rocket instance");
        let customer_id = Uuid::new_v4().to_string();
        let (id, master_key) = key_gen(&client, customer_id.clone());
        let message = BigInt::from(1234u32);

        let first_signature: party_one::SignatureRecid =
            sign(&client, id.clone(), customer_id.clone(), &master_key, message.clone());

        println!(
            "first_signature: s = (r: {}, s: {}, recid: {})",
            first_signature.r.to_hex(),
            first_signature.s.to_hex(),
            first_signature.recid
        );

        let rotated_master_key = rotate(&client, customer_id.clone(), id.clone(), &master_key);

        let second_signature: party_one::SignatureRecid =
            sign(&client, id.clone(), customer_id.clone(), &rotated_master_key, message.clone());

        println!(
            "second_signature: s = (r: {}, s: {}, recid: {})",
            second_signature.r.to_hex(),
            second_signature.s.to_hex(),
            second_signature.recid
        );
    }
}
