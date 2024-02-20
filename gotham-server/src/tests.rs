#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::env;
    use std::time::Instant;
    use floating_duration::TimeFormat;
    use log::info;
    use crate::server;
    use rocket::{http::ContentType, http::{Status}, local::blocking::Client};
    use two_party_ecdsa::{BigInt, party_one, party_two};

    use two_party_ecdsa::kms::ecdsa::two_party::{MasterKey2, party1};
    use two_party_ecdsa::kms::chain_code::two_party::party2::ChainCode2;
    use two_party_ecdsa::kms::ecdsa;

    use rocket::http::Header;
    use time_test::time_test;
    use two_party_ecdsa::curv::cryptographic_primitives::twoparty::coin_flip_optimal_rounds;
    use two_party_ecdsa::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::{DHPoKParty1FirstMessage, DHPoKParty1SecondMessage};
    use two_party_ecdsa::kms::ecdsa::two_party::party2::{Party2SignSecondMessage, Party2SignSecondMessageVector};
    use two_party_ecdsa::kms::rotation::two_party::party1::RotationParty1Message1;

    use two_party_ecdsa::kms::rotation::two_party::party2::Rotation2;
    use two_party_ecdsa::party_one::{Converter, Party1EphKeyGenFirstMessage, Party1KeyGenFirstMessage, Party1KeyGenSecondMessage, Party1PDLFirstMessage, Party1PDLSecondMessage, Party1SignatureRecid};
    use two_party_ecdsa::party_two::Party2EphKeyGenFirstMessage;
    use uuid::Uuid;

    fn key_gen(client: &Client, customer_id: String, url_prefix: String) -> (String, MasterKey2) {
        time_test!();
        let x_customer_header = Header::new("x-customer-id", customer_id);

        /*************** START: FIRST MESSAGE ***************/
        let start = Instant::now();

        let response = client
            .post(format!("{}/first", url_prefix))
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        info!(
        "{} Network/Server: party1 first message",
        TimeFormat(start.elapsed())
    );
        let res_body = response.into_string().unwrap();

        let (id, kg_party_one_first_message): (String, Party1KeyGenFirstMessage) =
            serde_json::from_str(&res_body).unwrap();

        let start = Instant::now();

        let (kg_party_two_first_message, kg_ec_key_pair_party2) = MasterKey2::key_gen_first_message();

        info!(
        "{} Client: party2 first message",
        TimeFormat(start.elapsed())
    );
        /*************** END: FIRST MESSAGE ***************/

        /*************** START: SECOND MESSAGE ***************/
        let body = serde_json::to_string(&kg_party_two_first_message.d_log_proof).unwrap();

        let start = Instant::now();

        let response = client
            .post(format!("{}/{}/second", url_prefix, id))
            .body(body)
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        info!(
        "{} Network/Server: party1 second message",
        TimeFormat(start.elapsed())
    );

        let res_body = response.into_string().unwrap();
        let kg_party_one_second_message: Party1KeyGenSecondMessage =
            serde_json::from_str(&res_body).unwrap();

        let start = Instant::now();

        let key_gen_second_message = MasterKey2::key_gen_second_message(
            &kg_party_one_first_message,
            &kg_party_one_second_message,
        );
        assert!(key_gen_second_message.is_ok());

        info!(
        "{} Client: party2 second message",
        TimeFormat(start.elapsed())
    );

        let (party_two_second_message, party_two_paillier, party_two_pdl_chal) =
            key_gen_second_message.unwrap();

        /*************** END: SECOND MESSAGE ***************/

        /*************** START: THIRD MESSAGE ***************/
        let body = serde_json::to_string(&party_two_second_message.pdl_first_message).unwrap();

        let start = Instant::now();

        let response = client
            .post(format!("{}/{}/third", url_prefix, id))
            .body(body)
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        info!(
        "{} Network/Server: party1 third message",
        TimeFormat(start.elapsed())
    );

        let res_body = response.into_string().unwrap();
        let party_one_third_message: Party1PDLFirstMessage = serde_json::from_str(&res_body).unwrap();

        let start = Instant::now();

        let pdl_decom_party2 = MasterKey2::key_gen_third_message(&party_two_pdl_chal);

        info!(
        "{} Client: party2 third message",
        TimeFormat(start.elapsed())
    );
        /*************** END: THIRD MESSAGE ***************/

        /*************** START: FOURTH MESSAGE ***************/

        let party_2_pdl_second_message = pdl_decom_party2;
        let request = party_2_pdl_second_message;
        let body = serde_json::to_string(&request).unwrap();

        let start = Instant::now();

        let response = client
            .post(format!("{}/{}/fourth", url_prefix, id))
            .body(body)
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        info!(
        "{} Network/Server: party1 fourth message",
        TimeFormat(start.elapsed())
    );

        let res_body = response.into_string().unwrap();
        let party_one_pdl_second_message: Party1PDLSecondMessage =
            serde_json::from_str(&res_body).unwrap();

        let start = Instant::now();

        MasterKey2::key_gen_fourth_message(
            &party_two_pdl_chal,
            &party_one_third_message,
            &party_one_pdl_second_message,
        )
            .expect("pdl error party1");

        info!(
        "{} Client: party2 fourth message",
        TimeFormat(start.elapsed())
    );
        /*************** END: FOURTH MESSAGE ***************/

        /*************** START: CHAINCODE FIRST MESSAGE ***************/
        let start = Instant::now();

        let response = client
            .post(format!("{}/{}/chaincode/first", url_prefix, id))
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        info!(
        "{} Network/Server: party1 chain code first message",
        TimeFormat(start.elapsed())
    );

        let res_body = response.into_string().unwrap();
        let cc_party_one_first_message: DHPoKParty1FirstMessage =
            serde_json::from_str(&res_body).unwrap();

        let start = Instant::now();
        let (cc_party_two_first_message, cc_ec_key_pair2) = ChainCode2::chain_code_first_message();

        info!(
        "{} Client: party2 chain code first message",
        TimeFormat(start.elapsed())
    );
        /*************** END: CHAINCODE FIRST MESSAGE ***************/

        /*************** START: CHAINCODE SECOND MESSAGE ***************/
        let body = serde_json::to_string(&cc_party_two_first_message.d_log_proof).unwrap();

        let start = Instant::now();

        let response = client
            .post(format!("{}/{}/chaincode/second", url_prefix, id))
            .body(body)
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        info!(
        "{} Network/Server: party1 chain code second message",
        TimeFormat(start.elapsed())
    );

        let res_body = response.into_string().unwrap();
        let cc_party_one_second_message: DHPoKParty1SecondMessage =
            serde_json::from_str(&res_body).unwrap();

        let start = Instant::now();
        let _cc_party_two_second_message = ChainCode2::chain_code_second_message(
            &cc_party_one_first_message,
            &cc_party_one_second_message,
        );

        info!(
        "{} Client: party2 chain code second message",
        TimeFormat(start.elapsed())
    );
        /*************** END: CHAINCODE SECOND MESSAGE ***************/

        let start = Instant::now();
        let party2_cc = ChainCode2::compute_chain_code(
            &cc_ec_key_pair2,
            &cc_party_one_second_message.comm_witness.public_share,
        )
            .chain_code;

        info!(
        "{} Client: party2 chain code second message",
        TimeFormat(start.elapsed())
    );
        /*************** END: CHAINCODE COMPUTE MESSAGE ***************/

        info!(
        "{} Network/Server: party1 master key",
        TimeFormat(start.elapsed())
    );

        let start = Instant::now();
        let party_two_master_key = MasterKey2::set_master_key(
            &party2_cc,
            &kg_ec_key_pair_party2,
            &kg_party_one_second_message
                .ecdh_second_message
                .comm_witness
                .public_share,
            &party_two_paillier,
        );

        info!("{} Client: party2 master_key", TimeFormat(start.elapsed()));
        /*************** END: MASTER KEYS MESSAGE ***************/

        (id, party_two_master_key)
    }

    enum SignVersion {
        V1,
        V2,
        V3,
    }

    fn sign(
        client: &Client,
        id: String,
        customer_id: String,
        master_key_2: &MasterKey2,
        message: BigInt,
        version: SignVersion,
    ) -> Party1SignatureRecid {
        let x_customer_header = Header::new("x-customer-id", customer_id);
        time_test!();
        let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
            MasterKey2::sign_first_message();

        let request: Party2EphKeyGenFirstMessage = eph_key_gen_first_message_party_two;

        let body = serde_json::to_string(&request).unwrap();

        let start = Instant::now();

        let sign_first_endpoint = match version {
            SignVersion::V1 => format!("/ecdsa/sign/{}/first", id),
            SignVersion::V2 => format!("/ecdsa/sign/{}/first_v2", id),
            SignVersion::V3 => format!("/ecdsa/sign/{}/first_v3", id),
        };

        let response = client
            .post(sign_first_endpoint)
            .body(body)
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        info!(
        "{} Network/Server: party1 sign first message",
        TimeFormat(start.elapsed())
    );

        let res_body = response.into_string().unwrap();
        let sign_party_one_first_message: (Option<String>, Party1EphKeyGenFirstMessage) = match version
        {
            SignVersion::V1 => {
                let res: Party1EphKeyGenFirstMessage = serde_json::from_str(&res_body).unwrap();
                (None, res)
            }
            SignVersion::V2 | SignVersion::V3 => {
                let res: (String, Party1EphKeyGenFirstMessage) =
                    serde_json::from_str(&res_body).unwrap();
                (Some(res.0), res.1)
            }
        };

        let mut pos_child_key = vec![BigInt::from(0u32), BigInt::from(21u32)];
        match version {
            SignVersion::V1 | SignVersion::V2 => {}
            SignVersion::V3 => pos_child_key.push(BigInt::from(2u32)),
        }

        let child_party_two_master_key = master_key_2.get_child(pos_child_key.clone());

        let start = Instant::now();

        let party_two_sign_message = child_party_two_master_key.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness.clone(),
            &sign_party_one_first_message.1,
            &message,
        );

        info!(
        "{} Client: party2 sign_v3 second message",
        TimeFormat(start.elapsed())
    );

        let body = match version {
            SignVersion::V1 | SignVersion::V2 => {
                let request: Party2SignSecondMessage = Party2SignSecondMessage {
                    message,
                    party_two_sign_message,
                    x_pos_child_key: pos_child_key[0].clone(),
                    y_pos_child_key: pos_child_key[1].clone(),
                };
                serde_json::to_string(&request).unwrap()
            }
            SignVersion::V3 => {
                let request: Party2SignSecondMessageVector = Party2SignSecondMessageVector {
                    message,
                    party_two_sign_message,
                    pos_child_key,
                };

                serde_json::to_string(&request).unwrap()
            }
        };

        let sign_second_endpoint = match version {
            SignVersion::V1 => format!("/ecdsa/sign/{}/second", id),
            SignVersion::V2 => {
                let sid = sign_party_one_first_message.0.unwrap();
                format!("/ecdsa/sign/{}/second_v2", sid)
            }
            SignVersion::V3 => {
                let sid = sign_party_one_first_message.0.unwrap();
                format!("/ecdsa/sign/{}/second_v3", sid)
            }
        };

        let start = Instant::now();

        let response = client
            .post(sign_second_endpoint)
            .body(body)
            .header(ContentType::JSON)
            .header(x_customer_header.clone())
            .dispatch();

        assert_eq!(response.status(), Status::Ok);

        info!(
        "{} Network/Server: party1 sign second message",
        TimeFormat(start.elapsed())
    );

        let res_body = response.into_string().unwrap();
        let signature_recid: Party1SignatureRecid = serde_json::from_str(&res_body).unwrap();

        signature_recid
    }


    fn rotate(
        client: &Client,
        customer_id: String,
        id: String,
        master_key_2: &MasterKey2
    ) -> MasterKey2 {
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
    fn unit_test_keygen() {
        let settings = HashMap::<String, String>::from([
            ("db".to_string(), "local".to_string()),
            ("db_name".to_string(), "KeyGen".to_string()),
        ]);

        let server = server::get_server(settings);

        let client = Client::tracked(server).expect("invalid rocket instance");

        let message = BigInt::from(1234u32);

        let customer_id = Uuid::new_v4().to_string();

        let (id, master_key_2): (String, MasterKey2) = key_gen(&client, customer_id.clone(), "/ecdsa/keygen".to_string());

        // TODO: Enable when keygen_v2 will work with rotation
        // let (id, master_key_2): (String, MasterKey2) = key_gen(&client, customer_id.clone(), "/ecdsa/keygen_v2".to_string());
    }

    #[test]
    fn unit_test_keygen_sign_v1_v2_v3() {
        let settings = HashMap::<String, String>::from([
            ("db".to_string(), "local".to_string()),
            ("db_name".to_string(), "KeyGenSign".to_string()),
        ]);

        let server = server::get_server(settings);

        let client = Client::tracked(server).expect("invalid rocket instance");

        let message = BigInt::from(1234u32);

        let customer_id = Uuid::new_v4().to_string();
        let (id, master_key_2): (String, MasterKey2) = key_gen(&client, customer_id.clone(), "/ecdsa/keygen".to_string());

        let signature: Party1SignatureRecid = sign(
            &client,
            id.clone(),
            customer_id.clone(),
            &master_key_2,
            message.clone(),
            SignVersion::V1,
        );
        info!(
            "Sign V1: s = (r: {}, s: {}, recid: {})",
            signature.r.to_hex(),
            signature.s.to_hex(),
            signature.recid
        );


        let signature: Party1SignatureRecid = sign(
            &client,
            id.clone(),
            customer_id.clone(),
            &master_key_2,
            message.clone(),
            SignVersion::V2,
        );
        info!(
        "Sign V2: s = (r: {}, s: {}, recid: {})",
            signature.r.to_hex(),
            signature.s.to_hex(),
            signature.recid
        );

        let signature: Party1SignatureRecid = sign(
            &client,
            id.clone(),
            customer_id.clone(),
            &master_key_2,
            message.clone(),
            SignVersion::V3,
        );
        info!(
        "Sign V3: s = (r: {}, s: {}, recid: {})",
            signature.r.to_hex(),
            signature.s.to_hex(),
            signature.recid
        );
    }

    #[test]
    fn unit_test_keygen_sign_rotate() {
        let settings = HashMap::<String, String>::from([
            ("db".to_string(), "local".to_string()),
            ("db_name".to_string(), "KeyGenSignRotate".to_string()),
        ]);


        let server = server::get_server(settings);

        let client = Client::tracked(server).expect("invalid rocket instance");

        let message = BigInt::from(1234u32);

        let customer_id = Uuid::new_v4().to_string();
        let (id, master_key_2): (String, MasterKey2) = key_gen(&client, customer_id.clone(), "/ecdsa/keygen".to_string());


    }
}
