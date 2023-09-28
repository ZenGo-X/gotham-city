#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::env;
    use std::time::Instant;
    use floating_duration::TimeFormat;
    use crate::server;
    use rocket::{http::ContentType, http::{Status}, local::blocking::Client};
    use two_party_ecdsa::{BigInt, party_one, party_two};
    use two_party_ecdsa::curv::cryptographic_primitives::twoparty::dh_key_exchange_variant_with_pok_comm::{Party1FirstMessage, Party1SecondMessage};
    use two_party_ecdsa::kms::ecdsa::two_party::{MasterKey2, party1};
    use two_party_ecdsa::kms::chain_code::two_party::party2::ChainCode2;
    use two_party_ecdsa::kms::ecdsa;
    use gotham_engine::types::SignSecondMsgRequest;
    use two_party_ecdsa::party_one::Converter;

    fn key_gen(client: &Client) -> (String, MasterKey2) {
        let response = client
            .post("/ecdsa/keygen/first")
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let res_body = response.into_string().unwrap();

        let (id, kg_party_one_first_message): (String, party_one::KeyGenFirstMsg) =
            serde_json::from_str(&res_body).unwrap();


        let (kg_party_two_first_message, kg_ec_key_pair_party2) = MasterKey2::key_gen_first_message();

        /*************** END: FIRST MESSAGE ***************/

        /*************** START: SECOND MESSAGE ***************/
        let body = serde_json::to_string(&kg_party_two_first_message.d_log_proof).unwrap();
        let response = client
            .post(format!("/ecdsa/keygen/{}/second", id))
            .body(body)
            .header(ContentType::JSON)
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
            .post(format!("/ecdsa/keygen/{}/third", id))
            .body(body)
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let res_body = response.into_string().unwrap();
        let party_one_third_message: party_one::PDLFirstMessage =
            serde_json::from_str(&res_body).unwrap();

        let start = Instant::now();

        let pdl_decom_party2 = MasterKey2::key_gen_third_message(&party_two_pdl_chal);

        /*************** END: THIRD MESSAGE ***************/

        /*************** START: FOURTH MESSAGE ***************/

        let party_2_pdl_second_message = pdl_decom_party2;
        let request = party_2_pdl_second_message;
        let body = serde_json::to_string(&request).unwrap();


        let response = client
            .post(format!("/ecdsa/keygen/{}/fourth", id))
            .body(body)
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);


        let res_body = response.into_string().unwrap();
        let party_one_pdl_second_message: party_one::PDLSecondMessage =
            serde_json::from_str(&res_body).unwrap();


        MasterKey2::key_gen_fourth_message(
            &party_two_pdl_chal,
            &party_one_third_message,
            &party_one_pdl_second_message,
        )
            .expect("pdl error party1");

        /*************** START: CHAINCODE FIRST MESSAGE ***************/

        let response = client
            .post(format!("/ecdsa/keygen/{}/chaincode/first", id))
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);


        let res_body = response.into_string().unwrap();
        let cc_party_one_first_message: Party1FirstMessage = serde_json::from_str(&res_body).unwrap();

        let (cc_party_two_first_message, cc_ec_key_pair2) =
            ChainCode2::chain_code_first_message();


        /*************** END: CHAINCODE FIRST MESSAGE ***************/

        /*************** START: CHAINCODE SECOND MESSAGE ***************/
        let body = serde_json::to_string(&cc_party_two_first_message.d_log_proof).unwrap();


        let response = client
            .post(format!("/ecdsa/keygen/{}/chaincode/second", id))
            .body(body)
            .header(ContentType::JSON)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let res_body = response.into_string().unwrap();
        let cc_party_one_second_message: Party1SecondMessage = serde_json::from_str(&res_body).unwrap();

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
        master_key_2: MasterKey2,
        message: BigInt,
    ) -> party_one::SignatureRecid {
        let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
            MasterKey2::sign_first_message();

        let request: party_two::EphKeyGenFirstMsg = eph_key_gen_first_message_party_two;

        let body = serde_json::to_string(&request).unwrap();


        let response = client
            .post(format!("/ecdsa/sign/{}/first", id))
            .body(body)
            .header(ContentType::JSON)
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
            .dispatch();
        assert_eq!(response.status(), Status::Ok);



        let res_body = response.into_string().unwrap();
        let signature_recid: party_one::SignatureRecid = serde_json::from_str(&res_body).unwrap();

        signature_recid
    }



    #[test]
    fn key_gen_and_sign() {
        // Passthrough mode
        env::set_var("region", "");
        env::set_var("pool_id", "");
        env::set_var("issuer", "");
        env::set_var("audience", "");
        // env::set_var("ELASTICACHE_URL", "127.0.0.1");

        let settings = HashMap::<String, String>::from([
            ("db".to_string(), "local".to_string()),
            ("db_name".to_string(), "KeyGenAndSign".to_string()),
        ]);
        let server = server::get_server(settings);
        let client = Client::tracked(server).expect("valid rocket instance");
        let (id,master_key_2) = key_gen(&client);

        let message = BigInt::from(1234u32);

        let signature: party_one::SignatureRecid =
            sign(&client, id.clone(), master_key_2, message.clone());

        println!(
            "s = (r: {}, s: {}, recid: {})",
            signature.r.to_hex(),
            signature.s.to_hex(),
            signature.recid
        );
        //test v2 sign interface with session id enabled
    }
}
