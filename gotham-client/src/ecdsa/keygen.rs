use rocket::local::Client;
use serde_json;

use super::super::utilities::requests;

const kg_path_pre : &str = "/ecdsa/keygen/";

pub fn get_master_key(client: &Client, verbose: bool) {
    println!("Generating master key...");
    let res_body = requests::post(
        client, &format!("{}/first", kg_path_pre), None);

    /*let (id, kg_party_one_first_message) :
        (String, party_one::KeyGenFirstMsg) =
            serde_json::from_str(&res_body.unwrap()).unwrap();*/
}