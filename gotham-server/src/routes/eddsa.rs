use rocket::{post, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::jwt::Claims;
use crate::storage::db;
use crate::Config;

use two_party_musig2_eddsa::{
    generate_partial_nonces, AggPublicKeyAndMusigCoeff, KeyPair, PartialSignature,
    PrivatePartialNonces, PublicPartialNonces, Signature,
};

use self::EddsaStruct::*;

#[derive(Debug)]
pub enum EddsaStruct {
    ClientPublicKey,
    ServerSecret,
    AggregatedPublicKey,
    ClientPublicPartialNonce,
    Message,
    ServerPrivatePartialNonces,
    ServerPublicPartialNonces,
}

impl db::MPCStruct for EddsaStruct {
    fn to_string(&self) -> String {
        format!("Eddsa{:?}", self)
    }
}

// creating a wrapper for dynamodb insertion compatibility
#[derive(Debug, Serialize, Deserialize)]
struct MessageStruct {
    message: Vec<u8>,
}

/// Generate a keypair for 2-party Ed25519 signing
#[post("/eddsa/keygen", format = "json", data = "<client_public_key_json>")]
pub async fn keygen(
    state: &State<Config>,
    claim: Claims,
    client_public_key_json: Json<[u8; 32]>,
) -> Result<Json<(String, [u8; 32])>, String> {
    let id = Uuid::new_v4().to_string();
    let (server_key_pair, server_secret) = KeyPair::create();

    // Compute aggregated pubkey and a "musig coefficient" used later for signing - fails if received invalid pubkey!
    let agg_pubkey = AggPublicKeyAndMusigCoeff::aggregate_public_keys(
        server_key_pair.pubkey(),
        client_public_key_json.0,
    )
    .or(Err("Invalid public key received from client!"))?;

    // Save state to DB
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &ClientPublicKey,
        &client_public_key_json.0,
    )
    .await
    .or(Err("Failed to insert into db"))?;
    db::insert(&state.db, &claim.sub, &id, &ServerSecret, &server_secret)
        .await
        .or(Err("Failed to insert into db"))?;
    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &AggregatedPublicKey,
        &agg_pubkey,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    // Send server public key to client
    Ok(Json((id, server_key_pair.pubkey())))
}

#[post("/eddsa/sign/<id>/first", format = "json", data = "<client_first_msg>")]
pub async fn sign_first(
    state: &State<Config>,
    claim: Claims,
    id: String,
    client_first_msg: Json<(PublicPartialNonces, Vec<u8>)>,
) -> Result<Json<PublicPartialNonces>, String> {
    let (client_nonces, message): (PublicPartialNonces, Vec<u8>) = client_first_msg.0;

    // Check client nonces validity
    let client_nonces_bytes = client_nonces.serialize();
    match PublicPartialNonces::deserialize(client_nonces_bytes) {
        Some(_) => (),
        None => return Err("Received invalid public nonces from client!".to_string()),
    }

    let server_secret: [u8; 32] = db::get(&state.db, &claim.sub, &id, &ServerSecret)
        .await
        .or(Err("Failed to get from db"))?
        .ok_or(format!("No data for such identifier {}", id))?;

    let server_key_pair = KeyPair::create_from_private_key(server_secret);

    // Generate partial nonces.
    let (private_nonces, public_nonces) =
        generate_partial_nonces(&server_key_pair, Some(&message[..]));

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &ClientPublicPartialNonce,
        &client_nonces,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    let message_struct = MessageStruct { message };
    db::insert(&state.db, &claim.sub, &id, &Message, &message_struct)
        .await
        .or(Err("Failed to insert into db"))?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &ServerPrivatePartialNonces,
        &private_nonces,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    db::insert(
        &state.db,
        &claim.sub,
        &id,
        &ServerPublicPartialNonces,
        &public_nonces,
    )
    .await
    .or(Err("Failed to insert into db"))?;

    Ok(Json(public_nonces))
}

#[allow(non_snake_case)]
#[post(
    "/eddsa/sign/<id>/second",
    format = "json",
    data = "<client_partial_sig>"
)]
pub async fn sign_second(
    state: &State<Config>,
    claim: Claims,
    id: String,
    client_partial_sig: Json<PartialSignature>,
) -> Result<Json<PartialSignature>, String> {
    // Validate client partial signature
    let client_partial_sig_bytes = client_partial_sig.0.serialize();
    match PartialSignature::deserialize(client_partial_sig_bytes) {
        Some(_) => (),
        None => return Err("Received invalid partial signature from client!".to_string()),
    }

    // Retrieve state from db
    let server_secret: [u8; 32] = db::get(&state.db, &claim.sub, &id, &ServerSecret)
        .await
        .or(Err("Failed to get from db"))?
        .ok_or(format!("No data for such identifier {}", id))?;

    let server_key_pair = KeyPair::create_from_private_key(server_secret);

    let server_private_nonces: PrivatePartialNonces =
        db::get(&state.db, &claim.sub, &id, &ServerPrivatePartialNonces)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;

    let server_public_nonces: PublicPartialNonces =
        db::get(&state.db, &claim.sub, &id, &ServerPublicPartialNonces)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;

    let client_public_nonces: PublicPartialNonces =
        db::get(&state.db, &claim.sub, &id, &ClientPublicPartialNonce)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;

    let agg_pubkey: AggPublicKeyAndMusigCoeff =
        db::get(&state.db, &claim.sub, &id, &AggregatedPublicKey)
            .await
            .or(Err("Failed to get from db"))?
            .ok_or(format!("No data for such identifier {}", id))?;

    let message: MessageStruct = db::get(&state.db, &claim.sub, &id, &Message)
        .await
        .or(Err("Failed to get from db"))?
        .ok_or(format!("No data for such identifier {}", id))?;

    // Compute server partial sig
    let (server_partial_sig, agg_nonce) = server_key_pair.partial_sign(
        server_private_nonces,
        [client_public_nonces, server_public_nonces],
        &agg_pubkey,
        &message.message[..],
    );

    // Aggregate the partial signatures together
    let signature = Signature::aggregate_partial_signatures(
        agg_nonce,
        [server_partial_sig.clone(), client_partial_sig.0],
    );

    // Make sure the signature verifies against the aggregated public key
    match signature.verify(&message.message[..], agg_pubkey.aggregated_pubkey()) {
        Ok(_) => (),
        Err(_) => return Err("Signature did not pass verfification!".to_string()),
    };

    Ok(Json(server_partial_sig))
}
