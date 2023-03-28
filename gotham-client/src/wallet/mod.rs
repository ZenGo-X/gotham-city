// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use two_party_ecdsa::curv::elliptic::curves::secp256_k1::{GE};
use two_party_ecdsa::curv::elliptic::curves::traits::ECPoint;
use electrumx_client::{electrumx_client::ElectrumxClient, interface::Electrumx};
use kms::ecdsa::two_party::MasterKey2;
use kms::ecdsa::two_party::*;
use mockall::*;
use serde_json;
use std::fs;
use uuid::Uuid;
use two_party_ecdsa::curv::PK;
use kms::chain_code::two_party::party2::ChainCode2;
// use secp256k1::{ecdsa::Signature, Message, SECP256K1,PublicKey,ecdsa::RecoveryId,ecdsa::};
use secp256k1::{ecdsa::Signature,Error,SECP256K1, Message, PublicKey, Secp256k1, SecretKey, Signing, Verification};

use std::str;
use super::ecdsa;
use super::ecdsa::types::PrivateShare;
use super::escrow;
use super::ClientShim;
pub use two_party_ecdsa::curv::{arithmetic::traits::Converter, BigInt};
use sha2::{Sha256, Digest};

use hex;
use itertools::Itertools;
use std::collections::HashMap;
use std::str::FromStr;
use log::debug;
use two_party_ecdsa::centipede::juggling::proof_system::Proof;
use two_party_ecdsa::centipede::juggling::segmentation::Msegmentation;
use two_party_ecdsa::{Helgamalsegmented, party_one};
use crate::Client;

const WALLET_FILENAME: &str = "mywallet";



#[derive(Serialize, Deserialize)]
pub struct SignSecondMsgRequest {
    pub message: BigInt,
    pub party_two_sign_message: party2::SignMessage,
    pub pos_child_key: u32,
}



#[derive(Serialize, Deserialize)]
pub struct AddressDerivation {
    pub pos: u32,
    pub mk: MasterKey2,
}

#[derive(Serialize, Deserialize)]
pub struct Wallet {
    pub id: String,
    pub network: String,
    pub private_share: PrivateShare,
    pub last_derived_pos: u32,
    pub addresses_derivation_map: HashMap<String, AddressDerivation>,
}

impl Wallet {
    pub fn new<C: Client>(client_shim: &ClientShim<C>, net: &str) -> Wallet {
        let id = Uuid::new_v4().to_string();
        let private_share = ecdsa::get_master_key(client_shim);
        let last_derived_pos = 0;
        let addresses_derivation_map = HashMap::new();
        let network = net;

        Wallet {
            id,
            network: network.to_string(),
            private_share,
            last_derived_pos,
            addresses_derivation_map,
        }
    }



    pub fn save_to(&self, filepath: &str) {
        let wallet_json = serde_json::to_string(self).unwrap();

        fs::write(filepath, wallet_json).expect("Unable to save wallet!");

        debug!("(wallet id: {}) Saved wallet to disk", self.id);
    }

    pub fn save(&self) {
        self.save_to(WALLET_FILENAME)
    }

    pub fn load_from(filepath: &str) -> Wallet {
        let data = fs::read_to_string(filepath).expect("Unable to load wallet!");

        let wallet: Wallet = serde_json::from_str(&data).unwrap();
        debug!("(wallet id: {}) Loaded wallet to memory", wallet.id);

        wallet
    }

    pub fn load() -> Wallet {
        Wallet::load_from(WALLET_FILENAME)
    }

    pub fn sign<C: Client>(
        &mut self,
        msg: &[u8],
        client_shim: &ClientShim<C>,
    ) {

        //derive a master client new key from msk by forwording the counter +1
        let (pos,child_master_key) = Wallet::derive_new_key(&self.private_share,self.last_derived_pos);
        self.last_derived_pos=pos;
        self.save();
            let signature = ecdsa::sign(
                client_shim,
                BigInt::from(&msg[..]),
                &child_master_key,
                BigInt::from(0),
                BigInt::from(self.last_derived_pos),
                &self.private_share.id,
            ).expect("ECDSA signature failed");

        let r = BigInt::to_vec(&signature.r);
        let s = BigInt::to_vec(&signature.s);

        let message = Message::from_slice(msg).unwrap();

        println!("hash{:?},\n signature: [r={},s={}]",msg,&signature.r,&signature.s);

        //prepare signature to be verified from secp256k1 lib

        let mut sig = [0u8; 64];
        sig[32 - r.len()..32].copy_from_slice(&r);
        sig[32 + 32 - s.len()..].copy_from_slice(&s);

        let Sig = Signature::from_compact(&sig).unwrap();
        let pk = child_master_key.public.q.get_element();

        let secp = Secp256k1::new();
        let id = secp256k1::ecdsa::RecoveryId::from_i32(signature.recid as i32).unwrap();
        let sig = secp256k1::ecdsa::RecoverableSignature::from_compact(&sig, id).unwrap();

        assert_eq!(
            secp.recover_ecdsa(&message, &sig),
            Ok(pk)
        );
        println!("Trying to recover pk from r,s,recid");
        println!("Recovered pk:{:?}",secp.recover_ecdsa(&message, &sig));
        println!("pk:{:?}",pk);


        SECP256K1.verify_ecdsa(&message, &Sig, &pk).unwrap();
    }



    fn derive_new_key(private_share: &PrivateShare, pos: u32) -> (u32, MasterKey2) {
        let last_pos: u32 = pos + 1;

        let last_child_master_key = private_share
            .master_key
            .get_child(vec![BigInt::from(0), BigInt::from(last_pos)]);

        (last_pos, last_child_master_key)
    }


}


