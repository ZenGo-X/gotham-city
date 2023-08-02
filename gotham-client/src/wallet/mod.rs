// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

<<<<<<< HEAD
use two_party_ecdsa::curv::elliptic::curves::secp256_k1::{GE};
use two_party_ecdsa::curv::elliptic::curves::traits::ECPoint;
use electrumx_client::{electrumx_client::ElectrumxClient, interface::Electrumx};
use kms::ecdsa::two_party::MasterKey2;
use kms::ecdsa::two_party::*;
use mockall::*;
=======
use bitcoin;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::{hex::FromHex, sha256d};
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::Signature;
use bitcoin::util::bip143::SighashComponents;
use bitcoin::{TxIn, TxOut, Txid};
use curv::elliptic::curves::secp256_k1::{GE, PK};
use curv::elliptic::curves::traits::ECPoint;
use curv::BigInt;
use electrumx_client::{electrumx_client::ElectrumxClient, interface::Electrumx};
use kms::ecdsa::two_party::MasterKey2;
use kms::ecdsa::two_party::*;
use mockall::automock;
>>>>>>> master
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
use secp256k1::Signature;
use std::collections::HashMap;
use std::str::FromStr;
use log::debug;
use two_party_ecdsa::centipede::juggling::proof_system::Proof;
use two_party_ecdsa::centipede::juggling::segmentation::Msegmentation;
use two_party_ecdsa::{Helgamalsegmented, party_one};
use crate::Client;

const WALLET_FILENAME: &str = "mywallet";



#[automock]
pub trait BalanceFetcher {
    fn get_balance(&mut self, address: &bitcoin::Address) -> GetBalanceResponse;
}

pub struct ElectrumxBalanceFetcher {
    client: ElectrumxClient<String>,
}

impl ElectrumxBalanceFetcher {
    pub fn new(url: &str) -> Self {
        Self {
            client: ElectrumxClient::new(url.to_string()).unwrap(),
        }
    }
}

impl BalanceFetcher for ElectrumxBalanceFetcher {
    fn get_balance(&mut self, address: &bitcoin::Address) -> GetBalanceResponse {
        let resp = self.client.get_balance(&address.to_string()).unwrap();

        GetBalanceResponse {
            confirmed: resp.confirmed,
            unconfirmed: resp.unconfirmed,
            address: address.to_string(),
        }
    }
}

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

<<<<<<< HEAD

=======
    pub fn rotate<C: Client>(self, client_shim: &ClientShim<C>) -> Self {
        ecdsa::rotate_master_key(self, client_shim)
    }

    pub fn backup(&self, escrow_service: escrow::Escrow) {
        let g: GE = ECPoint::generator();
        let y = escrow_service.get_public_key();
        let (segments, encryptions) = self.private_share.master_key.private.to_encrypted_segment(
            escrow::SEGMENT_SIZE,
            escrow::NUM_SEGMENTS,
            &y,
            &g,
        );

        let proof = Proof::prove(&segments, &encryptions, &g, &y, &escrow::SEGMENT_SIZE);

        let client_backup_json = serde_json::to_string(&(
            encryptions,
            proof,
            self.private_share.master_key.public.clone(),
            self.private_share.master_key.chain_code.clone(),
            self.private_share.id.clone(),
        ))
        .unwrap();

        fs::write(BACKUP_FILENAME, client_backup_json).expect("Unable to save client backup!");

        debug!("(wallet id: {}) Backup wallet with escrow", self.id);
    }

    pub fn verify_backup(&self, escrow_service: escrow::Escrow) {
        let g: GE = ECPoint::generator();
        let y = escrow_service.get_public_key();

        let data = fs::read_to_string(BACKUP_FILENAME).expect("Unable to load client backup!");
        let (encryptions, proof, client_public, _, _): (
            Helgamalsegmented,
            Proof,
            Party2Public,
            ChainCode2,
            String,
        ) = serde_json::from_str(&data).unwrap();
        let verify = proof.verify(
            &encryptions,
            &g,
            &y,
            &client_public.p2,
            &escrow::SEGMENT_SIZE,
        );
        match verify {
            Ok(_x) => println!("backup verified 🍻"),
            Err(_e) => println!("Backup was not verified correctly 😲"),
        }
    }

    pub fn recover_and_save_share<C: Client>(
        escrow_service: escrow::Escrow,
        net: &str,
        client_shim: &ClientShim<C>,
    ) -> Wallet {
        let g: GE = ECPoint::generator();
        let y_priv = escrow_service.get_private_key();

        let data = fs::read_to_string(BACKUP_FILENAME).expect("Unable to load client backup!");

        let (encryptions, _proof, public_data, chain_code2, key_id): (
            Helgamalsegmented,
            Proof,
            Party2Public,
            BigInt,
            String,
        ) = serde_json::from_str(&data).unwrap();

        let sk = Msegmentation::decrypt(&encryptions, &g, &y_priv, &escrow::SEGMENT_SIZE);

        let client_master_key_recovered =
            MasterKey2::recover_master_key(sk.unwrap(), public_data, chain_code2);
        let pos_old: u32 =
            client_shim.post(&format!("ecdsa/{}/recover", key_id)).unwrap();

        let pos_old = if pos_old < 10 { 10 } else { pos_old };
        //TODO: temporary, server will keep updated pos, to do so we need to send update to server for every get_new_address

        let id = Uuid::new_v4().to_string();
        let addresses_derivation_map = HashMap::new(); //TODO: add a fucntion to recreate
        let network = net;

        let new_wallet = Wallet {
            id,
            network: network.to_string(),
            private_share: PrivateShare {
                master_key: client_master_key_recovered,
                id: key_id,
            },
            last_derived_pos: pos_old,
            addresses_derivation_map,
        };

        new_wallet.save();
        println!("Recovery Completed Successfully ❤️");

        new_wallet
    }
>>>>>>> master

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

<<<<<<< HEAD
    pub fn sign<C: Client>(
        &mut self,
        msg: &[u8],
        client_shim: &ClientShim<C>,
    )-> Result<bool, Error> {

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

        println!("hash{:?},\nsignature: [r={},s={}]",msg,&signature.r,&signature.s);

        //prepare signature to be verified from secp256k1 lib

        let mut sig = [0u8; 64];
        sig[32 - r.len()..32].copy_from_slice(&r);
        sig[32 + 32 - s.len()..].copy_from_slice(&s);
=======
    pub fn send<E: BalanceFetcher, C: Client>(
        &mut self,
        to_address: String,
        amount_btc: f32,
        client_shim: &ClientShim<C>,
        fetcher: &mut E,
    ) -> String {
        let selected = self.select_tx_in(amount_btc, fetcher);
        if selected.is_empty() {
            panic!("Not enough fund");
        }

        let to_btc_adress = bitcoin::Address::from_str(&to_address).unwrap();

        let txs_in: Vec<TxIn> = selected
            .clone()
            .into_iter()
            .map(|s| bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::util::hash::Sha256dHash::from_hex(&s.tx_hash).unwrap(),
                    vout: s.tx_pos as u32,
                },
                script_sig: bitcoin::Script::default(),
                sequence: 0xFFFFFFFF,
                witness: Vec::default(),
            })
            .collect();

        let fees = 10_000;

        let amount_satoshi = (amount_btc * 100_000_000 as f32) as u64;

        let change_address = self.get_new_bitcoin_address();

        let total_selected = selected
            .clone()
            .into_iter()
            .fold(0, |sum, val| sum + val.value) as u64;

        let txs_out = vec![
            TxOut {
                value: amount_satoshi,
                script_pubkey: to_btc_adress.script_pubkey(),
            },
            TxOut {
                value: total_selected - amount_satoshi - fees,
                script_pubkey: change_address.script_pubkey(),
            },
        ];

        let transaction = bitcoin::Transaction {
            version: 0,
            lock_time: 0,
            input: txs_in,
            output: txs_out,
        };

        let mut signed_transaction = transaction.clone();

        for (i, item) in selected.iter().enumerate().take(transaction.input.len()) {
            let address_derivation = self.addresses_derivation_map.get(&item.address).unwrap();

            let mk = &address_derivation.mk;
            let pk = mk.public.q.get_element();

            let comp = SighashComponents::new(&transaction);
            let sig_hash = comp.sighash_all(
                &transaction.input[i],
                &bitcoin::Address::p2pkh(&to_bitcoin_public_key(pk), self.get_bitcoin_network())
                    .script_pubkey(),
                (item.value as u32).into(),
            );

            let signature = ecdsa::sign(
                client_shim,
                BigInt::from_hex(&hex::encode(&sig_hash[..])).unwrap(),
                mk,
                BigInt::from(0u32),
                BigInt::from(address_derivation.pos),
                &self.private_share.id,
            )
            .unwrap();

            let mut v = BigInt::to_vec(&signature.r);
            v.extend(BigInt::to_vec(&signature.s));

            let mut sig_vec = Signature::from_compact(&v[..])
                .unwrap()
                .serialize_der()
                .to_vec();
            sig_vec.push(1);

            sig.push(01);
            let mut witness = Vec::new();
            witness.push(sig);
            witness.push(pk.serialize().to_vec());

            signed_transaction.input[i].witness = witness;
        }

        let mut electrum = ElectrumxClient::new(ELECTRUM_HOST).unwrap();

        let raw_tx_hex = hex::encode(serialize(&signed_transaction));
        let txid = electrum.broadcast_transaction(raw_tx_hex);

        txid.unwrap()
    }

    pub fn get_new_bitcoin_address(&mut self) -> bitcoin::Address {
        let (pos, mk) = Self::derive_new_key(&self.private_share, self.last_derived_pos);
        let pk = mk.public.q.get_element();
        let address =
            bitcoin::Address::p2wpkh(&to_bitcoin_public_key(pk), self.get_bitcoin_network())
                .expect(
                    "Cannot panic because `to_bitcoin_public_key` creates a compressed address",
                );
>>>>>>> master

        let Sig = Signature::from_compact(&sig).unwrap();
        let pk = child_master_key.public.q.get_element();

        let secp = Secp256k1::new();
        //v = chain_id * 2 + 35 + recovery_id
        let id = secp256k1::ecdsa::RecoveryId::from_i32(signature.recid as i32).unwrap();
        let sig = secp256k1::ecdsa::RecoverableSignature::from_compact(&sig, id).unwrap();

<<<<<<< HEAD
        assert_eq!(
            secp.recover_ecdsa(&message, &sig),
            Ok(pk)
        );

        println!("Trying to recover pk from r,s,recid");
        println!("Recovered pk:{:?}",secp.recover_ecdsa(&message, &sig));
        println!("pk:{:?}",pk);


        Ok(SECP256K1.verify_ecdsa(&message, &Sig, &pk).is_ok())
=======
        address
    }

    pub fn derived(&mut self) {
        for i in 0..self.last_derived_pos {
            let (pos, mk) = Self::derive_new_key(&self.private_share, i);

            let address = bitcoin::Address::p2wpkh(
                &to_bitcoin_public_key(mk.public.q.get_element()),
                self.get_bitcoin_network(),
            )
            .expect("Cannot panic because `to_bitcoin_public_key` creates a compressed address");

            self.addresses_derivation_map
                .insert(address.to_string(), AddressDerivation { mk, pos });
        }
    }

    pub fn get_balance<E: BalanceFetcher>(&mut self, fetcher: &mut E) -> GetWalletBalanceResponse {
        let mut aggregated_balance = GetWalletBalanceResponse {
            confirmed: 0,
            unconfirmed: 0,
        };

        for b in self.get_all_addresses_balance(fetcher) {
            aggregated_balance.unconfirmed += b.unconfirmed;
            aggregated_balance.confirmed += b.confirmed;
        }

        aggregated_balance
    }

    // TODO: handle fees
    pub fn select_tx_in<E: BalanceFetcher>(
        &self,
        amount_btc: f32,
        fetcher: &mut E,
    ) -> Vec<GetListUnspentResponse> {
        // greedy selection
        let list_unspent: Vec<GetListUnspentResponse> = self
            .get_all_addresses_balance(fetcher)
            .into_iter()
            .filter(|b| b.confirmed > 0)
            .map(|a| self.list_unspent_for_addresss(a.address.to_string()))
            .flatten()
            .sorted_by(|a, b| a.value.partial_cmp(&b.value).unwrap())
            .into_iter()
            .collect();

        let mut remaining: i64 = amount_btc as i64 * 100_000_000;
        let mut selected: Vec<GetListUnspentResponse> = Vec::new();

        for unspent in list_unspent {
            selected.push(unspent.clone());
            remaining -= unspent.value as i64;

            if remaining < 0 {
                break;
            }
        }

        selected
    }

    pub fn list_unspent(&self) -> Vec<GetListUnspentResponse> {
        let response: Vec<GetListUnspentResponse> = self
            .get_all_addresses()
            .into_iter()
            .map(|a| self.list_unspent_for_addresss(a.to_string()))
            .flatten()
            .collect();

        response
    }

    /* PRIVATE */
    fn list_unspent_for_addresss(&self, address: String) -> Vec<GetListUnspentResponse> {
        let mut client = ElectrumxClient::new(ELECTRUM_HOST).unwrap();

        let resp = client.get_list_unspent(&address).unwrap();

        resp.into_iter()
            .map(|u| GetListUnspentResponse {
                value: u.value,
                height: u.height,
                tx_hash: u.tx_hash,
                tx_pos: u.tx_pos,
                address: address.clone(),
            })
            .collect()
    }

    fn get_all_addresses_balance<E: BalanceFetcher>(
        &self,
        fetcher: &mut E,
    ) -> Vec<GetBalanceResponse> {
        let response: Vec<GetBalanceResponse> = self
            .get_all_addresses()
            .into_iter()
            // .map(|a| Self::get_address_balance(&a))
            .map(|a| fetcher.get_balance(&a))
            .collect();
        response
>>>>>>> master
    }



    fn derive_new_key(private_share: &PrivateShare, pos: u32) -> (u32, MasterKey2) {
        let last_pos: u32 = pos + 1;

        let last_child_master_key = private_share
            .master_key
            .get_child(vec![BigInt::from(0), BigInt::from(last_pos)]);

        (last_pos, last_child_master_key)
    }

<<<<<<< HEAD

}


=======
    fn get_bitcoin_network(&self) -> Network {
        self.network.parse::<Network>().unwrap()
    }

    fn to_bitcoin_address(mk: &MasterKey2, network: Network) -> bitcoin::Address {
        bitcoin::Address::p2wpkh(&to_bitcoin_public_key(mk.public.q.get_element()), network)
            .expect("Cannot panic because `to_bitcoin_public_key` creates a compressed address")
    }
}

// type conversion
fn to_bitcoin_public_key(pk: PK) -> bitcoin::util::key::PublicKey {
    bitcoin::util::key::PublicKey {
        compressed: true,
        key: pk,
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::hex::ToHex;
    use bitcoin::hashes::sha256d;
    use bitcoin::hashes::Hash;
    use curv::arithmetic::traits::Converter;
    use curv::BigInt;

    #[test]
    fn test_message_conv() {
        let message: [u8; 32] = [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        // 14abf5ed107ff58bf844ee7f447bec317c276b00905c09a45434f8848599597e
        let hash = Sha256dHash::from_data(&message);

        // 7e59998584f83454a4095c90006b277c31ec7b447fee44f88bf57f10edf5ab14
        let ser = hash.le_hex_string();

        // 57149727877124134702546803488322951680010683936655914236113461592936003513108
        let b: BigInt = BigInt::from_hex(&ser);

        println!("({},{},{})", hash, ser, b.to_hex());
    }
}
>>>>>>> master
