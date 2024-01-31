// Gotham-city
//
// Copyright 2018 by Kzen Networks (kzencorp.com)
// Gotham city is free software: you can redistribute
// it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//

use bitcoin;
use bitcoin::consensus::encode::serialize;

use bitcoin::network::constants::Network;
use bitcoin::secp256k1::Signature;
use bitcoin::util::bip143::SigHashCache;
use bitcoin::{Address, SigHashType, TxIn, TxOut};
use electrumx_client::interface::Electrumx;
use hex;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs;
use two_party_ecdsa::centipede::juggling::proof_system::{Helgamalsegmented, Proof};
use two_party_ecdsa::curv::elliptic::curves::secp256_k1::{GE, PK};
use two_party_ecdsa::curv::elliptic::curves::traits::ECPoint;
use two_party_ecdsa::curv::BigInt;
use two_party_ecdsa::kms::ecdsa::two_party::MasterKey2;
use two_party_ecdsa::kms::ecdsa::two_party::*;
use uuid::Uuid;

use client_lib::ecdsa;
use client_lib::ecdsa::types::PrivateShare;
use client_lib::Client;
use client_lib::ClientShim;
use itertools::Itertools;
use log::debug;
use std::collections::HashMap;

use std::process::exit;
use std::str::FromStr;
use two_party_ecdsa::curv::arithmetic::traits::Converter;

pub mod commands;
pub mod escrow;

/*
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

 */

#[derive(Serialize, Deserialize)]
pub struct SignSecondMsgRequest {
    pub message: BigInt,
    pub party_two_sign_message: party2::SignMessage,
    pub pos_child_key: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GetBalanceResponse {
    pub address: String,
    pub confirmed: u64,
    pub unconfirmed: i128,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GetListUnspentResponse {
    pub height: usize,
    pub tx_hash: String,
    pub tx_pos: usize,
    pub value: usize,
    pub address: String,
}

#[derive(Debug, Deserialize)]
pub struct GetWalletBalanceResponse {
    pub confirmed: u64,
    pub unconfirmed: i128,
}

#[derive(Serialize, Deserialize)]
pub struct AddressDerivation {
    pub pos: u32,
    pub mk: MasterKey2,
}

#[derive(Serialize, Deserialize)]
pub struct BitcoinWallet {
    pub id: String,
    pub network: String,
    pub private_share: PrivateShare,
    pub last_derived_pos: u32,
    pub addresses_derivation_map: HashMap<String, AddressDerivation>,
}

impl BitcoinWallet {
    pub fn new<C: Client>(client_shim: &ClientShim<C>, net: &str) -> BitcoinWallet {
        let id = Uuid::new_v4().to_string();
        let private_share = ecdsa::get_master_key(client_shim);
        let last_derived_pos = 0;
        let addresses_derivation_map = HashMap::new();

        BitcoinWallet {
            id,
            network: net.to_string(),
            private_share,
            last_derived_pos,
            addresses_derivation_map,
        }
    }

    // Rotation is not up to date
    // pub fn rotate<C: Client>(self, client_shim: &ClientShim<C>) -> Self {
    //     ecdsa::rotate_master_key(self, client_shim)
    // }

    pub fn backup(&self, escrow_service: escrow::Escrow, path: &str) {
        let g: GE = ECPoint::generator();
        let y = escrow_service.get_public_key();
        let (segments, encryptions) = self.private_share.master_key.private.to_encrypted_segment(
            &escrow::SEGMENT_SIZE,
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

        fs::write(path, client_backup_json).expect("Unable to save client backup!");

        debug!("(wallet id: {}) Backup wallet with escrow", self.id);
    }

    pub fn verify_backup(&self, escrow_service: escrow::Escrow, path: &str) {
        let g: GE = ECPoint::generator();
        let y = escrow_service.get_public_key();

        let data = fs::read_to_string(path).expect("Unable to load client backup!");
        let (encryptions, proof, client_public, _, _): (
            Helgamalsegmented,
            Proof,
            Party2Public,
            String,
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

    /*
        // recover_master_key was removed from MasterKey2 in version 2.0
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
    */
    pub fn save_to(&self, path: &str) {
        let wallet_json = serde_json::to_string_pretty(self).unwrap();

        fs::write(path, wallet_json).expect("Unable to save wallet!");

        debug!("(wallet id: {}) Saved wallet to disk", self.id);
    }

    pub fn load_from(path: &str) -> BitcoinWallet {
        let data = fs::read_to_string(path).expect("Unable to load wallet!");

        let wallet: BitcoinWallet = serde_json::from_str(&data).unwrap();

        debug!("(wallet id: {}) Loaded wallet to memory", wallet.id);

        wallet
    }

    pub fn send<C: Client>(
        &mut self,
        to_address: &String,
        amount_btc: f32,
        client_shim: &ClientShim<C>,
        electrumx: &mut dyn Electrumx,
    ) -> String {
        let selected = self.select_tx_in(amount_btc, electrumx);
        if selected.is_empty() {
            println!("Insufficient funds");
            exit(-1);
        }

        let to_btc_adress = bitcoin::Address::from_str(to_address).unwrap();

        let txs_in: Vec<TxIn> = selected
            .clone()
            .into_iter()
            .map(|s| bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: s.tx_hash.parse().unwrap(),
                    vout: s.tx_pos as u32,
                },
                script_sig: bitcoin::Script::default(),
                sequence: 0xFFFFFFFF,
                witness: Vec::default(),
            })
            .collect();

        // TODO: bring back correct fees and amount calculation
        // let fees = 10_000;

        let amount_satoshi = (amount_btc * 100_000_000 as f32) as u64;

        let change_address = self.get_new_bitcoin_address();

        let total_selected = selected
            .clone()
            .into_iter()
            .fold(0, |sum, val| sum + val.value) as u64;

        let txs_out = vec![
            TxOut {
                value: amount_satoshi,
                script_pubkey: to_btc_adress.payload.script_pubkey(),
            },
            TxOut {
                value: total_selected - amount_satoshi, //- fees,
                script_pubkey: change_address.payload.script_pubkey(),
            },
        ];

        let transaction = bitcoin::Transaction {
            version: 0,
            lock_time: 0,
            input: txs_in,
            output: txs_out,
        };

        let mut signed_transaction = transaction.clone();

        for (idx, item) in selected.iter().enumerate() {
            let address_derivation = self.addresses_derivation_map.get(&item.address).unwrap();

            let mk = &address_derivation.mk;
            let pk = mk.public.q.get_element();

            let script_code = &Address::p2pkh(
                &Self::to_bitcoin_public_key(&pk),
                self.get_bitcoin_network(),
            )
            .script_pubkey();

            let mut cash = SigHashCache::new(&transaction);
            let sig_hash = cash.signature_hash(
                idx,
                script_code,
                (item.value as u64).into(),
                SigHashType::All,
            );

            let signature = ecdsa::sign(
                client_shim,
                BigInt::from(&sig_hash[..]),
                mk,
                vec![BigInt::from(0u32), BigInt::from(address_derivation.pos)],
                &self.private_share.id,
            )
            .unwrap();

            let mut v = BigInt::to_vec(&signature.r);
            v.extend(BigInt::to_vec(&signature.s));

            let mut sig_vec = Signature::from_compact(&v[..])
                .unwrap()
                .serialize_der()
                .to_vec();

            sig_vec.push(01);
            let mut witness = Vec::new();
            witness.push(sig_vec);
            witness.push(pk.serialize().to_vec());

            signed_transaction.input[idx].witness = witness;
        }

        let raw_tx_hex = hex::encode(serialize(&signed_transaction));
        let txid = electrumx.broadcast_transaction(raw_tx_hex);

        txid.unwrap()
    }

    pub fn get_new_bitcoin_address(&mut self) -> bitcoin::Address {
        let (pos, mk) = Self::derive_new_key(&self.private_share, self.last_derived_pos);
        let pk = mk.public.q.get_element();
        let address = bitcoin::Address::p2wpkh(
            &Self::to_bitcoin_public_key(&pk),
            self.get_bitcoin_network(),
        )
        .unwrap();

        self.addresses_derivation_map
            .insert(address.to_string(), AddressDerivation { mk, pos });

        self.last_derived_pos = pos;

        address
    }

    pub fn derived(&mut self) {
        for i in 0..self.last_derived_pos {
            let (pos, mk) = Self::derive_new_key(&self.private_share, i);

            let address = Self::to_bitcoin_address(&mk, self.get_bitcoin_network());
            self.addresses_derivation_map
                .insert(address.to_string(), AddressDerivation { mk, pos });
        }
    }

    pub fn get_balance(&mut self, electrumx: &mut dyn Electrumx) -> GetWalletBalanceResponse {
        let mut aggregated_balance = GetWalletBalanceResponse {
            confirmed: 0,
            unconfirmed: 0,
        };

        for b in self.get_all_addresses_balance(electrumx) {
            aggregated_balance.unconfirmed += b.unconfirmed;
            aggregated_balance.confirmed += b.confirmed;
        }

        aggregated_balance
    }

    // TODO: handle fees
    pub fn select_tx_in(
        &self,
        amount_btc: f32,
        electrumx: &mut dyn Electrumx,
    ) -> Vec<GetListUnspentResponse> {
        // greedy selection
        let list_unspent: Vec<GetListUnspentResponse> = self
            .get_all_addresses_balance(electrumx)
            .into_iter()
            .filter(|b| b.confirmed > 0)
            .map(|a| self.list_unspent_for_addresss(a.address.to_string(), electrumx))
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

    pub fn list_unspent(&self, electrumx: &mut dyn Electrumx) -> Vec<GetListUnspentResponse> {
        let response: Vec<GetListUnspentResponse> = self
            .get_all_addresses()
            .into_iter()
            .map(|a| self.list_unspent_for_addresss(a.to_string(), electrumx))
            .flatten()
            .collect();

        response
    }

    /* PRIVATE */
    fn list_unspent_for_addresss(
        &self,
        address: String,
        electrumx: &mut dyn Electrumx,
    ) -> Vec<GetListUnspentResponse> {
        let resp = electrumx.get_list_unspent(&address).unwrap();

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

    fn get_all_addresses_balance(&self, electrumx: &mut dyn Electrumx) -> Vec<GetBalanceResponse> {
        let response: Vec<GetBalanceResponse> = self
            .get_all_addresses()
            .into_iter()
            // .map(|a| Self::get_address_balance(&a))
            .map(|a| self.get_balance_by_address(electrumx, &a))
            .collect();
        response
    }

    fn get_balance_by_address(
        &self,
        electrumx: &mut dyn Electrumx,
        a: &Address,
    ) -> GetBalanceResponse {
        let response = electrumx.get_balance(&a.to_string()).unwrap();

        GetBalanceResponse {
            confirmed: response.confirmed,
            unconfirmed: response.unconfirmed,
            address: a.to_string(),
        }
    }

    fn get_all_addresses(&self) -> Vec<bitcoin::Address> {
        let init = 0;
        let last_pos = self.last_derived_pos;

        let mut response: Vec<bitcoin::Address> = Vec::new();

        for n in init..=last_pos {
            let mk = self
                .private_share
                .master_key
                .get_child(vec![BigInt::from(0), BigInt::from(n)]);
            let bitcoin_address = Self::to_bitcoin_address(&mk, self.get_bitcoin_network());

            response.push(bitcoin_address);
        }

        response
    }

    fn derive_new_key(private_share: &PrivateShare, pos: u32) -> (u32, MasterKey2) {
        let last_pos: u32 = pos + 1;

        let last_child_master_key = private_share
            .master_key
            .get_child(vec![BigInt::from(0), BigInt::from(last_pos)]);

        (last_pos, last_child_master_key)
    }

    fn get_bitcoin_network(&self) -> Network {
        self.network.parse::<Network>().unwrap()
    }

    fn to_bitcoin_address(mk: &MasterKey2, network: Network) -> bitcoin::Address {
        bitcoin::Address::p2wpkh(
            &Self::to_bitcoin_public_key(&mk.public.q.get_element()),
            network,
        )
        .unwrap()
    }

    fn to_bitcoin_public_key(pk: &PK) -> bitcoin::util::key::PublicKey {
        bitcoin::util::key::PublicKey::from_slice(&pk.serialize()).unwrap()
    }
}
