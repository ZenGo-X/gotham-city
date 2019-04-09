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
use bitcoin::util::bip143::SighashComponents;
use bitcoin::{TxIn, TxOut};
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{BigInt, GE};
use electrumx_client::{electrumx_client::ElectrumxClient, interface::Electrumx};
use kms::ecdsa::two_party_gg18::MasterKey1;
use kms::ecdsa::two_party_lindell17::MasterKey2;
use serde_json;
use std::fs;
use uuid::Uuid;

use centipede::juggling::proof_system::{Helgamalsegmented, Proof};
use centipede::juggling::segmentation::Msegmentation;

use super::api;
use super::api::PrivateShare;
use super::api::PrivateShareGG;
use super::ecdsa::keygen;
use super::ecdsa::rotate;
use super::ecdsa::rotate_legacy;

use super::escrow;
use super::utilities::requests;
use curv::arithmetic::traits::Converter;
use hex;
use itertools::Itertools;
use kms::ecdsa::two_party_lindell17::Party2Public;
use secp256k1::Signature;
use std::collections::HashMap;
use std::str::FromStr;

// TODO: move that to a config file and double check electrum server addresses
const ELECTRUM_HOST: &str = "ec2-34-219-15-143.us-west-2.compute.amazonaws.com:60001";
//const ELECTRUM_HOST: &str = "testnet1.bauerj.eu:51001";
const WALLET_FILENAME: &str = "wallet/wallet.data";
const BACKUP_FILENAME: &str = "wallet/backup.data";

#[derive(Debug, Deserialize, Clone)]
pub struct GetBalanceResponse {
    pub address: String,
    pub confirmed: u64,
    pub unconfirmed: u64,
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
    pub unconfirmed: u64,
}

#[derive(Serialize, Deserialize)]
pub struct AddressDerivation {
    pub pos: u32,
    pub mk: MasterKey2,
}

#[derive(Serialize, Deserialize)]
pub struct AddressDerivationNew {
    pub pos: u32,
    pub mk: MasterKey1,
}

#[derive(Serialize, Deserialize)]
pub struct Wallet {
    pub id: String,
    pub network: String,
    pub private_share: PrivateShare,
    pub last_derived_pos: u32,
    pub addresses_derivation_map: HashMap<String, AddressDerivation>,
}

#[derive(Serialize, Deserialize)]
pub struct WalletNew {
    pub id: String,
    pub network: String,
    pub private_share: PrivateShareGG,
    pub last_derived_pos: u32,
    pub addresses_derivation_map: HashMap<String, AddressDerivationNew>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
struct HDPos {
    pos: u32,
}

impl Wallet {
    pub fn new(client_shim: &api::ClientShim, net: &String) -> Wallet {
        let id = Uuid::new_v4().to_string();
        let private_share = api::get_master_key(client_shim);
        let last_derived_pos = 0;
        let addresses_derivation_map = HashMap::new();
        let network = net.clone();

        Wallet {
            id,
            network,
            private_share,
            last_derived_pos,
            addresses_derivation_map,
        }
    }

    pub fn rotate(self, client_shim: &api::ClientShim) -> Self {
        rotate_legacy::rotate_master_key(self, client_shim)
    }

    pub fn backup(&self, escrow_service: escrow::Escrow) {
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
            BigInt,
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

    pub fn recover_and_save_share(
        escrow_service: escrow::Escrow,
        net: &String,
        client_shim: &api::ClientShim,
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
            MasterKey2::recover_master_key(sk, public_data, chain_code2);
        let res_body =
            requests::post(client_shim, &format!("ecdsa/{}/recover_legacy", key_id)).unwrap();

        let pos_old: HDPos = serde_json::from_str(&res_body).unwrap();
        let pos_old = if pos_old.pos < 10 { 10 } else { pos_old.pos };
        //TODO: temporary, server will keep updated pos, to do so we need to send update to server for every get_new_address

        let id = Uuid::new_v4().to_string();
        let addresses_derivation_map = HashMap::new(); //TODO: add a fucntion to recreate
        let network = net.clone();

        let mut new_wallet = Wallet {
            id,
            network,
            private_share: PrivateShare {
                master_key: client_master_key_recovered,
                id: key_id,
            },
            last_derived_pos: pos_old,
            addresses_derivation_map,
        };
        new_wallet.derived();
        new_wallet.save();
        println!("Recovery Completed Successfully ❤️");

        new_wallet
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

    pub fn send(
        &mut self,
        to_address: String,
        amount_btc: f32,
        client_shim: &api::ClientShim,
    ) -> String {
        let selected = self.select_tx_in(amount_btc);
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

        for i in 0..transaction.input.len() {
            let address_derivation = self
                .addresses_derivation_map
                .get(&selected[i].address)
                .unwrap();

            let mk = &address_derivation.mk;
            let pk = mk.public.q.get_element();

            let comp = SighashComponents::new(&transaction);
            let sig_hash = comp.sighash_all(
                &transaction.input[i],
                &bitcoin::Address::p2pkh(&pk, self.get_bitcoin_network()).script_pubkey(),
                (selected[i].value as u32).into(),
            );

            let signature = api::sign(
                client_shim,
                BigInt::from_hex(&sig_hash.le_hex_string()),
                &mk,
                BigInt::from(0),
                BigInt::from(address_derivation.pos),
                &self.private_share.id,
            );

            let mut v = BigInt::to_vec(&signature.r.to_big_int());
            v.extend(BigInt::to_vec(&signature.s.to_big_int()));

            let mut sig = Signature::from_compact(&v[..]).unwrap().serialize_der();

            sig.push(01);
            let mut witness = Vec::new();
            witness.push(sig);
            witness.push(pk.serialize().to_vec());

            signed_transaction.input[i].witness = witness;
        }

        let mut electrum = ElectrumxClient::new(ELECTRUM_HOST).unwrap();

        let raw_tx_hex = hex::encode(serialize(&signed_transaction));
        let txid = electrum.broadcast_transaction(raw_tx_hex.clone());

        txid.unwrap()
    }

    pub fn get_new_bitcoin_address(&mut self) -> bitcoin::Address {
        let (pos, mk) = Self::derive_new_key(&self.private_share, self.last_derived_pos);
        let pk = mk.public.q.get_element();
        let address = bitcoin::Address::p2wpkh(&pk, self.get_bitcoin_network());

        self.addresses_derivation_map
            .insert(address.to_string(), AddressDerivation { mk, pos });

        self.last_derived_pos = pos;

        address
    }

    pub fn derived(&mut self) {
        for i in 0..self.last_derived_pos {
            let (pos, mk) = Self::derive_new_key(&self.private_share, i);

            let address =
                bitcoin::Address::p2wpkh(&mk.public.q.get_element(), self.get_bitcoin_network());

            self.addresses_derivation_map
                .insert(address.to_string(), AddressDerivation { mk, pos });
        }
    }

    pub fn get_balance(&mut self) -> GetWalletBalanceResponse {
        let mut aggregated_balance = GetWalletBalanceResponse {
            confirmed: 0,
            unconfirmed: 0,
        };

        for b in self.get_all_addresses_balance() {
            aggregated_balance.unconfirmed += b.unconfirmed;
            aggregated_balance.confirmed += b.confirmed;
        }

        aggregated_balance
    }

    // TODO: handle fees
    pub fn select_tx_in(&self, amount_btc: f32) -> Vec<GetListUnspentResponse> {
        // greedy selection
        let list_unspent: Vec<GetListUnspentResponse> = self
            .get_all_addresses_balance()
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

    fn get_address_balance(address: &bitcoin::Address) -> GetBalanceResponse {
        let mut client = ElectrumxClient::new(ELECTRUM_HOST).unwrap();
        let resp = client.get_balance(&address.to_string()).unwrap();
        GetBalanceResponse {
            confirmed: resp.confirmed,
            unconfirmed: resp.unconfirmed,
            address: address.to_string(),
        }
    }

    fn get_all_addresses_balance(&self) -> Vec<GetBalanceResponse> {
        let response: Vec<GetBalanceResponse> = self
            .get_all_addresses()
            .into_iter()
            .map(|a| Self::get_address_balance(&a))
            .collect();

        response
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
        bitcoin::Address::p2wpkh(&mk.public.q.get_element(), network)
    }
}

impl WalletNew {
    pub fn new(client_shim: &api::ClientShim, net: &String) -> WalletNew {
        let id = Uuid::new_v4().to_string();
        let private_share = api::get_master_key_new(client_shim);
        let last_derived_pos = 0;
        let addresses_derivation_map = HashMap::new();
        let network = net.clone();

        WalletNew {
            id,
            network,
            private_share,
            last_derived_pos,
            addresses_derivation_map,
        }
    }

    pub fn rotate(self, client_shim: &api::ClientShim) -> Self {
        rotate::rotate_master_key(self, client_shim)
    }

    pub fn backup(&self, escrow_service: escrow::Escrow) {
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
            self.private_share.master_key.private.y_i(),
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
            GE,
            BigInt,
            String,
        ) = serde_json::from_str(&data).unwrap();
        let verify = proof.verify(&encryptions, &g, &y, &client_public, &escrow::SEGMENT_SIZE);
        match verify {
            Ok(_x) => println!("backup verified 🍻"),
            Err(_e) => println!("Backup was not verified correctly 😲"),
        }
    }

    pub fn recover_and_save_share(
        escrow_service: escrow::Escrow,
        net: &String,
        client_shim: &api::ClientShim,
    ) -> WalletNew {
        let g: GE = ECPoint::generator();
        let y_priv = escrow_service.get_private_key();

        let data = fs::read_to_string(BACKUP_FILENAME).expect("Unable to load client backup!");

        let (encryptions, _proof, _client_public, chain_code2, key_id): (
            Helgamalsegmented,
            Proof,
            GE,
            BigInt,
            String,
        ) = serde_json::from_str(&data).unwrap();

        let sk = Msegmentation::decrypt(&encryptions, &g, &y_priv, &escrow::SEGMENT_SIZE);
        let private_share: PrivateShareGG =
            keygen::get_master_key_new(key_id.clone(), sk, &client_shim);
        // correct chain code. TODO: take chain code from server
        let master_key_updated_cc = MasterKey1 {
            public: private_share.master_key.public.clone(),
            private: private_share.master_key.private.clone(),
            chain_code: chain_code2,
        };
        let private_share = PrivateShareGG {
            id: key_id.clone(),
            master_key: master_key_updated_cc,
        };
        let res_body = requests::post(client_shim, &format!("ecdsa/{}/recover", key_id)).unwrap();

        let pos_old: HDPos = serde_json::from_str(&res_body).unwrap();
        let pos_old = if pos_old.pos < 10 { 10 } else { pos_old.pos };
        //TODO: temporary, server will keep updated pos, to do so we need to send update to server for every get_new_address

        let id = Uuid::new_v4().to_string();
        let addresses_derivation_map = HashMap::new(); //TODO: add a fucntion to recreate
        let network = net.clone();

        let mut new_wallet = WalletNew {
            id,
            network,
            private_share,
            last_derived_pos: pos_old,
            addresses_derivation_map,
        };
        new_wallet.derived();
        new_wallet.save();
        println!("Recovery Completed Successfully ❤️");

        new_wallet
    }

    pub fn save_to(&self, filepath: &str) {
        let wallet_json = serde_json::to_string(self).unwrap();

        fs::write(filepath, wallet_json).expect("Unable to save wallet!");

        debug!("(wallet id: {}) Saved wallet to disk", self.id);
    }

    pub fn save(&self) {
        self.save_to(WALLET_FILENAME)
    }

    pub fn load_from(filepath: &str) -> WalletNew {
        let data = fs::read_to_string(filepath).expect("Unable to load wallet!");

        let wallet: WalletNew = serde_json::from_str(&data).unwrap();

        debug!("(wallet id: {}) Loaded wallet to memory", wallet.id);

        wallet
    }

    pub fn load() -> WalletNew {
        WalletNew::load_from(WALLET_FILENAME)
    }

    pub fn send(
        &mut self,
        to_address: String,
        amount_btc: f32,
        client_shim: &api::ClientShim,
    ) -> String {
        let selected = self.select_tx_in(amount_btc);
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

        for i in 0..transaction.input.len() {
            let address_derivation = self
                .addresses_derivation_map
                .get(&selected[i].address)
                .unwrap();

            let mk = &address_derivation.mk;
            let pk = mk.public.q.get_element();

            let comp = SighashComponents::new(&transaction);
            let sig_hash = comp.sighash_all(
                &transaction.input[i],
                &bitcoin::Address::p2pkh(&pk, self.get_bitcoin_network()).script_pubkey(),
                (selected[i].value as u32).into(),
            );
            let signature = api::sign_gg(
                client_shim,
                BigInt::from_hex(&sig_hash.le_hex_string()),
                &mk,
                BigInt::zero(),
                BigInt::from(address_derivation.pos),
                &self.private_share.id,
            );

            let mut v = BigInt::to_vec(&signature.r.to_big_int());
            v.extend(BigInt::to_vec(&signature.s.to_big_int()));

            let mut sig = Signature::from_compact(&v[..]).unwrap().serialize_der();

            sig.push(01);
            let mut witness = Vec::new();
            witness.push(sig);
            witness.push(pk.serialize().to_vec());

            signed_transaction.input[i].witness = witness;
        }

        let mut electrum = ElectrumxClient::new(ELECTRUM_HOST).unwrap();

        let raw_tx_hex = hex::encode(serialize(&signed_transaction));
        let txid = electrum.broadcast_transaction(raw_tx_hex.clone());
        println!("txid: {:?}", txid.is_ok());

        txid.unwrap()
    }

    pub fn get_new_bitcoin_address(&mut self) -> bitcoin::Address {
        let (pos, mk) = Self::derive_new_key(&self.private_share, self.last_derived_pos);
        let pk = mk.public.q.get_element();
        let address = bitcoin::Address::p2wpkh(&pk, self.get_bitcoin_network());

        self.addresses_derivation_map
            .insert(address.to_string(), AddressDerivationNew { mk, pos });

        self.last_derived_pos = pos;

        address
    }

    pub fn derived(&mut self) {
        for i in 0..self.last_derived_pos {
            let (pos, mk) = Self::derive_new_key(&self.private_share, i);

            let address =
                bitcoin::Address::p2wpkh(&mk.public.q.get_element(), self.get_bitcoin_network());

            self.addresses_derivation_map
                .insert(address.to_string(), AddressDerivationNew { mk, pos });
        }
    }

    pub fn get_balance(&mut self) -> GetWalletBalanceResponse {
        let mut aggregated_balance = GetWalletBalanceResponse {
            confirmed: 0,
            unconfirmed: 0,
        };

        for b in self.get_all_addresses_balance() {
            aggregated_balance.unconfirmed += b.unconfirmed;
            aggregated_balance.confirmed += b.confirmed;
        }

        aggregated_balance
    }

    // TODO: handle fees
    pub fn select_tx_in(&self, amount_btc: f32) -> Vec<GetListUnspentResponse> {
        // greedy selection
        let list_unspent: Vec<GetListUnspentResponse> = self
            .get_all_addresses_balance()
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

    fn get_address_balance(address: &bitcoin::Address) -> GetBalanceResponse {
        let mut client = ElectrumxClient::new(ELECTRUM_HOST).unwrap();

        let resp = client.get_balance(&address.to_string()).unwrap();

        GetBalanceResponse {
            confirmed: resp.confirmed,
            unconfirmed: resp.unconfirmed,
            address: address.to_string(),
        }
    }

    fn get_all_addresses_balance(&self) -> Vec<GetBalanceResponse> {
        let response: Vec<GetBalanceResponse> = self
            .get_all_addresses()
            .into_iter()
            .map(|a| Self::get_address_balance(&a))
            .collect();

        response
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

    fn derive_new_key(private_share: &PrivateShareGG, pos: u32) -> (u32, MasterKey1) {
        let last_pos: u32 = pos + 1;

        let last_child_master_key = private_share
            .master_key
            .get_child(vec![BigInt::from(0), BigInt::from(last_pos)]);

        (last_pos, last_child_master_key)
    }

    fn get_bitcoin_network(&self) -> Network {
        self.network.parse::<Network>().unwrap()
    }

    fn to_bitcoin_address(mk: &MasterKey1, network: Network) -> bitcoin::Address {
        bitcoin::Address::p2wpkh(&mk.public.q.get_element(), network)
    }
}
