use reqwest;
use uuid::Uuid;
use kms::ecdsa::two_party::*;
use kms::ecdsa::two_party::MasterKey2;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use std::fs;
use serde_json;
use curv::BigInt;
use bitcoin;
use bitcoin::consensus::encode::{serialize, Encoder, Decoder};
use bitcoin::network::constants::Network;
use bitcoin::{Transaction, TxIn, TxOut, SigHashType};
use bitcoin::blockdata::script::Builder;
use curv::elliptic::curves::traits::ECPoint;
use electrumx_client::{
    electrumx_client::ElectrumxClient,
    interface::Electrumx
};
use std::str::FromStr;
use std::collections::HashMap;
use itertools::Itertools;
use curv::arithmetic::traits::Converter;
use secp256k1::Signature;
use secp256k1::PublicKey;
use secp256k1::Secp256k1;
use super::utilities::requests;
use super::ecdsa::keygen;
use super::escrow;
use hex;

// TODO: move that to a config file and double check electrum server addresses
//const ELECTRUM_HOST : &str = "testnet.hsmiths.com:53011";

const ELECTRUM_HOST : &str = "ec2-34-219-15-143.us-west-2.compute.amazonaws.com:60001";
const WALLET_FILENAME : &str = "wallet/wallet.data";

#[derive(Serialize, Deserialize)]
pub struct SignSecondMsgRequest {
    pub message: BigInt,
    pub party_two_sign_message: party2::SignMessage,
    pub eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg,
    pub pos_child_key: u32
}

#[derive(Debug, Deserialize, Clone)]
pub struct GetBalanceResponse {
    pub address: String,
    pub confirmed:   u64,
    pub unconfirmed: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GetListUnspentResponse {
    pub height:  usize,
    pub tx_hash: String,
    pub tx_pos:  usize,
    pub value:   usize,
    pub address: String
}

#[derive(Debug, Deserialize)]
pub struct GetWalletBalanceResponse {
    pub confirmed:   u64,
    pub unconfirmed: u64,
}

#[derive(Serialize, Deserialize)]
pub struct PrivateShares {
    pub id: String,
    pub master_key: MasterKey2
}

#[derive(Serialize, Deserialize)]
pub struct AddressDerivation {
    pub pos: u32,
    pub mk: MasterKey2
}

#[derive(Serialize, Deserialize)]
pub struct Wallet {
    id: String,
    network: String,
    private_shares: PrivateShares,
    last_derived_pos: u32,
    addresses_derivation_map: HashMap<String, AddressDerivation>
}

impl Wallet {
    pub fn new(client: &reqwest::Client, network: String) -> Wallet {
        let id = Uuid::new_v4().to_string();
        let private_shares = keygen::get_master_key(client);
        let last_derived_pos = 0;
        let addresses_derivation_map = HashMap::new();

        Wallet { id, network, private_shares, last_derived_pos, addresses_derivation_map }
    }

    pub fn backup(&self, escrow: &escrow::Escrow) {
        escrow.backup_shares(&self.private_shares.master_key);

        println!("(wallet id: {}) Backup wallet with escrow", self.id);
    }

    pub fn save(&self) {
        let wallet_json = serde_json::to_string(self).unwrap();

        fs::write(WALLET_FILENAME, wallet_json)
            .expect("Unable to save wallet!");

        println!("(wallet id: {}) Saved wallet to disk", self.id);
    }

    pub fn load() -> Wallet {
        let data = fs::read_to_string(WALLET_FILENAME)
            .expect("Unable to load wallet!");

        let wallet: Wallet = serde_json::from_str(&data).unwrap();

        println!("(wallet id: {}) Loaded wallet to memory", wallet.id);

        wallet
    }

    pub fn send(&mut self, client: &reqwest::Client, to_address: String, amount_btc: f32) -> bool {
        let selected = self.select_tx_in(amount_btc);
        if selected.is_empty() {
            panic!("Not enough fund");
        }

        let to_btc_adress = bitcoin::Address::from_str(&to_address).unwrap();


        let txs_in : Vec<TxIn> = selected
            .clone()
            .into_iter()
            .map(| s | bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::util::hash::Sha256dHash::from_hex(&s.tx_hash).unwrap(),
                    vout: s.tx_pos as u32
                },
                script_sig: bitcoin::Script::default(),
                sequence: 0xFFFFFFFF,
                witness: Vec::default()
            })
            .collect();

        let fees = 100;

        let amount_satoshi = (amount_btc * 100_000_00 as f32) as u64;

        let change_address = self.get_new_bitcoin_address();

        let total_selected = selected
            .clone()
            .into_iter()
            .fold(0, |sum, val| sum + val.value) as u64;

        let txs_out = vec![
            TxOut {
                value: amount_satoshi,
                script_pubkey: to_btc_adress.script_pubkey()
            },
            TxOut {
                value: total_selected - amount_satoshi - fees,
                script_pubkey: change_address.script_pubkey()
            }
        ];

        let mut transaction = bitcoin::Transaction {
            version: 1,
            lock_time: 0,
            input: txs_in,
            output: txs_out
        };

        let mut signatures : Vec<party_one::Signature> = Vec::new();

        let mut signed_transaction = transaction.clone();

        for i in 0..transaction.input.len() {
            let address = bitcoin::Address::from_str(&selected[i].address).unwrap();

            let addressDerivation = self.addresses_derivation_map.get(&selected[i].address).unwrap();

            let mk = &addressDerivation.mk;
            let pk = mk.public.q.get_element();

            let sig_hash = transaction.signature_hash(
                i,
                &address.script_pubkey(),
                bitcoin::SigHashType::All.as_u32());

            let (eph_key_gen_first_message_party_two, party_two_sign_message) =
                self.sign(client, sig_hash, &mk);

            let signatures = self.get_signature(
                client,
                sig_hash,
                eph_key_gen_first_message_party_two,
                party_two_sign_message,
                addressDerivation.pos);

            let mut v = BigInt::to_vec(&signatures.r);
            v.extend(BigInt::to_vec(&signatures.s));

            let context = Secp256k1::new();
            let sig =
                Signature::from_compact(&context, &v[..]).unwrap()
                    .serialize_der(&context);

            let mut witness = Vec::new();
            witness.push(sig);
            witness.push(pk.serialize().to_vec());

            signed_transaction.input[i].witness = witness;
        }

        println!("serialized: {}", hex::encode(serialize(&signed_transaction)));

        true
    }

    fn get_signature(&self,
                     client: &reqwest::Client,
                     message: bitcoin::util::hash::Sha256dHash,
                     eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg,
                     party_two_sign_message: party2::SignMessage,
                     pos_child_key: u32) -> party_one::Signature
    {
        let request : SignSecondMsgRequest = SignSecondMsgRequest {
            message: BigInt::from_hex(&message.be_hex_string()),
            party_two_sign_message,
            eph_key_gen_first_message_party_two,
            pos_child_key
        };

        let res_body = requests::postb(
            client, &format!("/ecdsa/sign/{}/second", self.private_shares.id),
            &request).unwrap();

        let signature : party_one::Signature = serde_json::from_str(&res_body).unwrap();

        signature
    }

    fn sign(&self, client: &reqwest::Client, message: bitcoin::util::hash::Sha256dHash, mk: &MasterKey2) ->
    (party_two::EphKeyGenFirstMsg, party2::SignMessage)
    {

        let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
            MasterKey2::sign_first_message();

        let res_body = requests::post(
            client, &format!("/ecdsa/sign/{}/first", self.private_shares.id)).unwrap();

        let sign_party_one_first_message : party_one::EphKeyGenFirstMsg =
            serde_json::from_str(&res_body).unwrap();

        let party_two_sign_message = mk.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness.clone(),
            &sign_party_one_first_message,
            &BigInt::from_hex(&message.be_hex_string()),
        );

        (eph_key_gen_first_message_party_two, party_two_sign_message)
    }

    pub fn get_new_bitcoin_address(&mut self) -> bitcoin::Address {
        let (pos, mk) = Self::derive_new_key(&self.private_shares, self.last_derived_pos);
        let pk = mk.public.q.get_element();
        let address = bitcoin::Address::p2wpkh(&pk, self.get_bitcoin_network());

        self.addresses_derivation_map.insert(address.to_string(), AddressDerivation { mk, pos });

        self.last_derived_pos = pos;

        address
    }

    pub fn derived(&mut self) {
        for i in 0..self.last_derived_pos {
            let (pos, mk) = Self::derive_new_key(&self.private_shares, i);

            let address = bitcoin::Address::p2wpkh(
                &mk.public.q.get_element(), self.get_bitcoin_network());

            self.addresses_derivation_map.insert(address.to_string(), AddressDerivation { mk, pos });
        }
    }

    pub fn get_balance(&mut self) -> GetWalletBalanceResponse  {
        let mut aggregated_balance = GetWalletBalanceResponse { confirmed: 0, unconfirmed: 0 };

        for b in self.get_all_addresses_balance() {
            aggregated_balance.unconfirmed += b.unconfirmed;
            aggregated_balance.confirmed += b.confirmed;
        }

        aggregated_balance
    }

    // TODO: handle fees
    pub fn select_tx_in(&self, amount_btc: f32) -> Vec<GetListUnspentResponse> { // greedy selection
        let list_unspent : Vec<GetListUnspentResponse> = self.get_all_addresses_balance()
            .into_iter()
            .filter(|b| b.confirmed > 0)
            .map(| a | self.list_unspent_for_addresss(a.address.to_string()))
            .flatten()
            .sorted_by(| a, b |
                a.value.partial_cmp(&b.value).unwrap())
            .into_iter()
            .collect();

        println!("{:?}", list_unspent);

        let mut remaining : i64 = amount_btc as i64 * 100_000_000;
        let mut selected : Vec<GetListUnspentResponse> = Vec::new();

        for unspent in list_unspent {
            selected.push(unspent.clone());
            remaining -= unspent.value as i64;

            if remaining < 0 { break; }
        }

        selected
    }

    pub fn list_unspent(&self) -> Vec<GetListUnspentResponse> {
        let response : Vec<GetListUnspentResponse> = self.get_all_addresses()
            .into_iter()
            .map(| a | self.list_unspent_for_addresss(a.to_string()))
            .flatten()
            .collect();

        response
    }

    /* PRIVATE */
    fn list_unspent_for_addresss(&self, address: String) -> Vec<GetListUnspentResponse>  {
        let mut client = ElectrumxClient::new(ELECTRUM_HOST).unwrap();

        let resp = client.get_list_unspent(&address).unwrap();

        resp
            .into_iter()
            .map(| u | GetListUnspentResponse {
                value: u.value,
                height: u.height,
                tx_hash: u.tx_hash,
                tx_pos: u.tx_pos,
                address: address.clone()
            })
            .collect()
    }

    fn get_address_balance(address: &bitcoin::Address) -> GetBalanceResponse  {
        let mut client = ElectrumxClient::new(ELECTRUM_HOST).unwrap();

        let resp = client.get_balance(&address.to_string()).unwrap();

        GetBalanceResponse {
            confirmed: resp.confirmed,
            unconfirmed: resp.unconfirmed,
            address: address.to_string()
        }
    }

    fn get_all_addresses_balance(&self) -> Vec<GetBalanceResponse> {
        let response : Vec<GetBalanceResponse> = self.get_all_addresses()
            .into_iter()
            .map(| a | Self::get_address_balance(&a))
            .collect();

        response
    }

    fn get_all_addresses(&self) -> Vec<bitcoin::Address> {
        let init = 0;
        let last_pos = self.last_derived_pos;

        let mut response : Vec<bitcoin::Address> = Vec::new();

        for n in init..last_pos {
            let mk = self.private_shares.master_key.get_child(vec![BigInt::from(n)]);
            let bitcoin_address = Self::to_bitcoin_address(&mk, self.get_bitcoin_network());

            response.push(bitcoin_address);
        }

        response
    }

    fn derive_new_key(private_shares: &PrivateShares, pos: u32) -> (u32, MasterKey2) {
        let last_pos : u32 = pos + 1;

        let last_child_master_key = private_shares.master_key
            .get_child(vec![BigInt::from(last_pos)]);

        (last_pos, last_child_master_key)
    }

    fn get_bitcoin_network(&self) -> Network {
        self.network.parse::<Network>().unwrap()
    }

    fn to_bitcoin_address(mk: &MasterKey2, network: Network) -> bitcoin::Address {
        bitcoin::Address::p2wpkh(&mk.public.q.get_element(), network)
    }
}