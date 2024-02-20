use std::error::Error;
use std::fs::File;
use std::path::Path;

use std::sync::Arc;

use client_lib as GothamClient;
use GothamClient::ecdsa::PrivateShare;
use GothamClient::{BigInt, Converter, ECPoint};

use ethers::prelude::transaction::eip2718::TypedTransaction;
use ethers::prelude::transaction::eip712::Eip712;
use ethers::prelude::*;
use ethers::signers::Signer;
use ethers::utils::{format_units, keccak256, parse_units};

use serde::{Deserialize, Serialize};

pub mod commands;

#[derive(Serialize, Deserialize)]
pub struct GothamWallet {
    /// gotham client's private share
    pub private_share: PrivateShare,

    /// Hierarchical-Deterministic derivation path of child keys
    pub hd_path: Vec<u32>,

    /// wallet's chain id (for EIP-155)
    pub chain_id: u64,

    /// wallet's address
    pub address: Address,
}

impl GothamWallet {
    pub fn new<C: GothamClient::Client>(
        gotham_client_shim: &GothamClient::ClientShim<C>,
        hd_path: Vec<u32>,
        chain_id: u64,
    ) -> Self {
        let master_share = GothamClient::ecdsa::get_master_key(gotham_client_shim);

        let derivation_path: Vec<BigInt> = hd_path.clone().into_iter().map(BigInt::from).collect();

        let child_master_key = master_share
            .master_key
            .get_child(derivation_path);

        let pk = child_master_key.public.q.get_element();
        let _pk_x = child_master_key.public.q.x_coor().unwrap();
        let _pk_y = child_master_key.public.q.y_coor().unwrap();

        // Ethereum address is the last 20 bytes of the keccack256 of the uncompressed public key
        let pk = pk.serialize_uncompressed();
        debug_assert_eq!(pk[0], 0x04); // uncompressed public key has 0x04 prefix

        let hash = H256(keccak256(&pk[1..]));

        let address = Address::from_slice(&hash[12..]);

        GothamWallet {
            private_share: master_share,
            hd_path,
            chain_id,
            address,
        }
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> () {
        let file = File::create(path).expect("Error while creating file");
        serde_json::to_writer_pretty(&file, &self).expect("Error while serializing wallet")
    }

    pub fn load<P: AsRef<Path>>(path: P) -> GothamWallet {
        let file = File::open(path).expect("Error while opening file");
        serde_json::from_reader(&file).expect("Error while deserializing wallet")
    }
}

pub struct GothamSigner<C: GothamClient::Client> {
    /// gotham client wrapper
    pub gotham_client_shim: GothamClient::ClientShim<C>,

    /// gotham ethereum wallet
    pub wallet: GothamWallet,
}

// https://betterprogramming.pub/a-simple-guide-to-using-thiserror-crate-in-rust-eee6e442409b
#[derive(thiserror::Error, Debug)]
pub enum GothamSignerError {
    /// Error type from Eip712Error message
    #[error("error encoding eip712 struct: {0:?}")]
    Eip712Error(String),
}

impl<C: GothamClient::Client> std::fmt::Debug for GothamSigner<C> {
    fn fmt(&self, _f: &mut std::fmt::Formatter) -> std::fmt::Result {
        todo!()
    }
}

impl<'w, C: GothamClient::Client> GothamSigner<C> {
    pub fn sign_hash(&self, hash: H256) -> Result<Signature, GothamSignerError> {
        let message: BigInt = BigInt::from(hash.as_ref());

        let derivation_path: Vec<BigInt> = self.wallet.hd_path.clone().into_iter().map(BigInt::from).collect();

        let child_master_key = self
            .wallet
            .private_share
            .master_key
            .get_child(derivation_path.clone());

        let signature = GothamClient::ecdsa::sign(
            &self.gotham_client_shim,
            message,
            &child_master_key,
            derivation_path,
            &self.wallet.private_share.id,
        )
        .unwrap();

        let r_bytes = BigInt::to_vec(&signature.r);
        let s_bytes = BigInt::to_vec(&signature.s);

        let signature = Signature {
            r: U256::from_big_endian(&r_bytes),
            s: U256::from_big_endian(&s_bytes),
            v: signature.recid as u64,
        };

        Ok(signature)
    }

    fn chain_id(&self) -> u64 {
        self.wallet.chain_id
    }
}

#[async_trait::async_trait]
impl<'w, C: GothamClient::Client + Sync + Send> Signer for GothamSigner<C> {
    type Error = GothamSignerError;

    async fn sign_message<S: Send + Sync + AsRef<[u8]>>(
        &self,
        message: S,
    ) -> Result<Signature, Self::Error> {
        let message = message.as_ref();
        let hash: H256 = ethers::utils::hash_message(message);
        self.sign_hash(hash)
    }

    async fn sign_transaction(&self, tx: &TypedTransaction) -> Result<Signature, Self::Error> {
        let mut tx_with_chain = tx.clone();
        if tx_with_chain.chain_id().is_none() {
            // in the case we don't have a chain_id, let's use the signer chain id instead
            tx_with_chain.set_chain_id(self.wallet.chain_id);
        }

        // rlp (for sighash) must have the same chain id as v in the signature
        let chain_id = tx_with_chain
            .chain_id()
            .map(|id| id.as_u64())
            .unwrap_or(self.wallet.chain_id);
        let mut tx_with_chain = tx_with_chain.clone();
        tx_with_chain.set_chain_id(chain_id);

        let sighash = tx_with_chain.sighash();

        let mut signature = self.sign_hash(sighash)?;

        // Modify the v value of a signature to conform to eip155
        // signature.v = to_eip155_v(signature.v as u8, chain_id);
        signature.v = (chain_id * 2 + 35) + signature.v;

        Ok(signature)
    }

    async fn sign_typed_data<T: Eip712 + Send + Sync>(
        &self,
        payload: &T,
    ) -> Result<Signature, Self::Error> {
        let encoded = payload
            .encode_eip712()
            .map_err(|e| Self::Error::Eip712Error(e.to_string()))?;
        self.sign_hash(H256::from(encoded))
    }

    fn address(&self) -> Address {
        self.wallet.address
    }

    fn chain_id(&self) -> u64 {
        self.wallet.chain_id
    }

    fn with_chain_id<T: Into<u64>>(mut self, chain_id: T) -> Self {
        self.wallet.chain_id = chain_id.into();
        self
    }
}

abigen!(
    ERC20Contract,
    r#"[
        function name() public view returns (string)
        function symbol() public view returns (string)
        function decimals() public view returns (uint8)
        function totalSupply() public view returns (uint256)
        function balanceOf(address _owner) public view returns (uint256 balance)
        function transfer(address _to, uint256 _value) public returns (bool success)
        function transferFrom(address _from, address _to, uint256 _value) public returns (bool success)
        function approve(address _spender, uint256 _value) public returns (bool success)
        function allowance(address _owner, address _spender) public view returns (uint256 remaining)
        event Transfer(address indexed _from, address indexed _to, uint256 _value)
        event Approval(address indexed _owner, address indexed _spender, uint256 _value)
    ]"#,
);

pub struct TransferDetails {
    pub contract_address: String,
    pub to_address: String,
    pub amount: f64,
    pub gas_limit: Option<u128>,
    pub gas_price: Option<f64>,
    pub nonce: Option<u128>,
}

pub async fn transfer_erc20<S: Signer + 'static>(
    rpc_url: String,
    chain_id: u64,
    signer: S,
    details: TransferDetails,
) -> Result<(), Box<dyn Error>> {
    let provider =
        Arc::new(Provider::<Http>::try_from(rpc_url)?.with_signer(signer.with_chain_id(chain_id)));

    let contract = ERC20Contract::new(
        details.contract_address.parse::<Address>()?,
        Arc::clone(&provider),
    );

    let decimals = contract.decimals().call().await?;

    let float_amount = details.amount * (10.0_f64).powi(decimals.into());
    let decimal_amount = U256::from(float_amount.floor() as u128);

    let mut contract_call =
        contract.transfer(details.to_address.parse::<Address>()?, decimal_amount);

    if let Some(gas_limit) = details.gas_limit {
        contract_call.tx.set_gas(U256::from(gas_limit));
    }

    if let Some(gas_price) = details.gas_price {
        let gas_price: U256 = parse_units(gas_price, "gwei").unwrap().into();
        contract_call.tx.set_gas_price(gas_price);
    }

    if let Some(nonce) = details.nonce {
        contract_call.tx.set_nonce(U256::from(nonce));
    }

    let receipt = contract_call.send().await?.await?.unwrap();
    println!("Transaction Hash: {:?}", receipt.transaction_hash);
    Ok(())
}

pub struct TransactionDetails {
    pub to_address: String,
    pub amount: f64,
    pub gas_limit: Option<u128>,
    pub gas_price: Option<f64>,
    pub nonce: Option<u128>,
}

pub async fn send_transaction<S: Signer + 'static>(
    rpc_url: String,
    chain_id: u64,
    signer: S,
    details: TransactionDetails,
) -> Result<(), Box<dyn Error>> {
    let provider = Provider::<Http>::try_from(rpc_url)?.with_signer(signer.with_chain_id(chain_id));
    let amount: U256 = parse_units(details.amount, "ether").unwrap().into();

    let mut tx: TypedTransaction = TransactionRequest::new()
        .from(provider.address())
        .chain_id(chain_id)
        .to(details.to_address.parse::<Address>()?)
        .value(amount)
        .into();

    if let Some(gas_limit) = details.gas_limit {
        tx.set_gas(U256::from(gas_limit));
    }

    if let Some(gas_price) = details.gas_price {
        let gas_price: U256 = parse_units(gas_price, "gwei").unwrap().into();
        tx.set_gas_price(gas_price);
    }

    if let Some(nonce) = details.nonce {
        tx.set_nonce(U256::from(nonce));
    }

    let receipt = provider.send_transaction(tx, None).await?.await?.unwrap();
    println!("Transaction Hash: {:?}", receipt.transaction_hash);

    Ok(())
}

pub async fn get_balance(
    rpc_url: String,
    address: Address,
    contracts: Option<Vec<String>>,
) -> Result<(), Box<dyn Error>> {
    let provider = Arc::new(Provider::<Http>::try_from(rpc_url)?);

    let balance = provider.get_balance(address, None).await?;
    println!("[Native Token] = {}", format_units(balance, "ether")?);

    if let Some(contract_addresses) = contracts {
        for contract_address in contract_addresses.iter() {
            let contract =
                ERC20Contract::new(contract_address.parse::<Address>()?, Arc::clone(&provider));

            let name = contract.name().call().await?;

            let balance = contract.balance_of(address).call().await?;
            println!("[{}] = {}", name, format_units(balance, "ether")?);
        }
    }
    Ok(())
}

pub fn create_new_wallet(file_path: String, server_url: String, hd_path: Vec<u32>, chain_id: u64) {
    let client = GothamClient::ClientShim::new(server_url.clone(), None);
    let wallet = GothamWallet::new(&client, hd_path.clone(), chain_id);
    wallet.save(file_path);
}
