use super::utilities::requests;
use super::Result;
use super::ClientShim;
use multi_party_schnorr::protocols::thresholdsig::zilliqa_schnorr::*;
pub use multi_party_schnorr::protocols::thresholdsig::zilliqa_schnorr::{Signature, Share};

const PREFIX: &str = "schnorr";
const PARTY1_INDEX: usize = 1; // server
const PARTY2_INDEX: usize = 2; // client (self)
const PARAMS: Parameters = Parameters {
    threshold: 1,
    share_count: 2,
};

pub fn generate_key(client_shim: &ClientShim) -> Result<Share> {
    let key: Keys = Keys::phase1_create(PARTY2_INDEX);
    let (msg1, msg2) = key.phase1_broadcast();

    let (id, party1_msg1): (String, KeyGenBroadcastMessage1) = requests::postb(
        client_shim,
        &format!("{}/keygen/first", PREFIX), &msg1)
        .unwrap();

    let party1_msg2: KeyGenBroadcastMessage2 = requests::postb(
        client_shim,
        &format!("{}/keygen/{}/second", PREFIX, id),
        &msg2)
        .unwrap();

    let (vss_scheme, secret_shares, _index) = key.phase1_verify_com_phase2_distribute(
        &PARAMS,
        &vec![party1_msg2.clone(), msg2],
        &vec![party1_msg1, msg1],
        &vec![PARTY1_INDEX, PARTY2_INDEX])
        .or_else(|e| Err(e))?;
    let msg3 = KeyGenMessage3 {
        vss_scheme,
        secret_share: secret_shares[PARTY1_INDEX - 1],
    };

    let party1_msg3: KeyGenMessage3 = requests::postb(
        client_shim,
        &format!("{}/keygen/{}/third", PREFIX, id), &msg3)
        .unwrap();

    let vss_scheme_vec = vec![party1_msg3.vss_scheme, msg3.vss_scheme];
    let shared_key: SharedKeys = key.phase2_verify_vss_construct_keypair(
        &PARAMS,
        &vec![party1_msg2.y_i, key.y_i],
        &vec![party1_msg3.secret_share, secret_shares[key.party_index - 1]],
        &vss_scheme_vec,
        &key.party_index)
        .or_else(|e| Err(e))?;

    let share: Share = Share {
        id,
        shared_key,
        vss_scheme_vec,
    };
    Ok(share)
}

pub fn sign(
    client_shim: &ClientShim,
    message: BigInt,
    share: &Share,
) -> Result<Signature> {
    let eph_share = generate_key(client_shim)
        .or_else(|e| Err(e))?;
    let message_vec = BigInt::to_vec(&message);
    let message_slice = message_vec.as_slice();
    let local_sig = LocalSig::compute(
        message_slice,
        &eph_share.shared_key,
        &share.shared_key);

    let sign_msg1 = SignMessage1 {
        message,
        local_sig,
    };

    let party1_local_sig: LocalSig = requests::postb(
        client_shim,
        &format!("{}/sign/{}/{}", PREFIX, share.id, eph_share.id),
        &sign_msg1)
        .unwrap();

    let local_sig_vec = &vec![party1_local_sig, local_sig];
    let vss_sum_local_sigs: VerifiableSS = LocalSig::verify_local_sigs(
        local_sig_vec,
        &vec![PARTY1_INDEX - 1, PARTY2_INDEX - 1],
        &share.vss_scheme_vec,
        &eph_share.vss_scheme_vec)
        .or_else(|e| Err(e))?;

    let signature = Signature::generate(
        &vss_sum_local_sigs,
        local_sig_vec,
        &vec![PARTY1_INDEX - 1, PARTY2_INDEX - 1],
        &eph_share.shared_key.y,
        &share.shared_key.y,
        message_slice,
    );
    signature.verify(message_slice, &share.shared_key.y)
        .or_else(|e| Err(format_err!("{}", e)))
        .and_then(|()| Ok(signature))
}