//! The threshold verdict (docs/game-spec.md §8): the resolver keys, the exact
//! contract byte formats, and the signing sweep. The verdict is written to
//! stable memory before any signature is requested; a retry can only ever
//! re-sign the same recorded outcome.

use ic_cdk_management_canister::{
    EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgs, SchnorrAlgorithm, SchnorrKeyId,
    SchnorrPublicKeyArgs, SignWithEcdsaArgs, SignWithSchnorrArgs, ecdsa_public_key,
    schnorr_public_key, sign_with_ecdsa, sign_with_schnorr,
};
use sha3::{Digest, Keccak256};

use crate::auth::{ChainKind, abi_address, abi_uint};
use crate::{ChainSpec, OutcomeView, StateView};

fn ecdsa_key_id() -> EcdsaKeyId {
    EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: crate::THRESHOLD_KEY.to_string(),
    }
}

fn schnorr_key_id() -> SchnorrKeyId {
    SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Ed25519,
        name: crate::THRESHOLD_KEY.to_string(),
    }
}

/// Fetches and caches the public keys for every chain kind in the config.
/// Runs on the timer until both caches are warm; queries serve from cache.
pub(crate) async fn ensure_resolver_keys() {
    let kinds: Vec<ChainKind> = crate::CHAINS.iter().map(ChainSpec::kind).collect();
    if kinds.contains(&ChainKind::Evm) && crate::ecdsa_public_key_bytes().is_empty() {
        match ecdsa_public_key(&EcdsaPublicKeyArgs {
            canister_id: None,
            derivation_path: Vec::new(),
            key_id: ecdsa_key_id(),
        })
        .await
        {
            Ok(result) => crate::set_ecdsa_public_key(result.public_key),
            Err(error) => ic_cdk::println!("ecdsa_public_key: {error}"),
        }
    }
    if kinds.contains(&ChainKind::Solana) && crate::schnorr_public_key_bytes().is_empty() {
        match schnorr_public_key(&SchnorrPublicKeyArgs {
            canister_id: None,
            derivation_path: Vec::new(),
            key_id: schnorr_key_id(),
        })
        .await
        {
            Ok(result) => crate::set_schnorr_public_key(result.public_key),
            Err(error) => ic_cdk::println!("schnorr_public_key: {error}"),
        }
    }
}

/// The RESOLVER birth field this canister answers for on `spec`'s chain:
/// the eth address of the tECDSA key on EVM, the Ed25519 public key on
/// Solana. `None` until the key cache is warm.
pub(crate) fn resolver_for(spec: &ChainSpec) -> Option<Vec<u8>> {
    match spec.kind() {
        ChainKind::Evm => {
            let sec1 = crate::ecdsa_public_key_bytes();
            let key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).ok()?;
            Some(crate::auth::eth_address(&key))
        }
        ChainKind::Solana => {
            let key = crate::schnorr_public_key_bytes();
            (key.len() == 32).then_some(key)
        }
    }
}

/// The contract outcome index of a recorded verdict (factory-spec §2).
fn outcome_index(outcome: OutcomeView) -> u8 {
    match outcome {
        OutcomeView::Settle => 0,
        OutcomeView::Cancel => 1,
    }
}

/// EVM: keccak256(abi.encode(chainid, escrow, outcome)) — the raw digest the
/// escrow recovers, no EIP-191/712 prefix (game-spec §8).
pub fn evm_verdict_digest(chain_id: u64, escrow: &[u8], outcome: u8) -> Option<[u8; 32]> {
    let mut encoded = Vec::with_capacity(96);
    abi_uint(&mut encoded, chain_id);
    abi_address(&mut encoded, escrow).ok()?;
    abi_uint(&mut encoded, u64::from(outcome));
    Some(Keccak256::digest(&encoded).into())
}

/// Solana: DOMAIN ‖ program ‖ escrow ‖ outcome — the ed25519_program message
/// the escrow demands right before claim (game-spec §8).
pub fn sol_verdict_message(domain: &str, program: &[u8], escrow: &[u8], outcome: u8) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len() + 65);
    message.extend_from_slice(domain.as_bytes());
    message.extend_from_slice(program);
    message.extend_from_slice(escrow);
    message.push(outcome);
    message
}

/// Signs every recorded-but-unsigned verdict. A failure leaves the task in
/// the pending set for the next sweep; the outcome it signs can never differ
/// from the one in stable memory.
pub(crate) async fn sign_pending() {
    for key in crate::take_pending_signatures() {
        let Some(record) = crate::load_task(&key) else {
            continue;
        };
        let StateView::Decided { outcome } = record.state else {
            continue;
        };
        if record.verdict_signature.is_some() {
            continue;
        }
        match sign_verdict(&record, outcome_index(outcome)).await {
            Ok(signature) => {
                // The await yielded: re-read the truth before writing.
                let Some(mut record) = crate::load_task(&key) else {
                    continue;
                };
                if matches!(record.state, StateView::Decided { .. })
                    && record.verdict_signature.is_none()
                {
                    record.verdict_signature = Some(serde_bytes::ByteBuf::from(signature));
                    crate::save_task(&record);
                }
            }
            Err(error) => {
                ic_cdk::println!("sign verdict: {error}");
                crate::requeue_signature(key);
            }
        }
    }
}

async fn sign_verdict(record: &crate::TaskRecord, outcome: u8) -> Result<Vec<u8>, String> {
    let spec = crate::auth::spec_of(&record.chain).map_err(|e| e.text().to_string())?;
    match spec.kind() {
        ChainKind::Evm => {
            let digest = evm_verdict_digest(spec.evm_chain_id, &record.task_id, outcome)
                .ok_or("bad escrow address length")?;
            let result = sign_with_ecdsa(&SignWithEcdsaArgs {
                message_hash: digest.to_vec(),
                derivation_path: Vec::new(),
                key_id: ecdsa_key_id(),
            })
            .await
            .map_err(|error| format!("sign_with_ecdsa: {error}"))?;
            evm_signature_with_v(&digest, &result.signature)
        }
        ChainKind::Solana => {
            let program = bs58::decode(spec.factory)
                .into_vec()
                .map_err(|_| "malformed factory program id")?;
            let message = sol_verdict_message(spec.domain, &program, &record.task_id, outcome);
            let result = sign_with_schnorr(&SignWithSchnorrArgs {
                message: message.clone(),
                derivation_path: Vec::new(),
                key_id: schnorr_key_id(),
                aux: None,
            })
            .await
            .map_err(|error| format!("sign_with_schnorr: {error}"))?;
            // Sanity against the cached key: a signature the chain would
            // reject must never be stored.
            let key: [u8; 32] = crate::schnorr_public_key_bytes()
                .try_into()
                .map_err(|_| "schnorr key cache empty")?;
            let signature: [u8; 64] = result
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| "unexpected schnorr signature length")?;
            ed25519_dalek::VerifyingKey::from_bytes(&key)
                .and_then(|key| {
                    key.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&signature))
                })
                .map_err(|_| "schnorr signature does not verify")?;
            Ok(signature.to_vec())
        }
    }
}

/// tECDSA returns 64 bytes r ‖ s. The contract's `ECDSA.recover` demands
/// low-s and v ∈ {27, 28}: normalize, then find the recovery id by trial
/// against the cached public key — which simultaneously verifies the bytes.
fn evm_signature_with_v(digest: &[u8; 32], signature: &[u8]) -> Result<Vec<u8>, String> {
    let sec1 = crate::ecdsa_public_key_bytes();
    let expected =
        k256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| "ecdsa key cache empty")?;
    let sig =
        k256::ecdsa::Signature::from_slice(signature).map_err(|_| "unexpected ecdsa signature")?;
    let sig = sig.normalize_s().unwrap_or(sig);
    for recovery in [0u8, 1] {
        let Some(id) = k256::ecdsa::RecoveryId::from_byte(recovery) else {
            continue;
        };
        if k256::ecdsa::VerifyingKey::recover_from_prehash(digest, &sig, id)
            .map(|key| key == expected)
            .unwrap_or(false)
        {
            let mut out = sig.to_bytes().to_vec();
            out.push(27 + recovery);
            return Ok(out);
        }
    }
    Err("ecdsa signature does not recover to the resolver key".to_string())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    // Frozen against the escrow's digest: keccak256(abi.encode(chainid,
    // escrow, outcome)), computed with `cast keccak $(cast abi-encode
    // "f(uint256,address,uint8)" 11155111 0x1111...11 0)`.
    #[test]
    fn evm_verdict_digest_matches_cast_vector() {
        let digest = evm_verdict_digest(11_155_111, &[0x11; 20], 0).unwrap();
        assert_eq!(
            digest.to_vec(),
            EVM_DIGEST_VECTOR
                .as_bytes()
                .chunks(2)
                .map(|pair| { u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap() })
                .collect::<Vec<_>>()
        );
    }

    const EVM_DIGEST_VECTOR: &str =
        "eac4b38624b36ed38a9df3e40d15f13f7c8b9ed392ea339acdbb03a922a42b48";

    // The Solana message mirrors the on-chain factory byte for byte:
    // DOMAIN ‖ program_id ‖ escrow ‖ outcome.
    #[test]
    fn sol_verdict_message_layout_is_pinned() {
        let message = sol_verdict_message("crown:two-outcome:solana-devnet", &[7; 32], &[9; 32], 1);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"crown:two-outcome:solana-devnet");
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&[9; 32]);
        expected.push(1);
        assert_eq!(message, expected);
    }
}
