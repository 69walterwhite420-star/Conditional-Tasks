//! The threshold verdict (docs/game-spec.md §8): the resolver key, the exact
//! contract byte format, and the signing sweep. The verdict is written to
//! stable memory before any signature is requested; a retry can only ever
//! re-sign the same recorded outcome.

use ic_cdk_management_canister::{
    SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgs, SignWithSchnorrArgs, schnorr_public_key,
    sign_with_schnorr,
};

use crate::{OutcomeView, StateView};

fn schnorr_key_id() -> SchnorrKeyId {
    SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Ed25519,
        name: crate::THRESHOLD_KEY.to_string(),
    }
}

/// Fetches and caches the resolver public key. Runs on the timer until the
/// cache is warm; queries serve from cache.
pub(crate) async fn ensure_resolver_keys() {
    if crate::schnorr_public_key_bytes().is_empty() {
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

/// The RESOLVER birth field this canister answers for: its Ed25519 public
/// key. `None` until the key cache is warm.
pub(crate) fn resolver() -> Option<Vec<u8>> {
    let key = crate::schnorr_public_key_bytes();
    (key.len() == 32).then_some(key)
}

/// The contract outcome index of a recorded verdict (factory-spec §2).
fn outcome_index(outcome: OutcomeView) -> u8 {
    match outcome {
        OutcomeView::Settle => 0,
        OutcomeView::Cancel => 1,
    }
}

/// DOMAIN ‖ program ‖ escrow ‖ outcome — the ed25519_program message the
/// escrow demands right before claim (game-spec §8).
pub fn verdict_message(domain: &str, program: &[u8], escrow: &[u8], outcome: u8) -> Vec<u8> {
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
    let program = bs58::decode(spec.factory)
        .into_vec()
        .map_err(|_| "malformed factory program id")?;
    let message = verdict_message(spec.domain, &program, &record.task_id, outcome);
    let result = sign_with_schnorr(&SignWithSchnorrArgs {
        message: message.clone(),
        derivation_path: Vec::new(),
        key_id: schnorr_key_id(),
        aux: None,
    })
    .await
    .map_err(|error| format!("sign_with_schnorr: {error}"))?;
    // Sanity against the cached key: a signature the chain would reject must
    // never be stored.
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

    // The verdict message mirrors the on-chain factory byte for byte:
    // DOMAIN ‖ program_id ‖ escrow ‖ outcome.
    #[test]
    fn verdict_message_layout_is_pinned() {
        let message = verdict_message("crown:two-outcome:solana-devnet", &[7; 32], &[9; 32], 1);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"crown:two-outcome:solana-devnet");
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&[9; 32]);
        expected.push(1);
        assert_eq!(message, expected);
    }
}
