//! Vote weight and donor reputation: the single inter-canister seam — a
//! replicated call into crown-index's book (docs/game-spec.md §6). The book
//! is the only authority on weight; there is no snapshot and no cache.

use candid::{Nat, Principal};
use serde_bytes::ByteBuf;

/// book[(chain, wallet, streamer)] at this moment, straight from the pinned
/// crown-index canister.
pub async fn book_value(chain: &str, wallet: &[u8], streamer: &[u8]) -> Result<u128, String> {
    let index = crate::crown_index().ok_or("crown-index principal is not configured")?;
    let response = ic_cdk::call::Call::unbounded_wait(index, "get_reputation")
        .with_args(&(
            chain.to_string(),
            ByteBuf::from(wallet.to_vec()),
            ByteBuf::from(streamer.to_vec()),
        ))
        .await
        .map_err(|error| format!("crown-index call failed: {error}"))?;
    let value: Nat = response
        .candid()
        .map_err(|error| format!("crown-index reply: {error}"))?;
    u128::try_from(value.0).map_err(|_| "book value exceeds u128".to_string())
}

/// The book canister: the init override (local testing) wins, otherwise the
/// baked config value. `None` means every reputation-dependent path errors.
pub(crate) fn resolve(override_bytes: &[u8], baked: &str) -> Option<Principal> {
    if !override_bytes.is_empty() {
        return Some(Principal::from_slice(override_bytes));
    }
    if baked.is_empty() {
        return None;
    }
    Principal::from_text(baked).ok()
}
