//! Authorization is a wallet signature, never the calling principal
//! (docs/game-spec.md §4): the message layout every participant signs, its
//! verification, and the task_id derivation that notarizes the declared
//! birth fields — the same arithmetic the core's indexer runs.
//!
//! Byte layouts here are a frozen protocol; the unit tests pin them.

use crate::ChainSpec;

/// Domain separator of every participant message. Versioned: a canister with
/// different rules is a different game and gets a different domain.
pub const DOMAIN: &[u8] = b"crown:conditional-tasks:v1";

/// Action bytes of the message protocol. Values are frozen forever.
pub const ACTION_REGISTER: u8 = 0;
pub const ACTION_ACCEPT: u8 = 1;
pub const ACTION_DECLINE: u8 = 2;
pub const ACTION_DONE: u8 = 3;
pub const ACTION_VOTE: u8 = 4;
pub const ACTION_SET_CHANNEL_PARAMS: u8 = 5;

/// Vote payload bytes (the single payload byte of ACTION_VOTE).
pub const CHOICE_DONE: u8 = 0;
pub const CHOICE_NOT_DONE: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    UnknownChain,
    BadFieldLength,
    BadSignature,
    MalformedConfig,
    DeadlineOverflow,
    NoAddress,
}

impl AuthError {
    pub fn text(self) -> &'static str {
        match self {
            AuthError::UnknownChain => "unknown chain",
            AuthError::BadFieldLength => "bad field length",
            AuthError::BadSignature => "bad signature",
            AuthError::MalformedConfig => "malformed chain config",
            AuthError::DeadlineOverflow => "deadline does not fit the chain",
            AuthError::NoAddress => "escrow address does not exist",
        }
    }
}

pub fn spec_of(chain: &str) -> Result<&'static ChainSpec, AuthError> {
    crate::CHAINS
        .iter()
        .find(|spec| spec.id == chain)
        .ok_or(AuthError::UnknownChain)
}

/// Length-prefixed part: u32 le length, then the bytes. Variable-length
/// parts are always framed so no two field splits share an encoding.
fn lp(out: &mut Vec<u8>, part: &[u8]) {
    out.extend((part.len() as u32).to_le_bytes());
    out.extend_from_slice(part);
}

/// The message a participant signs about one task:
/// `DOMAIN ‖ lp(chain) ‖ lp(canister_id) ‖ lp(task_id) ‖ action ‖ lp(payload)`.
pub fn task_message(
    chain: &str,
    canister_id: &[u8],
    task_id: &[u8],
    action: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(DOMAIN);
    lp(&mut out, chain.as_bytes());
    lp(&mut out, canister_id);
    lp(&mut out, task_id);
    out.push(action);
    lp(&mut out, payload);
    out
}

/// Registration payload: the text commitment and the game-level duration —
/// the two facts not already notarized by the task_id itself.
pub fn register_payload(text_hash: &[u8], duration: u64) -> Vec<u8> {
    let mut out = Vec::new();
    lp(&mut out, text_hash);
    out.extend(duration.to_le_bytes());
    out
}

/// The message a streamer signs to change channel knobs. The monotonic
/// counter keeps an old signature from being replayed.
pub fn channel_message(
    chain: &str,
    canister_id: &[u8],
    streamer: &[u8],
    min_gross: u64,
    min_reputation: u128,
    enabled: bool,
    counter: u64,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(DOMAIN);
    lp(&mut out, chain.as_bytes());
    lp(&mut out, canister_id);
    out.push(ACTION_SET_CHANNEL_PARAMS);
    lp(&mut out, streamer);
    out.extend(min_gross.to_le_bytes());
    out.extend(min_reputation.to_le_bytes());
    out.push(u8::from(enabled));
    out.extend(counter.to_le_bytes());
    out
}

/// Verifies a wallet signature over `message` by `signer` — the wallet's
/// address bytes. Wallets sign the raw message with Ed25519 (64 bytes),
/// the address being the public key itself.
pub fn verify_wallet_signature(
    message: &[u8],
    signature: &[u8],
    signer: &[u8],
) -> Result<(), AuthError> {
    let signer: [u8; 32] = signer.try_into().map_err(|_| AuthError::BadFieldLength)?;
    let signature: [u8; 64] = signature.try_into().map_err(|_| AuthError::BadSignature)?;
    let key =
        ed25519_dalek::VerifyingKey::from_bytes(&signer).map_err(|_| AuthError::BadSignature)?;
    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
        .map_err(|_| AuthError::BadSignature)
}

/// task_id ≡ escrow address, derived from the declared birth fields with the
/// same arithmetic the core's indexer uses (game-spec §4, factory-spec §4).
/// A wrong declaration derives an address where no escrow will ever exist —
/// a verdict for it is harmless.
pub fn derive_task_id(
    spec: &ChainSpec,
    donor: &[u8],
    streamer: &[u8],
    gross: u64,
    deadline: u64,
    resolver: &[u8],
    nonce: u64,
) -> Result<Vec<u8>, AuthError> {
    let donor: [u8; 32] = donor.try_into().map_err(|_| AuthError::BadFieldLength)?;
    let streamer: [u8; 32] = streamer.try_into().map_err(|_| AuthError::BadFieldLength)?;
    let resolver: [u8; 32] = resolver.try_into().map_err(|_| AuthError::BadFieldLength)?;
    // The on-chain program takes deadline as i64; out-of-range is caught here.
    let deadline = i64::try_from(deadline).map_err(|_| AuthError::DeadlineOverflow)?;
    // The game's fee is part of the salt: an escrow born with a price other
    // than this game's derives a different address and never becomes a task.
    let fee_wallet: [u8; 32] = bs58::decode(spec.fee_wallet)
        .into_vec()
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(AuthError::MalformedConfig)?;
    // The shape owns its byte format: `crown-salt` is the single offchain
    // definition of the salt, parity-tested against the deployed program's
    // `birth_salt`.
    let salt = crown_salt::two_outcome::salt(
        &donor,
        &streamer,
        gross,
        deadline,
        &resolver,
        spec.fee_bps,
        &fee_wallet,
        nonce,
    );

    let program: [u8; 32] = bs58::decode(spec.factory)
        .into_vec()
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(AuthError::MalformedConfig)?;
    let (address, _bump) = crown_derive::solana_pda_address(program, &[b"escrow", &salt])
        .ok_or(AuthError::NoAddress)?;
    Ok(address.to_vec())
}

/// Deploy-time validation: every baked chain entry must parse. A canister
/// with a malformed config must not exist.
pub fn validate_config() -> Result<(), AuthError> {
    for (i, spec) in crate::CHAINS.iter().enumerate() {
        bs58::decode(spec.factory)
            .into_vec()
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or(AuthError::MalformedConfig)?;
        bs58::decode(spec.fee_wallet)
            .into_vec()
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or(AuthError::MalformedConfig)?;
        if spec.fee_bps >= 10_000 {
            return Err(AuthError::MalformedConfig);
        }
        if spec.domain.is_empty() {
            return Err(AuthError::MalformedConfig);
        }
        if spec.min_gross == 0 {
            return Err(AuthError::MalformedConfig);
        }
        // Chains must be pairwise distinct in id, domain and factory. The
        // task_id (≡ escrow address) and its salt are chain-independent, so
        // the cluster is separated only by DOMAIN (factory-spec §2.2): two
        // chain entries sharing a (factory, domain) would derive one escrow
        // for the same birth fields and one verdict message, and the single
        // resolver key could then sign two outcomes for one escrow. Refuse
        // such a config to exist.
        for other in crate::CHAINS.iter().skip(i + 1) {
            if spec.id == other.id || spec.domain == other.domain || spec.factory == other.factory {
                return Err(AuthError::MalformedConfig);
            }
        }
    }
    Ok(())
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
    use sha2::{Digest, Sha256};

    use super::*;

    // ---- frozen message layouts -----------------------------------------

    #[test]
    fn task_message_layout_is_pinned() {
        let message = task_message("solana-devnet", &[0xAA, 0xBB], &[0xCC], ACTION_ACCEPT, &[]);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"crown:conditional-tasks:v1");
        expected.extend(13u32.to_le_bytes());
        expected.extend_from_slice(b"solana-devnet");
        expected.extend(2u32.to_le_bytes());
        expected.extend_from_slice(&[0xAA, 0xBB]);
        expected.extend(1u32.to_le_bytes());
        expected.extend_from_slice(&[0xCC]);
        expected.push(1);
        expected.extend(0u32.to_le_bytes());
        assert_eq!(message, expected);
    }

    #[test]
    fn choice_bytes_are_pinned() {
        assert_eq!((CHOICE_DONE, CHOICE_NOT_DONE), (0, 1));
    }

    #[test]
    fn register_payload_layout_is_pinned() {
        let payload = register_payload(&[0x11; 2], 300);
        let mut expected = Vec::new();
        expected.extend(2u32.to_le_bytes());
        expected.extend_from_slice(&[0x11; 2]);
        expected.extend(300u64.to_le_bytes());
        assert_eq!(payload, expected);
    }

    #[test]
    fn channel_message_layout_is_pinned() {
        let message = channel_message("solana-devnet", &[0x01], &[0x02], 34, 5, true, 7);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"crown:conditional-tasks:v1");
        expected.extend(13u32.to_le_bytes());
        expected.extend_from_slice(b"solana-devnet");
        expected.extend(1u32.to_le_bytes());
        expected.push(0x01);
        expected.push(ACTION_SET_CHANNEL_PARAMS);
        expected.extend(1u32.to_le_bytes());
        expected.push(0x02);
        expected.extend(34u64.to_le_bytes());
        expected.extend(5u128.to_le_bytes());
        expected.push(1);
        expected.extend(7u64.to_le_bytes());
        assert_eq!(message, expected);
    }

    // ---- signatures -------------------------------------------------------

    #[test]
    fn signature_roundtrip_and_rejections() {
        use ed25519_dalek::Signer;
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let address = key.verifying_key().to_bytes().to_vec();
        let message = task_message("solana-devnet", &[1], &[2; 32], ACTION_DONE, &[]);
        let sig = key.sign(&message).to_bytes().to_vec();
        verify_wallet_signature(&message, &sig, &address).unwrap();

        // Foreign signer.
        let other = ed25519_dalek::SigningKey::from_bytes(&[10; 32])
            .verifying_key()
            .to_bytes()
            .to_vec();
        assert_eq!(
            verify_wallet_signature(&message, &sig, &other),
            Err(AuthError::BadSignature)
        );
        // Foreign message: same signer, different task.
        let foreign = task_message("solana-devnet", &[1], &[3; 32], ACTION_DONE, &[]);
        assert_eq!(
            verify_wallet_signature(&foreign, &sig, &address),
            Err(AuthError::BadSignature)
        );
        // Foreign action: a decline signature does not accept.
        let action = task_message("solana-devnet", &[1], &[2; 32], ACTION_DECLINE, &[]);
        assert_eq!(
            verify_wallet_signature(&action, &sig, &address),
            Err(AuthError::BadSignature)
        );
    }

    // ---- task_id derivation ----------------------------------------------

    fn spec() -> ChainSpec {
        ChainSpec {
            id: "solana-devnet",
            factory: "83f7ziVs5VeQ8xiDka8zczbfJT4WcxsXQ18cqWwmV5ur",
            domain: "crown:two-outcome:solana-devnet",
            min_gross: 34,
            fee_bps: 500,
            // base58 of [0x44; 32], matching the crown-salt reference vector.
            fee_wallet: "5bV6jUfhDHCQVA1WfKBUnXUsboJgoKgkzkKcxr3joew5",
        }
    }

    // Frozen cross-tool vector: salt is sha256 over the exact byte concat,
    // computed independently with python3 hashlib over donor ‖ streamer ‖
    // u64le(1000000) ‖ i64le(1900000000) ‖ resolver ‖ u16le(500) ‖ fee_wallet
    // ‖ u64le(7); the PDA arithmetic itself is parity-tested in crown-derive.
    #[test]
    fn task_id_matches_reference_salt() {
        let donor = [0x11; 32];
        let streamer = [0x22; 32];
        let resolver = [0x33; 32];
        let task_id = derive_task_id(
            &spec(),
            &donor,
            &streamer,
            1_000_000,
            1_900_000_000,
            &resolver,
            7,
        )
        .unwrap();

        let mut hasher = Sha256::new();
        hasher.update(donor);
        hasher.update(streamer);
        hasher.update(1_000_000u64.to_le_bytes());
        hasher.update(1_900_000_000i64.to_le_bytes());
        hasher.update(resolver);
        hasher.update(500u16.to_le_bytes());
        hasher.update([0x44; 32]);
        hasher.update(7u64.to_le_bytes());
        let salt: [u8; 32] = hasher.finalize().into();
        let expected_salt: Vec<u8> = SALT_VECTOR
            .as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(salt.to_vec(), expected_salt);

        let program: [u8; 32] = bs58::decode(spec().factory)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        let (expected, _) = crown_derive::solana_pda_address(program, &[b"escrow", &salt]).unwrap();
        assert_eq!(task_id, expected.to_vec());
    }

    const SALT_VECTOR: &str = "149c82b09a080ef4c92921d13d974177bfea2dd546ef8b798627e3e4245afe6b";

    #[test]
    fn derivation_rejects_wrong_field_lengths() {
        assert_eq!(
            derive_task_id(&spec(), &[0x11; 32], &[0x22; 31], 34, 1, &[0x33; 32], 0),
            Err(AuthError::BadFieldLength)
        );
        assert_eq!(
            derive_task_id(
                &spec(),
                &[0x11; 32],
                &[0x22; 32],
                34,
                u64::MAX,
                &[0x33; 32],
                0
            ),
            Err(AuthError::DeadlineOverflow)
        );
    }

    #[test]
    fn baked_config_is_valid() {
        validate_config().unwrap();
    }
}
