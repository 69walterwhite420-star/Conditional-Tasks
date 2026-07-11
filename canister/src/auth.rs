//! Authorization is a wallet signature, never the calling principal
//! (docs/game-spec.md §4): the message layout every participant signs, its
//! verification per chain kind, and the task_id derivation that notarizes
//! the declared birth fields — the same arithmetic the core's indexer runs.
//!
//! Byte layouts here are a frozen protocol; the unit tests pin them.

use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::ChainSpec;

/// Domain separator of every participant message. Versioned: a canister with
/// different rules is a different game and gets a different domain.
pub const DOMAIN: &[u8] = b"crown:conditional-tasks:v1";

/// Action bytes of the message protocol. Values are frozen forever;
/// `4` is `vote` (G3).
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
pub enum ChainKind {
    Evm,
    Solana,
}

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

impl ChainSpec {
    pub fn kind(&self) -> ChainKind {
        if self.id.starts_with("solana") {
            ChainKind::Solana
        } else {
            ChainKind::Evm
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
/// chain-local address bytes. EVM wallets sign via EIP-191 `personal_sign`
/// (65 bytes r ‖ s ‖ v); Solana wallets sign the raw message with Ed25519
/// (64 bytes), the address being the public key itself.
pub fn verify_wallet_signature(
    kind: ChainKind,
    message: &[u8],
    signature: &[u8],
    signer: &[u8],
) -> Result<(), AuthError> {
    match kind {
        ChainKind::Evm => {
            let (sig, v) = match signature {
                [sig @ .., v] if sig.len() == 64 => (sig, *v),
                _ => return Err(AuthError::BadSignature),
            };
            let recovery = match v {
                0 | 1 => v,
                27 | 28 => v - 27,
                _ => return Err(AuthError::BadSignature),
            };
            let recovery =
                k256::ecdsa::RecoveryId::from_byte(recovery).ok_or(AuthError::BadSignature)?;
            let sig =
                k256::ecdsa::Signature::from_slice(sig).map_err(|_| AuthError::BadSignature)?;
            let digest = eip191_digest(message);
            let key = k256::ecdsa::VerifyingKey::recover_from_prehash(&digest, &sig, recovery)
                .map_err(|_| AuthError::BadSignature)?;
            if eth_address(&key) == signer {
                Ok(())
            } else {
                Err(AuthError::BadSignature)
            }
        }
        ChainKind::Solana => {
            let signer: [u8; 32] = signer.try_into().map_err(|_| AuthError::BadFieldLength)?;
            let signature: [u8; 64] = signature.try_into().map_err(|_| AuthError::BadSignature)?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&signer)
                .map_err(|_| AuthError::BadSignature)?;
            key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
                .map_err(|_| AuthError::BadSignature)
        }
    }
}

/// EIP-191 personal_sign digest: wallets prepend
/// `"\x19Ethereum Signed Message:\n" + len` before hashing.
fn eip191_digest(message: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(b"\x19Ethereum Signed Message:\n");
    hasher.update(message.len().to_string().as_bytes());
    hasher.update(message);
    hasher.finalize().into()
}

/// keccak256(uncompressed public key)[12..]: the wallet address.
pub fn eth_address(key: &k256::ecdsa::VerifyingKey) -> Vec<u8> {
    let point = key.to_encoded_point(false);
    let digest: [u8; 32] = Keccak256::digest(point.as_bytes().get(1..).unwrap_or_default()).into();
    digest.get(12..).unwrap_or_default().to_vec()
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
    match spec.kind() {
        ChainKind::Evm => {
            // salt = keccak256(abi.encode(donor, streamer, gross, deadline,
            // resolver, nonce)) — six 32-byte words, exactly Factory.sol.
            let mut encoded = Vec::with_capacity(192);
            abi_address(&mut encoded, donor)?;
            abi_address(&mut encoded, streamer)?;
            abi_uint(&mut encoded, gross);
            abi_uint(&mut encoded, deadline);
            abi_address(&mut encoded, resolver)?;
            abi_uint(&mut encoded, nonce);
            let salt: [u8; 32] = Keccak256::digest(&encoded).into();

            let factory: [u8; 20] = hex_bytes(spec.factory)
                .and_then(|b| b.try_into().ok())
                .ok_or(AuthError::MalformedConfig)?;
            let init_code_hash: [u8; 32] = hex_bytes(spec.escrow_init_code_hash)
                .and_then(|b| b.try_into().ok())
                .ok_or(AuthError::MalformedConfig)?;
            Ok(crown_derive::evm_create2_address(factory, salt, init_code_hash).to_vec())
        }
        ChainKind::Solana => {
            let donor: [u8; 32] = donor.try_into().map_err(|_| AuthError::BadFieldLength)?;
            let streamer: [u8; 32] = streamer.try_into().map_err(|_| AuthError::BadFieldLength)?;
            let resolver: [u8; 32] = resolver.try_into().map_err(|_| AuthError::BadFieldLength)?;
            // The on-chain program takes deadline as i64.
            let deadline = i64::try_from(deadline).map_err(|_| AuthError::DeadlineOverflow)?;
            // salt = sha256(donor ‖ streamer ‖ gross_le ‖ deadline_le ‖
            // resolver ‖ nonce_le) — exactly the program's birth_salt.
            let mut hasher = Sha256::new();
            hasher.update(donor);
            hasher.update(streamer);
            hasher.update(gross.to_le_bytes());
            hasher.update(deadline.to_le_bytes());
            hasher.update(resolver);
            hasher.update(nonce.to_le_bytes());
            let salt: [u8; 32] = hasher.finalize().into();

            let program: [u8; 32] = bs58::decode(spec.factory)
                .into_vec()
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or(AuthError::MalformedConfig)?;
            let (address, _bump) = crown_derive::solana_pda_address(program, &[b"escrow", &salt])
                .ok_or(AuthError::NoAddress)?;
            Ok(address.to_vec())
        }
    }
}

pub(crate) fn abi_address(out: &mut Vec<u8>, address: &[u8]) -> Result<(), AuthError> {
    if address.len() != 20 {
        return Err(AuthError::BadFieldLength);
    }
    out.extend([0u8; 12]);
    out.extend_from_slice(address);
    Ok(())
}

pub(crate) fn abi_uint(out: &mut Vec<u8>, value: u64) {
    out.extend([0u8; 24]);
    out.extend(value.to_be_bytes());
}

fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    let hex = text.strip_prefix("0x").unwrap_or(text);
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    hex.as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = char::from(*pair.first()?).to_digit(16)?;
            let low = char::from(*pair.get(1)?).to_digit(16)?;
            Some((high * 16 + low) as u8)
        })
        .collect()
}

/// Deploy-time validation: every baked chain entry must parse. A canister
/// with a malformed config must not exist.
pub fn validate_config() -> Result<(), AuthError> {
    for spec in crate::CHAINS {
        match spec.kind() {
            ChainKind::Evm => {
                hex_bytes(spec.factory)
                    .filter(|b| b.len() == 20)
                    .ok_or(AuthError::MalformedConfig)?;
                hex_bytes(spec.escrow_init_code_hash)
                    .filter(|b| b.len() == 32)
                    .ok_or(AuthError::MalformedConfig)?;
                if spec.evm_chain_id == 0 {
                    return Err(AuthError::MalformedConfig);
                }
            }
            ChainKind::Solana => {
                bs58::decode(spec.factory)
                    .into_vec()
                    .ok()
                    .filter(|b| b.len() == 32)
                    .ok_or(AuthError::MalformedConfig)?;
                if spec.domain.is_empty() {
                    return Err(AuthError::MalformedConfig);
                }
            }
        }
        if spec.min_gross == 0 {
            return Err(AuthError::MalformedConfig);
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
    use super::*;

    // ---- frozen message layouts -----------------------------------------

    #[test]
    fn task_message_layout_is_pinned() {
        let message = task_message("eth-sepolia", &[0xAA, 0xBB], &[0xCC], ACTION_ACCEPT, &[]);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"crown:conditional-tasks:v1");
        expected.extend(11u32.to_le_bytes());
        expected.extend_from_slice(b"eth-sepolia");
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

    fn evm_signer(seed: u8) -> (k256::ecdsa::SigningKey, Vec<u8>) {
        let key = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let address = eth_address(key.verifying_key());
        (key, address)
    }

    fn evm_sign(key: &k256::ecdsa::SigningKey, message: &[u8]) -> Vec<u8> {
        let digest = eip191_digest(message);
        let (sig, recovery) = key.sign_prehash_recoverable(&digest).unwrap();
        let mut out = sig.to_bytes().to_vec();
        out.push(27 + recovery.to_byte());
        out
    }

    #[test]
    fn evm_signature_roundtrip_and_rejections() {
        let (key, address) = evm_signer(7);
        let message = task_message("eth-sepolia", &[1], &[2; 20], ACTION_ACCEPT, &[]);
        let sig = evm_sign(&key, &message);
        verify_wallet_signature(ChainKind::Evm, &message, &sig, &address).unwrap();

        // Foreign signer.
        let (_, other) = evm_signer(8);
        assert_eq!(
            verify_wallet_signature(ChainKind::Evm, &message, &sig, &other),
            Err(AuthError::BadSignature)
        );
        // Foreign message: same signer, different task.
        let foreign = task_message("eth-sepolia", &[1], &[3; 20], ACTION_ACCEPT, &[]);
        assert_eq!(
            verify_wallet_signature(ChainKind::Evm, &foreign, &sig, &address),
            Err(AuthError::BadSignature)
        );
        // Malformed v.
        let mut bad_v = sig.clone();
        *bad_v.last_mut().unwrap() = 29;
        assert_eq!(
            verify_wallet_signature(ChainKind::Evm, &message, &bad_v, &address),
            Err(AuthError::BadSignature)
        );
        // v as a raw recovery id is accepted too.
        let mut raw_v = sig;
        *raw_v.last_mut().unwrap() -= 27;
        verify_wallet_signature(ChainKind::Evm, &message, &raw_v, &address).unwrap();
    }

    #[test]
    fn solana_signature_roundtrip_and_rejections() {
        use ed25519_dalek::Signer;
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let address = key.verifying_key().to_bytes().to_vec();
        let message = task_message("solana-devnet", &[1], &[2; 32], ACTION_DONE, &[]);
        let sig = key.sign(&message).to_bytes().to_vec();
        verify_wallet_signature(ChainKind::Solana, &message, &sig, &address).unwrap();

        let other = ed25519_dalek::SigningKey::from_bytes(&[10; 32])
            .verifying_key()
            .to_bytes()
            .to_vec();
        assert_eq!(
            verify_wallet_signature(ChainKind::Solana, &message, &sig, &other),
            Err(AuthError::BadSignature)
        );
        let foreign = task_message("solana-devnet", &[1], &[3; 32], ACTION_DONE, &[]);
        assert_eq!(
            verify_wallet_signature(ChainKind::Solana, &foreign, &sig, &address),
            Err(AuthError::BadSignature)
        );
    }

    // ---- task_id derivation ----------------------------------------------

    fn evm_spec() -> ChainSpec {
        ChainSpec {
            id: "eth-sepolia",
            factory: "0xb3e280657477c9effed7f02ff7233faa9ccc6258",
            escrow_init_code_hash: "0x5415a5314b9bebe5a6fe092fff7737865b86b2eb8538af8a25ae567781c02951",
            evm_chain_id: 11155111,
            domain: "",
            min_gross: 34,
        }
    }

    fn solana_spec() -> ChainSpec {
        ChainSpec {
            id: "solana-devnet",
            factory: "4VNAQAtgaUKCxn8ESzZsq5QPkGCypvXcsC6ehgLYY1zN",
            escrow_init_code_hash: "",
            evm_chain_id: 0,
            domain: "crown:two-outcome:solana-devnet",
            min_gross: 34,
        }
    }

    // Frozen cross-tool vector: salt computed with
    // `cast keccak $(cast abi-encode "f(address,address,uint256,uint64,address,uint256)" \
    //   0x1111111111111111111111111111111111111111 \
    //   0x2222222222222222222222222222222222222222 \
    //   1000000 1900000000 \
    //   0x3333333333333333333333333333333333333333 7)`,
    // address with `cast create2 --deployer ... --salt ... --init-code-hash ...`.
    #[test]
    fn evm_task_id_matches_cast_vector() {
        let task_id = derive_task_id(
            &evm_spec(),
            &[0x11; 20],
            &[0x22; 20],
            1_000_000,
            1_900_000_000,
            &[0x33; 20],
            7,
        )
        .unwrap();
        assert_eq!(
            task_id,
            hex_bytes(EVM_VECTOR_ADDRESS).unwrap(),
            "create2 vector mismatch"
        );
    }

    const EVM_VECTOR_ADDRESS: &str = "0xA1ea6D86b310625E714F81620E2558d5d98B230F";

    // Frozen cross-tool vector: salt is sha256 over the exact byte concat,
    // computed independently with python3 hashlib over
    // donor ‖ streamer ‖ u64le(1000000) ‖ i64le(1900000000) ‖ resolver ‖ u64le(7);
    // the PDA arithmetic itself is parity-tested inside crown-derive.
    #[test]
    fn solana_task_id_matches_reference_salt() {
        let donor = [0x11; 32];
        let streamer = [0x22; 32];
        let resolver = [0x33; 32];
        let task_id = derive_task_id(
            &solana_spec(),
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
        hasher.update(7u64.to_le_bytes());
        let salt: [u8; 32] = hasher.finalize().into();
        assert_eq!(salt.to_vec(), hex_bytes(SOLANA_VECTOR_SALT).unwrap());

        let program: [u8; 32] = bs58::decode(solana_spec().factory)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        let (expected, _) = crown_derive::solana_pda_address(program, &[b"escrow", &salt]).unwrap();
        assert_eq!(task_id, expected.to_vec());
    }

    const SOLANA_VECTOR_SALT: &str =
        "afcf96c22076785f4be1e9d7a94a78e1f3e9e6ec5e8c7709ef786e9a294972ed";

    #[test]
    fn derivation_rejects_wrong_field_lengths() {
        assert_eq!(
            derive_task_id(&evm_spec(), &[0x11; 19], &[0x22; 20], 34, 1, &[0x33; 20], 0),
            Err(AuthError::BadFieldLength)
        );
        assert_eq!(
            derive_task_id(
                &solana_spec(),
                &[0x11; 32],
                &[0x22; 31],
                34,
                1,
                &[0x33; 32],
                0
            ),
            Err(AuthError::BadFieldLength)
        );
        assert_eq!(
            derive_task_id(
                &solana_spec(),
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
