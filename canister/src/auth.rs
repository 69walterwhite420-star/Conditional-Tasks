//! Authorization is a wallet signature, never the calling principal
//! (docs/game-spec.md §4): the message every participant signs, its
//! verification, and the task_id derivation that notarizes the declared
//! birth fields — the same arithmetic the core's indexer runs.
//!
//! **Messages are UTF-8 text, and that is a hard requirement, not taste.**
//! Wallets refuse to sign bytes they cannot show to a human: Phantom runs
//! `isValidUTF8` over the payload and rejects everything else with "You
//! cannot sign solana transactions using sign message". A binary protocol
//! here means the game is unplayable with the largest Solana wallet — and a
//! signature nobody can read is a signature nobody should be asked for.
//!
//! The text is a frozen protocol; the unit tests pin every line of it.

use crate::ChainSpec;

/// Domain separator of every participant message, and its first line.
/// Versioned: a canister with different rules is a different game and gets a
/// different domain.
pub const DOMAIN: &str = "crown:conditional-tasks:v1";

/// The vote, as the message spells it. Words are frozen forever.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    Done,
    NotDone,
}

impl Choice {
    pub fn word(self) -> &'static str {
        match self {
            Choice::Done => "done",
            Choice::NotDone => "not_done",
        }
    }
}

/// What the participant is signing for. Carries the fields that belong to
/// that action and nothing else — an action and its payload can no longer
/// disagree, because there is no separate payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action<'a> {
    Register { text_hash: &'a [u8], duration: u64 },
    Accept,
    Decline,
    Done,
    Vote(Choice),
    OperatorRefund,
}

impl Action<'_> {
    /// The word that names the action in the message. Frozen forever.
    pub fn word(&self) -> &'static str {
        match self {
            Action::Register { .. } => "register",
            Action::Accept => "accept",
            Action::Decline => "decline",
            Action::Done => "done",
            Action::Vote(_) => "vote",
            Action::OperatorRefund => "operator-refund",
        }
    }
}

/// Lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

pub fn spec_of(chain: &str) -> Result<&'static ChainSpec, AuthError> {
    crate::CHAINS
        .iter()
        .find(|spec| spec.id == chain)
        .ok_or(AuthError::UnknownChain)
}

/// The message a participant signs about one task. One field per line,
/// `key: value`, in this exact order:
///
/// ```text
/// crown:conditional-tasks:v1
/// action: accept
/// chain: solana-devnet
/// canister: vizcg-th777-77774-qaaea-cai
/// task: 3tjoUqMwgUcyfWqYvDMGRY5gBXPNPKyY3gErYhJGqxcu
/// ```
///
/// `register` adds `text:` (hex) and `duration:`; `vote` adds `choice:`.
///
/// The encoding is injective — two different messages cannot render to the
/// same text — because the keys are fixed and ordered, the action decides
/// which keys follow, and no value can contain a newline: addresses are
/// base58, hashes are hex, numbers are decimal, words are a closed
/// vocabulary, and `validate_config` refuses a chain id with anything else
/// in it.
pub fn task_message(chain: &str, canister_id: &str, task_id: &[u8], action: &Action) -> String {
    let mut out = String::new();
    out.push_str(DOMAIN);
    out.push('\n');
    out.push_str(&format!("action: {}\n", action.word()));
    out.push_str(&format!("chain: {chain}\n"));
    out.push_str(&format!("canister: {canister_id}\n"));
    // task_id ≡ the escrow address, so base58 is the form the signer can
    // compare against an explorer.
    out.push_str(&format!("task: {}\n", bs58::encode(task_id).into_string()));
    match action {
        Action::Register {
            text_hash,
            duration,
        } => {
            out.push_str(&format!("text: {}\n", hex(text_hash)));
            out.push_str(&format!("duration: {duration}\n"));
        }
        Action::Vote(choice) => out.push_str(&format!("choice: {}\n", choice.word())),
        Action::Accept | Action::Decline | Action::Done | Action::OperatorRefund => {}
    }
    out
}

/// The message a recipient signs to change profile parameters. The monotonic
/// counter keeps an old signature from being replayed.
///
/// ```text
/// crown:conditional-tasks:v1
/// action: set-profile
/// chain: solana-devnet
/// canister: vizcg-th777-77774-qaaea-cai
/// recipient: Gt381v8RqGQUX7vdRbC9NdZCzGuzk6ZUgcTDLfUnYdcJ
/// min_gross: 34
/// min_reputation: 0
/// enabled: true
/// counter: 7
/// ```
pub fn profile_message(
    chain: &str,
    canister_id: &str,
    recipient: &[u8],
    min_gross: u64,
    min_reputation: u128,
    enabled: bool,
    counter: u64,
) -> String {
    let mut out = String::new();
    out.push_str(DOMAIN);
    out.push('\n');
    out.push_str("action: set-profile\n");
    out.push_str(&format!("chain: {chain}\n"));
    out.push_str(&format!("canister: {canister_id}\n"));
    out.push_str(&format!(
        "recipient: {}\n",
        bs58::encode(recipient).into_string()
    ));
    out.push_str(&format!("min_gross: {min_gross}\n"));
    out.push_str(&format!("min_reputation: {min_reputation}\n"));
    out.push_str(&format!("enabled: {enabled}\n"));
    out.push_str(&format!("counter: {counter}\n"));
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
    recipient: &[u8],
    gross: u64,
    deadline: u64,
    resolver: &[u8],
    nonce: u64,
) -> Result<Vec<u8>, AuthError> {
    let donor: [u8; 32] = donor.try_into().map_err(|_| AuthError::BadFieldLength)?;
    let recipient: [u8; 32] = recipient.try_into().map_err(|_| AuthError::BadFieldLength)?;
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
        &recipient,
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
    // The operator wallet is empty until a real deploy pins it (like the
    // book principal); non-empty it must be a valid address.
    if !crate::OPERATOR_WALLET.is_empty() {
        bs58::decode(crate::OPERATOR_WALLET)
            .into_vec()
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or(AuthError::MalformedConfig)?;
    }
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
        // The chain id goes into the signed text as a value. A newline (or a
        // control character) in it would let one chain id render a message
        // another chain id could also render — the encoding must stay
        // injective, so refuse such a config to exist at all.
        if spec.id.is_empty()
            || !spec
                .id
                .chars()
                .all(|c| c.is_ascii_graphic() && c != ':' && c != '\n')
        {
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

    const CANISTER: &str = "vizcg-th777-77774-qaaea-cai";
    /// base58 of [0xCC; 32], computed independently with python.
    const TASK_B58: &str = "EnTJCS15dqbDTU2XywYSMaScoPv4Py4GzExrtY9DQxoD";

    #[test]
    fn accept_message_is_pinned() {
        assert_eq!(
            task_message("solana-devnet", CANISTER, &[0xCC; 32], &Action::Accept),
            format!(
                "crown:conditional-tasks:v1\n\
                 action: accept\n\
                 chain: solana-devnet\n\
                 canister: {CANISTER}\n\
                 task: {TASK_B58}\n"
            )
        );
    }

    #[test]
    fn register_message_is_pinned() {
        let message = task_message(
            "solana-devnet",
            CANISTER,
            &[0xCC; 32],
            &Action::Register {
                text_hash: &[0x11; 2],
                duration: 300,
            },
        );
        assert_eq!(
            message,
            format!(
                "crown:conditional-tasks:v1\n\
                 action: register\n\
                 chain: solana-devnet\n\
                 canister: {CANISTER}\n\
                 task: {TASK_B58}\n\
                 text: 1111\n\
                 duration: 300\n"
            )
        );
    }

    #[test]
    fn vote_message_is_pinned() {
        for (choice, word) in [(Choice::Done, "done"), (Choice::NotDone, "not_done")] {
            assert_eq!(
                task_message(
                    "solana-devnet",
                    CANISTER,
                    &[0xCC; 32],
                    &Action::Vote(choice)
                ),
                format!(
                    "crown:conditional-tasks:v1\n\
                     action: vote\n\
                     chain: solana-devnet\n\
                     canister: {CANISTER}\n\
                     task: {TASK_B58}\n\
                     choice: {word}\n"
                )
            );
        }
    }

    #[test]
    fn operator_refund_message_is_pinned() {
        assert_eq!(
            task_message(
                "solana-devnet",
                CANISTER,
                &[0xCC; 32],
                &Action::OperatorRefund
            ),
            format!(
                "crown:conditional-tasks:v1\n\
                 action: operator-refund\n\
                 chain: solana-devnet\n\
                 canister: {CANISTER}\n\
                 task: {TASK_B58}\n"
            )
        );
    }

    #[test]
    fn profile_message_is_pinned() {
        assert_eq!(
            profile_message("solana-devnet", CANISTER, &[0x02; 32], 34, 5, true, 7),
            format!(
                "crown:conditional-tasks:v1\n\
                 action: set-profile\n\
                 chain: solana-devnet\n\
                 canister: {CANISTER}\n\
                 recipient: {}\n\
                 min_gross: 34\n\
                 min_reputation: 5\n\
                 enabled: true\n\
                 counter: 7\n",
                bs58::encode([0x02; 32]).into_string()
            )
        );
    }

    /// The whole point: a wallet must be able to show this to a human.
    /// Phantom rejects anything that is not valid UTF-8, so every message the
    /// protocol can produce must be printable ASCII.
    #[test]
    fn every_message_is_printable_ascii() {
        let messages = [
            task_message("solana-devnet", CANISTER, &[0xCC; 32], &Action::Accept),
            task_message("solana-devnet", CANISTER, &[0xCC; 32], &Action::Decline),
            task_message("solana-devnet", CANISTER, &[0xCC; 32], &Action::Done),
            task_message(
                "solana-devnet",
                CANISTER,
                &[0xCC; 32],
                &Action::OperatorRefund,
            ),
            task_message(
                "solana-devnet",
                CANISTER,
                &[0xCC; 32],
                &Action::Vote(Choice::NotDone),
            ),
            task_message(
                "solana-devnet",
                CANISTER,
                &[0xCC; 32],
                &Action::Register {
                    text_hash: &[0xFF; 32],
                    duration: u64::MAX,
                },
            ),
            profile_message(
                "solana-devnet",
                CANISTER,
                &[0xFF; 32],
                u64::MAX,
                u128::MAX,
                false,
                u64::MAX,
            ),
        ];
        for message in messages {
            assert!(
                message
                    .chars()
                    .all(|c| c == '\n' || c.is_ascii_graphic() || c == ' '),
                "not printable: {message:?}"
            );
        }
    }

    /// Injectivity: no two distinct messages may render the same text, or one
    /// signature would open two doors.
    #[test]
    fn distinct_messages_render_distinctly() {
        let mut seen = std::collections::BTreeSet::new();
        let messages = [
            task_message("solana-devnet", CANISTER, &[0xCC; 32], &Action::Accept),
            task_message("solana-devnet", CANISTER, &[0xCC; 32], &Action::Decline),
            task_message("solana-devnet", CANISTER, &[0xCC; 32], &Action::Done),
            task_message(
                "solana-devnet",
                CANISTER,
                &[0xCC; 32],
                &Action::OperatorRefund,
            ),
            task_message(
                "solana-devnet",
                CANISTER,
                &[0xCC; 32],
                &Action::Vote(Choice::Done),
            ),
            task_message(
                "solana-devnet",
                CANISTER,
                &[0xCC; 32],
                &Action::Vote(Choice::NotDone),
            ),
            // Another task, another chain, another canister.
            task_message("solana-devnet", CANISTER, &[0xCD; 32], &Action::Accept),
            task_message("solana-mainnet", CANISTER, &[0xCC; 32], &Action::Accept),
            task_message("solana-devnet", "aaaaa-aa", &[0xCC; 32], &Action::Accept),
            // Register: both payload fields must split it.
            task_message(
                "solana-devnet",
                CANISTER,
                &[0xCC; 32],
                &Action::Register {
                    text_hash: &[0x11; 2],
                    duration: 300,
                },
            ),
            task_message(
                "solana-devnet",
                CANISTER,
                &[0xCC; 32],
                &Action::Register {
                    text_hash: &[0x11; 2],
                    duration: 301,
                },
            ),
            task_message(
                "solana-devnet",
                CANISTER,
                &[0xCC; 32],
                &Action::Register {
                    text_hash: &[0x12; 2],
                    duration: 300,
                },
            ),
            profile_message("solana-devnet", CANISTER, &[0x02; 32], 34, 5, true, 7),
            profile_message("solana-devnet", CANISTER, &[0x02; 32], 34, 5, false, 7),
            profile_message("solana-devnet", CANISTER, &[0x02; 32], 34, 5, true, 8),
            profile_message("solana-devnet", CANISTER, &[0x03; 32], 34, 5, true, 7),
        ];
        let count = messages.len();
        for message in messages {
            assert!(seen.insert(message.clone()), "collision: {message:?}");
        }
        assert_eq!(seen.len(), count);
    }

    // ---- signatures -------------------------------------------------------

    #[test]
    fn signature_roundtrip_and_rejections() {
        use ed25519_dalek::Signer;
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let address = key.verifying_key().to_bytes().to_vec();
        let message = task_message("solana-devnet", CANISTER, &[2; 32], &Action::Done);
        let sig = key.sign(message.as_bytes()).to_bytes().to_vec();
        verify_wallet_signature(message.as_bytes(), &sig, &address).unwrap();

        // Foreign signer.
        let other = ed25519_dalek::SigningKey::from_bytes(&[10; 32])
            .verifying_key()
            .to_bytes()
            .to_vec();
        assert_eq!(
            verify_wallet_signature(message.as_bytes(), &sig, &other),
            Err(AuthError::BadSignature)
        );
        // Foreign message: same signer, different task.
        let foreign = task_message("solana-devnet", CANISTER, &[3; 32], &Action::Done);
        assert_eq!(
            verify_wallet_signature(foreign.as_bytes(), &sig, &address),
            Err(AuthError::BadSignature)
        );
        // Foreign action: a decline signature does not accept.
        let action = task_message("solana-devnet", CANISTER, &[2; 32], &Action::Decline);
        assert_eq!(
            verify_wallet_signature(action.as_bytes(), &sig, &address),
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
    // computed independently with python3 hashlib over donor ‖ recipient ‖
    // u64le(1000000) ‖ i64le(1900000000) ‖ resolver ‖ u16le(500) ‖ fee_wallet
    // ‖ u64le(7); the PDA arithmetic itself is parity-tested in crown-derive.
    #[test]
    fn task_id_matches_reference_salt() {
        let donor = [0x11; 32];
        let recipient = [0x22; 32];
        let resolver = [0x33; 32];
        let task_id = derive_task_id(
            &spec(),
            &donor,
            &recipient,
            1_000_000,
            1_900_000_000,
            &resolver,
            7,
        )
        .unwrap();

        let mut hasher = Sha256::new();
        hasher.update(donor);
        hasher.update(recipient);
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
