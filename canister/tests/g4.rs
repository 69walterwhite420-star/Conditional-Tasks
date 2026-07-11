//! G4 integration: the threshold verdict signature (docs/build-plan.md G4).
//! Byte formats against the shape's contracts are pinned locally here; the
//! real contracts accept them in the e2e (scripts/e2e-testnets.sh).
//!
//! Driven by scripts/test-canister.sh, hence the #[ignore] markers.

mod common;

use candid::Encode;
use common::*;
use conditional_tasks::api::{ActionArg, RegisterArg};
use conditional_tasks::{OutcomeView, StateView, auth, sign};
use conditional_tasks_logic as logic;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

const SEPOLIA_CHAIN_ID: u64 = 11_155_111;

/// Half the secp256k1 group order: the low-s bound OpenZeppelin enforces.
const SECP256K1_HALF_N: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
];

fn wait_for_signature(
    pic: &pocket_ic::PocketIc,
    canister: candid::Principal,
    chain: &str,
    task_id: &[u8],
) -> (conditional_tasks::TaskRecord, Vec<u8>) {
    for _ in 0..60 {
        pic.advance_time(std::time::Duration::from_secs(31));
        pic.tick();
        pic.tick();
        let record = task_state(&fetch_task(pic, canister, chain, task_id));
        if let Some(signature) = &record.verdict_signature {
            let signature = signature.to_vec();
            return (record, signature);
        }
    }
    panic!("verdict signature never appeared");
}

fn recover_eth(digest: &[u8; 32], signature: &[u8]) -> Option<Vec<u8>> {
    let (sig, v) = signature.split_at(64);
    let recovery = k256::ecdsa::RecoveryId::from_byte(v.first()? - 27)?;
    let sig = k256::ecdsa::Signature::from_slice(sig).ok()?;
    let key = k256::ecdsa::VerifyingKey::recover_from_prehash(digest, &sig, recovery).ok()?;
    let point = key.to_encoded_point(false);
    let digest: [u8; 32] = sha3::Keccak256::digest(&point.as_bytes()[1..]).into();
    Some(digest[12..].to_vec())
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn cancel_verdict_is_signed_for_the_evm_contract() {
    let (pic, canister) = setup();
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);
    let resolver = resolver(&pic, canister, EVM);

    let r = register_evm(&pic, canister, &donor, &streamer.address, 1).unwrap();
    streamer_call(
        &pic,
        canister,
        "decline",
        auth::ACTION_DECLINE,
        &r.task_id,
        &streamer,
    )
    .unwrap();

    let (record, signature) = wait_for_signature(&pic, canister, EVM, &r.task_id);
    assert_eq!(
        record.state,
        StateView::Decided {
            outcome: OutcomeView::Cancel
        }
    );

    // 65 bytes, v ∈ {27, 28}, low-s: exactly what ECDSA.recover demands.
    assert_eq!(signature.len(), 65);
    assert!(matches!(signature[64], 27 | 28));
    assert!(
        signature[32..64] <= SECP256K1_HALF_N[..],
        "high-s signature"
    );

    // The signature opens exactly (this chain, this escrow, cancel)...
    let digest = sign::evm_verdict_digest(SEPOLIA_CHAIN_ID, &r.task_id, 1).unwrap();
    assert_eq!(recover_eth(&digest, &signature).unwrap(), resolver);

    // ...and nothing else: other outcome, other chain, other escrow.
    let settle = sign::evm_verdict_digest(SEPOLIA_CHAIN_ID, &r.task_id, 0).unwrap();
    assert_ne!(recover_eth(&settle, &signature), Some(resolver.clone()));
    let base = sign::evm_verdict_digest(8453, &r.task_id, 1).unwrap();
    assert_ne!(recover_eth(&base, &signature), Some(resolver.clone()));
    let other = sign::evm_verdict_digest(SEPOLIA_CHAIN_ID, &[0x99; 20], 1).unwrap();
    assert_ne!(recover_eth(&other, &signature), Some(resolver));
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn settle_verdict_is_signed_after_votes() {
    let (pic, canister, index) = setup_with_index();
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);
    let voter = evm_wallet(3);
    let resolver = resolver(&pic, canister, EVM);
    seed_reputation(
        &pic,
        index,
        EVM,
        &voter.address,
        &streamer.address,
        5_000_000,
    );

    let r = register_evm(&pic, canister, &donor, &streamer.address, 1).unwrap();
    streamer_call(
        &pic,
        canister,
        "accept",
        auth::ACTION_ACCEPT,
        &r.task_id,
        &streamer,
    )
    .unwrap();
    streamer_call(
        &pic,
        canister,
        "done",
        auth::ACTION_DONE,
        &r.task_id,
        &streamer,
    )
    .unwrap();

    let message = auth::task_message(
        EVM,
        canister.as_slice(),
        &r.task_id,
        auth::ACTION_VOTE,
        &[auth::CHOICE_DONE],
    );
    let arg = conditional_tasks::api::VoteArg {
        chain: EVM.to_string(),
        task_id: ByteBuf::from(r.task_id.clone()),
        voter: ByteBuf::from(voter.address.clone()),
        choice: conditional_tasks::ChoiceView::Done,
        signature: ByteBuf::from(evm_sign(&voter, &message)),
    };
    let (result,): (Result<(), String>,) = update(&pic, canister, "vote", Encode!(&arg).unwrap());
    result.unwrap();

    pic.advance_time(std::time::Duration::from_secs(VOTING_PERIOD + 90));
    let (record, signature) = wait_for_signature(&pic, canister, EVM, &r.task_id);
    assert_eq!(
        record.state,
        StateView::Decided {
            outcome: OutcomeView::Settle
        }
    );

    let digest = sign::evm_verdict_digest(SEPOLIA_CHAIN_ID, &r.task_id, 0).unwrap();
    assert_eq!(recover_eth(&digest, &signature).unwrap(), resolver);

    // The record — signature included — is certified and frozen: further
    // sweeps change nothing.
    let before = fetch_task(&pic, canister, EVM, &r.task_id);
    verify_certified_task(&pic, canister, EVM, &before);
    pic.advance_time(std::time::Duration::from_secs(120));
    pic.tick();
    pic.tick();
    assert_eq!(
        fetch_task(&pic, canister, EVM, &r.task_id).data,
        before.data
    );
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn solana_cancel_verdict_is_signed_ed25519() {
    let (pic, canister) = setup();
    let donor = sol_wallet(1);
    let streamer = sol_wallet(2);
    let resolver = resolver(&pic, canister, SOL);

    let spec = auth::spec_of(SOL).unwrap();
    let now = now_seconds(&pic);
    let deadline = now + DURATION + VOTING_PERIOD + logic::DEADLINE_MARGIN + 60;
    let task_id = auth::derive_task_id(
        spec,
        &donor.address,
        &streamer.address,
        1_000_000,
        deadline,
        &resolver,
        1,
    )
    .unwrap();
    let text_hash = Sha256::digest(b"text \x00 salt").to_vec();
    let message = auth::task_message(
        SOL,
        canister.as_slice(),
        &task_id,
        auth::ACTION_REGISTER,
        &auth::register_payload(&text_hash, DURATION),
    );
    let arg = RegisterArg {
        chain: SOL.to_string(),
        donor: ByteBuf::from(donor.address.clone()),
        streamer: ByteBuf::from(streamer.address.clone()),
        gross: 1_000_000,
        deadline,
        resolver: ByteBuf::from(resolver.clone()),
        nonce: 1,
        duration: DURATION,
        text_hash: ByteBuf::from(text_hash),
        signature: ByteBuf::from(sol_sign(&donor, &message)),
    };
    let (result,): (Result<ByteBuf, String>,) =
        update(&pic, canister, "register_task", Encode!(&arg).unwrap());
    result.unwrap();

    let message = auth::task_message(
        SOL,
        canister.as_slice(),
        &task_id,
        auth::ACTION_DECLINE,
        &[],
    );
    let arg = ActionArg {
        chain: SOL.to_string(),
        task_id: ByteBuf::from(task_id.clone()),
        signature: ByteBuf::from(sol_sign(&streamer, &message)),
    };
    let (result,): (Result<(), String>,) =
        update(&pic, canister, "decline", Encode!(&arg).unwrap());
    result.unwrap();

    let (record, signature) = wait_for_signature(&pic, canister, SOL, &task_id);
    assert_eq!(
        record.state,
        StateView::Decided {
            outcome: OutcomeView::Cancel
        }
    );
    assert_eq!(signature.len(), 64);

    // Verifies for exactly (this program's domain, this escrow, cancel).
    let program = bs58::decode(spec.factory).into_vec().unwrap();
    let key: [u8; 32] = resolver.clone().try_into().unwrap();
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key).unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&signature.clone().try_into().unwrap());
    let message = sign::sol_verdict_message(spec.domain, &program, &task_id, 1);
    key.verify_strict(&message, &sig).unwrap();
    // And for nothing else.
    let settle = sign::sol_verdict_message(spec.domain, &program, &task_id, 0);
    assert!(key.verify_strict(&settle, &sig).is_err());
    let foreign = sign::sol_verdict_message(spec.domain, &program, &[0x99; 32], 1);
    assert!(key.verify_strict(&foreign, &sig).is_err());
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn foreign_resolver_is_rejected_at_registration() {
    let (pic, canister) = setup();
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);

    let spec = auth::spec_of(EVM).unwrap();
    let now = now_seconds(&pic);
    let deadline = now + DURATION + VOTING_PERIOD + logic::DEADLINE_MARGIN + 60;
    let foreign = [0x77u8; 20];
    let task_id = auth::derive_task_id(
        spec,
        &donor.address,
        &streamer.address,
        1_000_000,
        deadline,
        &foreign,
        1,
    )
    .unwrap();
    let text_hash = [0x42u8; 32].to_vec();
    let message = auth::task_message(
        EVM,
        canister.as_slice(),
        &task_id,
        auth::ACTION_REGISTER,
        &auth::register_payload(&text_hash, DURATION),
    );
    let arg = RegisterArg {
        chain: EVM.to_string(),
        donor: ByteBuf::from(donor.address.clone()),
        streamer: ByteBuf::from(streamer.address.clone()),
        gross: 1_000_000,
        deadline,
        resolver: ByteBuf::from(foreign.to_vec()),
        nonce: 1,
        duration: DURATION,
        text_hash: ByteBuf::from(text_hash),
        signature: ByteBuf::from(evm_sign(&donor, &message)),
    };
    let (result,): (Result<ByteBuf, String>,) =
        update(&pic, canister, "register_task", Encode!(&arg).unwrap());
    assert_eq!(result.unwrap_err(), "resolver is not this canister's key");
}
