//! G4 integration: the threshold verdict signature (docs/build-plan.md G4).
//! The byte format against the shape's contract is pinned locally here; the
//! real contract accepts it in the e2e (scripts/e2e-devnet.sh).
//!
//! Driven by scripts/test-canister.sh, hence the #[ignore] markers.

mod common;

use candid::Encode;
use common::*;
use conditional_tasks::api::{RegisterArg, VoteArg};
use conditional_tasks::{ChoiceView, OutcomeView, StateView, auth, sign as verdict};
use conditional_tasks_logic as logic;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

fn wait_for_signature(
    pic: &pocket_ic::PocketIc,
    canister: candid::Principal,
    task_id: &[u8],
) -> (conditional_tasks::TaskRecord, Vec<u8>) {
    for _ in 0..60 {
        pic.advance_time(std::time::Duration::from_secs(31));
        pic.tick();
        pic.tick();
        let record = task_state(&fetch_task(pic, canister, task_id));
        if let Some(signature) = &record.verdict_signature {
            let signature = signature.to_vec();
            return (record, signature);
        }
    }
    panic!("verdict signature never appeared");
}

fn verify_verdict(resolver: &[u8], task_id: &[u8], outcome: u8, signature: &[u8]) -> bool {
    let spec = auth::spec_of(CHAIN).unwrap();
    let program = bs58::decode(spec.factory).into_vec().unwrap();
    let message = verdict::verdict_message(spec.domain, &program, task_id, outcome);
    let key: [u8; 32] = resolver.to_vec().try_into().unwrap();
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&key) else {
        return false;
    };
    let Ok(sig) = <[u8; 64]>::try_from(signature.to_vec()) else {
        return false;
    };
    key.verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig))
        .is_ok()
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn cancel_verdict_is_signed_for_the_contract() {
    let (pic, canister) = setup();
    let donor = wallet(1);
    let recipient = wallet(2);
    let resolver = resolver(&pic, canister);
    assert_eq!(resolver.len(), 32);

    let r = register(&pic, canister, &donor, &recipient.address, 1).unwrap();
    recipient_call(
        &pic,
        canister,
        "decline",
        auth::Action::Decline,
        &r.task_id,
        &recipient,
    )
    .unwrap();

    let (record, signature) = wait_for_signature(&pic, canister, &r.task_id);
    assert_eq!(
        record.state,
        StateView::Decided {
            outcome: OutcomeView::Cancel
        }
    );
    assert_eq!(signature.len(), 64);

    // Verifies for exactly (this domain, this escrow, cancel)...
    assert!(verify_verdict(&resolver, &r.task_id, 1, &signature));
    // ...and nothing else: other outcome, other escrow.
    assert!(!verify_verdict(&resolver, &r.task_id, 0, &signature));
    assert!(!verify_verdict(&resolver, &[0x99; 32], 1, &signature));
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn settle_verdict_is_signed_after_votes() {
    let (pic, canister, index) = setup_with_index();
    let donor = wallet(1);
    let recipient = wallet(2);
    let voter = wallet(3);
    let resolver = resolver(&pic, canister);
    seed_reputation(&pic, index, &voter.address, &recipient.address, 5_000_000);

    let r = register(&pic, canister, &donor, &recipient.address, 1).unwrap();
    recipient_call(
        &pic,
        canister,
        "accept",
        auth::Action::Accept,
        &r.task_id,
        &recipient,
    )
    .unwrap();
    recipient_call(
        &pic,
        canister,
        "ready",
        auth::Action::Ready,
        &r.task_id,
        &recipient,
    )
    .unwrap();

    let message = auth::task_message(
        CHAIN,
        &canister.to_text(),
        &r.task_id,
        &auth::Action::Vote(auth::Choice::Done),
    );
    let arg = VoteArg {
        chain: CHAIN.to_string(),
        task_id: ByteBuf::from(r.task_id.clone()),
        voter: ByteBuf::from(voter.address.clone()),
        choice: ChoiceView::Done,
        signature: ByteBuf::from(sign(&voter, message.as_bytes())),
    };
    let (result,): (Result<(), String>,) = update(&pic, canister, "vote", Encode!(&arg).unwrap());
    result.unwrap();

    pic.advance_time(std::time::Duration::from_secs(VOTING_PERIOD + 90));
    let (record, signature) = wait_for_signature(&pic, canister, &r.task_id);
    assert_eq!(
        record.state,
        StateView::Decided {
            outcome: OutcomeView::Settle
        }
    );
    assert!(verify_verdict(&resolver, &r.task_id, 0, &signature));
    assert!(!verify_verdict(&resolver, &r.task_id, 1, &signature));

    // The record — signature included — is certified and frozen: further
    // sweeps change nothing.
    let before = fetch_task(&pic, canister, &r.task_id);
    verify_certified_task(&pic, canister, &before);
    pic.advance_time(std::time::Duration::from_secs(120));
    pic.tick();
    pic.tick();
    assert_eq!(fetch_task(&pic, canister, &r.task_id).data, before.data);
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn foreign_resolver_is_rejected_at_registration() {
    let (pic, canister) = setup();
    let donor = wallet(1);
    let recipient = wallet(2);

    let spec = auth::spec_of(CHAIN).unwrap();
    let now = now_seconds(&pic);
    let deadline = now + DURATION + VOTING_PERIOD + logic::DEADLINE_MARGIN + 60;
    let foreign = [0x77u8; 32];
    let task_id = auth::derive_task_id(
        spec,
        &donor.address,
        &recipient.address,
        1_000_000,
        deadline,
        &foreign,
        1,
    )
    .unwrap();
    let text_hash = Sha256::digest(b"text \x00 salt").to_vec();
    let message = auth::task_message(
        CHAIN,
        &canister.to_text(),
        &task_id,
        &auth::Action::Register {
            text_hash: &text_hash,
            duration: DURATION,
        },
    );
    let arg = RegisterArg {
        chain: CHAIN.to_string(),
        donor: ByteBuf::from(donor.address.clone()),
        recipient: ByteBuf::from(recipient.address.clone()),
        gross: 1_000_000,
        deadline,
        resolver: ByteBuf::from(foreign.to_vec()),
        nonce: 1,
        duration: DURATION,
        text_hash: ByteBuf::from(text_hash),
        signature: ByteBuf::from(sign(&donor, message.as_bytes())),
    };
    let (result,): (Result<ByteBuf, String>,) =
        update(&pic, canister, "register_task", Encode!(&arg).unwrap());
    assert_eq!(result.unwrap_err(), "resolver is not this canister's key");
}
