//! G3 integration: voting weighted by the book (docs/build-plan.md G3).
//! The book is a mock crown-index behind the init override; the real book
//! is exercised by the e2e against live devnet.
//!
//! Driven by scripts/test-canister.sh, hence the #[ignore] markers.

mod common;

use candid::{Encode, Principal};
use common::*;
use conditional_tasks::api::VoteArg;
use conditional_tasks::{ChoiceView, OutcomeView, StateView, auth};
use pocket_ic::PocketIc;
use serde_bytes::ByteBuf;

/// Registers, accepts and reports done: a task sitting in VOTING.
fn task_in_voting(
    pic: &PocketIc,
    game: Principal,
    donor: &Wallet,
    recipient: &Wallet,
    nonce: u64,
) -> Vec<u8> {
    let r = register(pic, game, donor, &recipient.address, nonce).unwrap();
    streamer_call(
        pic,
        game,
        "accept",
        auth::Action::Accept,
        &r.task_id,
        recipient,
    )
    .unwrap();
    streamer_call(pic, game, "ready", auth::Action::Ready, &r.task_id, recipient).unwrap();
    r.task_id
}

fn cast_vote(
    pic: &PocketIc,
    game: Principal,
    task_id: &[u8],
    voter: &Wallet,
    choice: ChoiceView,
) -> Result<(), String> {
    let signed_choice = match choice {
        ChoiceView::Done => auth::Choice::Done,
        ChoiceView::NotDone => auth::Choice::NotDone,
    };
    let message = auth::task_message(
        CHAIN,
        &game.to_text(),
        task_id,
        &auth::Action::Vote(signed_choice),
    );
    let arg = VoteArg {
        chain: CHAIN.to_string(),
        task_id: ByteBuf::from(task_id.to_vec()),
        voter: ByteBuf::from(voter.address.clone()),
        choice,
        signature: ByteBuf::from(sign(voter, message.as_bytes())),
    };
    let (result,): (Result<(), String>,) = update(pic, game, "vote", Encode!(&arg).unwrap());
    result
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn vote_weight_comes_from_the_book() {
    let (pic, game, index) = setup_with_index();
    let donor = wallet(1);
    let recipient = wallet(2);
    let rich = wallet(3);
    let poor = wallet(4);

    seed_reputation(&pic, index, &rich.address, &recipient.address, 5_000_000);
    let task_id = task_in_voting(&pic, game, &donor, &recipient, 1);

    cast_vote(&pic, game, &task_id, &rich, ChoiceView::Done).unwrap();
    let record = task_state(&fetch_task(&pic, game, &task_id));
    assert_eq!(record.votes.len(), 1);
    assert_eq!(record.votes[0].voter.as_slice(), rich.address.as_slice());
    assert_eq!(record.votes[0].weight, 5_000_000);

    // No reputation with this recipient — below the threshold.
    let error = cast_vote(&pic, game, &task_id, &poor, ChoiceView::Done).unwrap_err();
    assert_eq!(error, "vote weight below threshold");

    // One address, one vote, forever.
    let error = cast_vote(&pic, game, &task_id, &rich, ChoiceView::NotDone).unwrap_err();
    assert_eq!(error, "duplicate voter");
    let record = task_state(&fetch_task(&pic, game, &task_id));
    assert_eq!(record.votes.len(), 1);
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn majority_settles_and_the_tally_is_idempotent() {
    let (pic, game, index) = setup_with_index();
    let donor = wallet(1);
    let recipient = wallet(2);
    let a = wallet(3);
    let b = wallet(4);
    let c = wallet(5);

    seed_reputation(&pic, index, &a.address, &recipient.address, 5_000_000);
    seed_reputation(&pic, index, &b.address, &recipient.address, 1_000_000);
    seed_reputation(&pic, index, &c.address, &recipient.address, 5_900_000);

    let task_id = task_in_voting(&pic, game, &donor, &recipient, 1);
    cast_vote(&pic, game, &task_id, &a, ChoiceView::Done).unwrap();
    cast_vote(&pic, game, &task_id, &b, ChoiceView::Done).unwrap();
    cast_vote(&pic, game, &task_id, &c, ChoiceView::NotDone).unwrap();

    pic.advance_time(std::time::Duration::from_secs(VOTING_PERIOD + 90));
    pic.tick();
    pic.tick();

    // 6.0M done > 5.9M not done: strict majority settles.
    let task = fetch_task(&pic, game, &task_id);
    let record = task_state(&task);
    assert_eq!(
        record.state,
        StateView::Decided {
            outcome: OutcomeView::Settle
        }
    );
    assert_eq!(record.votes.len(), 3);
    verify_certified_task(&pic, game, &task);

    // The verdict is written once; the threshold signature appears once,
    // soon after (G4). From then on the record is frozen forever.
    let before = loop {
        pic.advance_time(std::time::Duration::from_secs(31));
        pic.tick();
        pic.tick();
        let task = fetch_task(&pic, game, &task_id);
        if task_state(&task).verdict_signature.is_some() {
            break task.data;
        }
    };
    pic.advance_time(std::time::Duration::from_secs(600));
    pic.tick();
    pic.tick();
    let after = fetch_task(&pic, game, &task_id);
    assert_eq!(before, after.data);

    // Late votes bounce off the decided task.
    let late = wallet(6);
    seed_reputation(&pic, index, &late.address, &recipient.address, 9_000_000);
    let error = cast_vote(&pic, game, &task_id, &late, ChoiceView::NotDone).unwrap_err();
    assert_eq!(error, "invalid transition");
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn tie_cancels() {
    let (pic, game, index) = setup_with_index();
    let donor = wallet(1);
    let recipient = wallet(2);
    let a = wallet(3);
    let b = wallet(4);

    seed_reputation(&pic, index, &a.address, &recipient.address, 1_000_000);
    seed_reputation(&pic, index, &b.address, &recipient.address, 1_000_000);

    let task_id = task_in_voting(&pic, game, &donor, &recipient, 1);
    cast_vote(&pic, game, &task_id, &a, ChoiceView::Done).unwrap();
    cast_vote(&pic, game, &task_id, &b, ChoiceView::NotDone).unwrap();

    pic.advance_time(std::time::Duration::from_secs(VOTING_PERIOD + 90));
    pic.tick();
    pic.tick();

    let record = task_state(&fetch_task(&pic, game, &task_id));
    assert_eq!(
        record.state,
        StateView::Decided {
            outcome: OutcomeView::Cancel
        }
    );
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn votes_outside_the_voting_window_are_rejected() {
    let (pic, game, index) = setup_with_index();
    let donor = wallet(1);
    let recipient = wallet(2);
    let voter = wallet(3);
    seed_reputation(&pic, index, &voter.address, &recipient.address, 5_000_000);

    // CREATED: no voting yet.
    let r = register(&pic, game, &donor, &recipient.address, 1).unwrap();
    let error = cast_vote(&pic, game, &r.task_id, &voter, ChoiceView::Done).unwrap_err();
    assert_eq!(error, "invalid transition");
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn min_reputation_gates_registration() {
    let (pic, game, index) = setup_with_index();
    let donor = wallet(1);
    let recipient = wallet(2);

    // The recipient demands reputation from donors.
    let message = auth::profile_message(
        CHAIN,
        &game.to_text(),
        &recipient.address,
        34,
        1_000_000,
        true,
        1,
    );
    let arg = conditional_tasks::api::ProfileArg {
        chain: CHAIN.to_string(),
        recipient: ByteBuf::from(recipient.address.clone()),
        min_gross: 34,
        min_reputation: 1_000_000,
        enabled: true,
        counter: 1,
        signature: ByteBuf::from(sign(&recipient, message.as_bytes())),
    };
    let (result,): (Result<(), String>,) =
        update(&pic, game, "set_profile", Encode!(&arg).unwrap());
    result.unwrap();

    // An unknown donor is below the bar.
    let error = register(&pic, game, &donor, &recipient.address, 1).unwrap_err();
    assert_eq!(error, "donor reputation below the profile minimum");

    // A donor with book history passes.
    seed_reputation(&pic, index, &donor.address, &recipient.address, 2_000_000);
    register(&pic, game, &donor, &recipient.address, 1).unwrap();
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn unconfigured_book_fails_votes_cleanly() {
    // A game with no crown-index anywhere: registration without a reputation
    // demand works (no book call), voting errors and records nothing.
    let (pic, game) = setup();
    let donor = wallet(1);
    let recipient = wallet(2);
    let voter = wallet(3);

    let task_id = task_in_voting(&pic, game, &donor, &recipient, 1);
    let error = cast_vote(&pic, game, &task_id, &voter, ChoiceView::Done).unwrap_err();
    assert_eq!(error, "crown-index principal is not configured");
    let record = task_state(&fetch_task(&pic, game, &task_id));
    assert!(record.votes.is_empty());
}
