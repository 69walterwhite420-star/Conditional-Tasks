//! G3 integration: voting weighted by the book (docs/build-plan.md G3).
//! The book is a mock crown-index behind the init override; the real book
//! is exercised by the G4 e2e against the test networks.
//!
//! Driven by scripts/test-canister.sh, hence the #[ignore] markers.

mod common;

use candid::{Encode, Principal};
use common::*;
use conditional_tasks::api::VoteArg;
use conditional_tasks::{ChoiceView, OutcomeView, StateView, auth};
use conditional_tasks_logic as logic;
use pocket_ic::PocketIc;
use serde_bytes::ByteBuf;

/// Registers, accepts and reports done: a task sitting in VOTING.
fn task_in_voting(
    pic: &PocketIc,
    game: Principal,
    donor: &EvmWallet,
    streamer: &EvmWallet,
    nonce: u64,
) -> Vec<u8> {
    let r = register_evm(pic, game, donor, &streamer.address, nonce).unwrap();
    streamer_call(
        pic,
        game,
        "accept",
        auth::ACTION_ACCEPT,
        &r.task_id,
        streamer,
    )
    .unwrap();
    streamer_call(pic, game, "done", auth::ACTION_DONE, &r.task_id, streamer).unwrap();
    r.task_id
}

fn cast_vote(
    pic: &PocketIc,
    game: Principal,
    task_id: &[u8],
    voter: &EvmWallet,
    choice: ChoiceView,
) -> Result<(), String> {
    let choice_byte = match choice {
        ChoiceView::Done => auth::CHOICE_DONE,
        ChoiceView::NotDone => auth::CHOICE_NOT_DONE,
    };
    let message = auth::task_message(
        EVM,
        game.as_slice(),
        task_id,
        auth::ACTION_VOTE,
        &[choice_byte],
    );
    let arg = VoteArg {
        chain: EVM.to_string(),
        task_id: ByteBuf::from(task_id.to_vec()),
        voter: ByteBuf::from(voter.address.clone()),
        choice,
        signature: ByteBuf::from(evm_sign(voter, &message)),
    };
    let (result,): (Result<(), String>,) = update(pic, game, "vote", Encode!(&arg).unwrap());
    result
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn vote_weight_comes_from_the_book() {
    let (pic, game, index) = setup_with_index();
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);
    let rich = evm_wallet(3);
    let poor = evm_wallet(4);

    seed_reputation(
        &pic,
        index,
        EVM,
        &rich.address,
        &streamer.address,
        5_000_000,
    );
    let task_id = task_in_voting(&pic, game, &donor, &streamer, 1);

    cast_vote(&pic, game, &task_id, &rich, ChoiceView::Done).unwrap();
    let record = task_state(&fetch_task(&pic, game, EVM, &task_id));
    assert_eq!(record.votes.len(), 1);
    assert_eq!(record.votes[0].voter.as_slice(), rich.address.as_slice());
    assert_eq!(record.votes[0].weight, 5_000_000);

    // No reputation with this streamer — below the threshold.
    let error = cast_vote(&pic, game, &task_id, &poor, ChoiceView::Done).unwrap_err();
    assert_eq!(error, "vote weight below threshold");

    // One address, one vote, forever.
    let error = cast_vote(&pic, game, &task_id, &rich, ChoiceView::NotDone).unwrap_err();
    assert_eq!(error, "duplicate voter");
    let record = task_state(&fetch_task(&pic, game, EVM, &task_id));
    assert_eq!(record.votes.len(), 1);
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn majority_settles_and_the_tally_is_idempotent() {
    let (pic, game, index) = setup_with_index();
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);
    let a = evm_wallet(3);
    let b = evm_wallet(4);
    let c = evm_wallet(5);

    seed_reputation(&pic, index, EVM, &a.address, &streamer.address, 5_000_000);
    seed_reputation(&pic, index, EVM, &b.address, &streamer.address, 1_000_000);
    seed_reputation(&pic, index, EVM, &c.address, &streamer.address, 5_900_000);

    let task_id = task_in_voting(&pic, game, &donor, &streamer, 1);
    cast_vote(&pic, game, &task_id, &a, ChoiceView::Done).unwrap();
    cast_vote(&pic, game, &task_id, &b, ChoiceView::Done).unwrap();
    cast_vote(&pic, game, &task_id, &c, ChoiceView::NotDone).unwrap();

    pic.advance_time(std::time::Duration::from_secs(logic::VOTING_PERIOD + 90));
    pic.tick();
    pic.tick();

    // 6.0M done > 5.9M not done: strict majority settles.
    let task = fetch_task(&pic, game, EVM, &task_id);
    let record = task_state(&task);
    assert_eq!(
        record.state,
        StateView::Decided {
            outcome: OutcomeView::Settle
        }
    );
    assert_eq!(record.votes.len(), 3);
    verify_certified_task(&pic, game, EVM, &task);

    // Further ticks change nothing: the verdict is written once.
    let before = task.data.clone();
    pic.advance_time(std::time::Duration::from_secs(600));
    pic.tick();
    pic.tick();
    let after = fetch_task(&pic, game, EVM, &task_id);
    assert_eq!(before, after.data);

    // Late votes bounce off the decided task.
    let late = evm_wallet(6);
    seed_reputation(
        &pic,
        index,
        EVM,
        &late.address,
        &streamer.address,
        9_000_000,
    );
    let error = cast_vote(&pic, game, &task_id, &late, ChoiceView::NotDone).unwrap_err();
    assert_eq!(error, "invalid transition");
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn tie_cancels() {
    let (pic, game, index) = setup_with_index();
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);
    let a = evm_wallet(3);
    let b = evm_wallet(4);

    seed_reputation(&pic, index, EVM, &a.address, &streamer.address, 1_000_000);
    seed_reputation(&pic, index, EVM, &b.address, &streamer.address, 1_000_000);

    let task_id = task_in_voting(&pic, game, &donor, &streamer, 1);
    cast_vote(&pic, game, &task_id, &a, ChoiceView::Done).unwrap();
    cast_vote(&pic, game, &task_id, &b, ChoiceView::NotDone).unwrap();

    pic.advance_time(std::time::Duration::from_secs(logic::VOTING_PERIOD + 90));
    pic.tick();
    pic.tick();

    let record = task_state(&fetch_task(&pic, game, EVM, &task_id));
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
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);
    let voter = evm_wallet(3);
    seed_reputation(
        &pic,
        index,
        EVM,
        &voter.address,
        &streamer.address,
        5_000_000,
    );

    // CREATED: no voting yet.
    let r = register_evm(&pic, game, &donor, &streamer.address, 1).unwrap();
    let error = cast_vote(&pic, game, &r.task_id, &voter, ChoiceView::Done).unwrap_err();
    assert_eq!(error, "invalid transition");
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn reputation_is_chain_local() {
    let (pic, game, index) = setup_with_index();
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);
    let voter = evm_wallet(3);

    // Reputation on another chain gives no voice here: the weight lookup is
    // keyed by the task's chain, and the book is chain-local.
    seed_reputation(
        &pic,
        index,
        SOL,
        &voter.address,
        &streamer.address,
        9_000_000,
    );

    let task_id = task_in_voting(&pic, game, &donor, &streamer, 1);
    let error = cast_vote(&pic, game, &task_id, &voter, ChoiceView::Done).unwrap_err();
    assert_eq!(error, "vote weight below threshold");
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn min_reputation_gates_registration() {
    let (pic, game, index) = setup_with_index();
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);

    // The streamer demands reputation from donors.
    let message = auth::channel_message(
        EVM,
        game.as_slice(),
        &streamer.address,
        34,
        1_000_000,
        true,
        1,
    );
    let arg = conditional_tasks::api::ChannelArg {
        chain: EVM.to_string(),
        streamer: ByteBuf::from(streamer.address.clone()),
        min_gross: 34,
        min_reputation: 1_000_000,
        enabled: true,
        counter: 1,
        signature: ByteBuf::from(evm_sign(&streamer, &message)),
    };
    let (result,): (Result<(), String>,) =
        update(&pic, game, "set_channel_params", Encode!(&arg).unwrap());
    result.unwrap();

    // An unknown donor is below the bar.
    let error = register_evm(&pic, game, &donor, &streamer.address, 1).unwrap_err();
    assert_eq!(error, "donor reputation below the channel minimum");

    // A donor with book history passes.
    seed_reputation(
        &pic,
        index,
        EVM,
        &donor.address,
        &streamer.address,
        2_000_000,
    );
    register_evm(&pic, game, &donor, &streamer.address, 1).unwrap();
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn unconfigured_book_fails_votes_cleanly() {
    // A game with no crown-index anywhere: registration without a reputation
    // demand works (no book call), voting errors and records nothing.
    let (pic, game) = setup();
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);
    let voter = evm_wallet(3);

    let task_id = task_in_voting(&pic, game, &donor, &streamer, 1);
    let error = cast_vote(&pic, game, &task_id, &voter, ChoiceView::Done).unwrap_err();
    assert_eq!(error, "crown-index principal is not configured");
    let record = task_state(&fetch_task(&pic, game, EVM, &task_id));
    assert!(record.votes.is_empty());
}
