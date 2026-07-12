//! G2 integration: the canister inside PocketIC — registration, streamer
//! signatures, timer transitions, certified state (docs/build-plan.md G2).
//!
//! Needs the release wasm and a pocket-ic server binary; driven by
//! scripts/test-canister.sh, hence the #[ignore] markers.

mod common;

use candid::Encode;
use common::*;
use conditional_tasks::api::{ActionArg, ChannelArg, RegisterArg};
use conditional_tasks::{ChannelRecord, auth};
use conditional_tasks_logic as logic;
use serde_bytes::ByteBuf;

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn full_flow_with_certificates() {
    let (pic, canister) = setup();
    let donor = wallet(1);
    let streamer = wallet(2);

    let registered = register(&pic, canister, &donor, &streamer.address, 1).unwrap();
    let task = fetch_task(&pic, canister, &registered.task_id);
    let record = task_state(&task);
    assert_eq!(record.state, conditional_tasks::StateView::Created);
    assert_eq!(record.donor.as_slice(), donor.address.as_slice());
    verify_certified_task(&pic, canister, &task);

    streamer_call(
        &pic,
        canister,
        "accept",
        auth::ACTION_ACCEPT,
        &registered.task_id,
        &streamer,
    )
    .unwrap();
    let task = fetch_task(&pic, canister, &registered.task_id);
    assert_eq!(
        task_state(&task).state,
        conditional_tasks::StateView::Accepted
    );
    verify_certified_task(&pic, canister, &task);

    streamer_call(
        &pic,
        canister,
        "done",
        auth::ACTION_DONE,
        &registered.task_id,
        &streamer,
    )
    .unwrap();
    let task = fetch_task(&pic, canister, &registered.task_id);
    assert!(matches!(
        task_state(&task).state,
        conditional_tasks::StateView::Voting { .. }
    ));
    verify_certified_task(&pic, canister, &task);

    let (ids,): (Vec<ByteBuf>,) = query(
        &pic,
        canister,
        "list_tasks",
        Encode!(&CHAIN.to_string(), &ByteBuf::from(streamer.address.clone())).unwrap(),
    );
    assert_eq!(ids, vec![ByteBuf::from(registered.task_id)]);

    let (version,): (u32,) = query(&pic, canister, "get_logic_version", Encode!().unwrap());
    assert_eq!(version, logic::LOGIC_VERSION);
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn foreign_signatures_are_rejected() {
    let (pic, canister) = setup();
    let donor = wallet(1);
    let streamer = wallet(2);
    let stranger = wallet(3);

    let a = register(&pic, canister, &donor, &streamer.address, 1).unwrap();
    let b = register(&pic, canister, &donor, &streamer.address, 2).unwrap();

    // A stranger's key is not the streamer.
    let error = streamer_call(
        &pic,
        canister,
        "accept",
        auth::ACTION_ACCEPT,
        &a.task_id,
        &stranger,
    )
    .unwrap_err();
    assert_eq!(error, "bad signature");
    // The donor's key is not the streamer either.
    let error = streamer_call(
        &pic,
        canister,
        "accept",
        auth::ACTION_ACCEPT,
        &a.task_id,
        &donor,
    )
    .unwrap_err();
    assert_eq!(error, "bad signature");

    // A signature for task B does not open task A: sign B's message, send to A.
    let message = auth::task_message(
        CHAIN,
        canister.as_slice(),
        &b.task_id,
        auth::ACTION_ACCEPT,
        &[],
    );
    let arg = ActionArg {
        chain: CHAIN.to_string(),
        task_id: ByteBuf::from(a.task_id.clone()),
        signature: ByteBuf::from(sign(&streamer, &message)),
    };
    let (result,): (Result<(), String>,) = update(&pic, canister, "accept", Encode!(&arg).unwrap());
    assert_eq!(result.unwrap_err(), "bad signature");

    // A decline signature does not accept.
    let message = auth::task_message(
        CHAIN,
        canister.as_slice(),
        &a.task_id,
        auth::ACTION_DECLINE,
        &[],
    );
    let arg = ActionArg {
        chain: CHAIN.to_string(),
        task_id: ByteBuf::from(a.task_id.clone()),
        signature: ByteBuf::from(sign(&streamer, &message)),
    };
    let (result,): (Result<(), String>,) = update(&pic, canister, "accept", Encode!(&arg).unwrap());
    assert_eq!(result.unwrap_err(), "bad signature");

    // The state never moved.
    let task = fetch_task(&pic, canister, &a.task_id);
    assert_eq!(
        task_state(&task).state,
        conditional_tasks::StateView::Created
    );
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn registration_validation_and_duplicates() {
    let (pic, canister) = setup();
    let donor = wallet(1);
    let streamer = wallet(2);

    register(&pic, canister, &donor, &streamer.address, 1).unwrap();
    let error = register(&pic, canister, &donor, &streamer.address, 1).unwrap_err();
    assert_eq!(error, "task already registered");

    // Deadline below registration + duration + voting + margin.
    let spec = auth::spec_of(CHAIN).unwrap();
    let now = now_seconds(&pic);
    let tight = now + DURATION + VOTING_PERIOD + logic::DEADLINE_MARGIN - 10;
    let resolver = resolver(&pic, canister);
    let task_id = auth::derive_task_id(
        spec,
        &donor.address,
        &streamer.address,
        1_000_000,
        tight,
        &resolver,
        9,
    )
    .unwrap();
    let text_hash = [0x42u8; 32].to_vec();
    let message = auth::task_message(
        CHAIN,
        canister.as_slice(),
        &task_id,
        auth::ACTION_REGISTER,
        &auth::register_payload(&text_hash, DURATION),
    );
    let arg = RegisterArg {
        chain: CHAIN.to_string(),
        donor: ByteBuf::from(donor.address.clone()),
        streamer: ByteBuf::from(streamer.address.clone()),
        gross: 1_000_000,
        deadline: tight,
        resolver: ByteBuf::from(resolver.to_vec()),
        nonce: 9,
        duration: DURATION,
        text_hash: ByteBuf::from(text_hash),
        signature: ByteBuf::from(sign(&donor, &message)),
    };
    let (result,): (Result<ByteBuf, String>,) =
        update(&pic, canister, "register_task", Encode!(&arg).unwrap());
    assert_eq!(result.unwrap_err(), "deadline too tight");
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn tampered_registration_fields_break_the_signature() {
    let (pic, canister) = setup();
    let donor = wallet(1);
    let streamer = wallet(2);
    let spec = auth::spec_of(CHAIN).unwrap();
    let now = now_seconds(&pic);
    let gross = 1_000_000;
    let deadline = now + DURATION + VOTING_PERIOD + logic::DEADLINE_MARGIN + 60;
    let resolver = resolver(&pic, canister);
    let task_id = auth::derive_task_id(
        spec,
        &donor.address,
        &streamer.address,
        gross,
        deadline,
        &resolver,
        1,
    )
    .unwrap();
    let text_hash = [0x42u8; 32].to_vec();
    let message = auth::task_message(
        CHAIN,
        canister.as_slice(),
        &task_id,
        auth::ACTION_REGISTER,
        &auth::register_payload(&text_hash, DURATION),
    );
    // A relayer doubles the declared duration after the donor signed.
    let arg = RegisterArg {
        chain: CHAIN.to_string(),
        donor: ByteBuf::from(donor.address.clone()),
        streamer: ByteBuf::from(streamer.address.clone()),
        gross,
        deadline,
        resolver: ByteBuf::from(resolver.to_vec()),
        nonce: 1,
        duration: DURATION * 2,
        text_hash: ByteBuf::from(text_hash),
        signature: ByteBuf::from(sign(&donor, &message)),
    };
    let (result,): (Result<ByteBuf, String>,) =
        update(&pic, canister, "register_task", Encode!(&arg).unwrap());
    assert_eq!(result.unwrap_err(), "bad signature");
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn time_expires_tasks_with_and_without_the_timer() {
    let (pic, canister) = setup();
    let donor = wallet(1);
    let streamer = wallet(2);

    // Task A dies by the global timer alone.
    let a = register(&pic, canister, &donor, &streamer.address, 1).unwrap();
    // Task B dies inside the rejected accept (time first), timer or not.
    let b = register(&pic, canister, &donor, &streamer.address, 2).unwrap();

    pic.advance_time(std::time::Duration::from_secs(DURATION + 90));
    pic.tick();
    pic.tick();

    let task = fetch_task(&pic, canister, &a.task_id);
    assert_eq!(
        task_state(&task).state,
        conditional_tasks::StateView::Decided {
            outcome: conditional_tasks::OutcomeView::Cancel
        }
    );

    let error = streamer_call(
        &pic,
        canister,
        "accept",
        auth::ACTION_ACCEPT,
        &b.task_id,
        &streamer,
    )
    .unwrap_err();
    assert_eq!(error, "invalid transition");
    let task = fetch_task(&pic, canister, &b.task_id);
    assert_eq!(
        task_state(&task).state,
        conditional_tasks::StateView::Decided {
            outcome: conditional_tasks::OutcomeView::Cancel
        }
    );
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn empty_voting_cancels_by_timer() {
    let (pic, canister) = setup();
    let donor = wallet(1);
    let streamer = wallet(2);

    let r = register(&pic, canister, &donor, &streamer.address, 1).unwrap();
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

    pic.advance_time(std::time::Duration::from_secs(VOTING_PERIOD + 90));
    pic.tick();
    pic.tick();

    let task = fetch_task(&pic, canister, &r.task_id);
    assert_eq!(
        task_state(&task).state,
        conditional_tasks::StateView::Decided {
            outcome: conditional_tasks::OutcomeView::Cancel
        }
    );
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn decline_after_accept_frees_the_task() {
    let (pic, canister) = setup();
    let donor = wallet(1);
    let streamer = wallet(2);

    let r = register(&pic, canister, &donor, &streamer.address, 1).unwrap();
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
        "decline",
        auth::ACTION_DECLINE,
        &r.task_id,
        &streamer,
    )
    .unwrap();
    let task = fetch_task(&pic, canister, &r.task_id);
    assert_eq!(
        task_state(&task).state,
        conditional_tasks::StateView::Decided {
            outcome: conditional_tasks::OutcomeView::Cancel
        }
    );
    // Replay of the same decline changes nothing and reports the dead state.
    let error = streamer_call(
        &pic,
        canister,
        "decline",
        auth::ACTION_DECLINE,
        &r.task_id,
        &streamer,
    )
    .unwrap_err();
    assert_eq!(error, "invalid transition");
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn channel_params_counter_and_floor() {
    let (pic, canister) = setup();
    let donor = wallet(1);
    let streamer = wallet(2);

    let set = |min_gross: u64, min_reputation: u128, enabled: bool, counter: u64| {
        let message = auth::channel_message(
            CHAIN,
            canister.as_slice(),
            &streamer.address,
            min_gross,
            min_reputation,
            enabled,
            counter,
        );
        let arg = ChannelArg {
            chain: CHAIN.to_string(),
            streamer: ByteBuf::from(streamer.address.clone()),
            min_gross,
            min_reputation,
            enabled,
            counter,
            signature: ByteBuf::from(sign(&streamer, &message)),
        };
        let (result,): (Result<(), String>,) =
            update(&pic, canister, "set_channel_params", Encode!(&arg).unwrap());
        result
    };

    set(2_000_000, 0, true, 1).unwrap();
    let (channel,): (Option<ChannelRecord>,) = query(
        &pic,
        canister,
        "get_channel",
        Encode!(&CHAIN.to_string(), &ByteBuf::from(streamer.address.clone())).unwrap(),
    );
    let channel = channel.unwrap();
    assert_eq!((channel.min_gross, channel.counter), (2_000_000, 1));

    // Same counter replays are dead.
    assert_eq!(set(3_000_000, 0, true, 1).unwrap_err(), "stale counter");
    // The channel knob can never undercut the shape floor.
    assert_eq!(
        set(10, 0, true, 2).unwrap_err(),
        "channel minimum below the shape floor"
    );

    // gross below the channel minimum is rejected at registration.
    let error = register(&pic, canister, &donor, &streamer.address, 1).unwrap_err();
    assert_eq!(error, "gross below the channel minimum");

    // A disabled channel registers nothing.
    set(2_000_000, 0, false, 2).unwrap();
    let error = register(&pic, canister, &donor, &streamer.address, 2).unwrap_err();
    assert_eq!(error, "channel disabled");
}
