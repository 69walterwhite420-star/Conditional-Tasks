//! G2 integration: the canister inside PocketIC — registration, recipient
//! signatures, timer transitions, certified state (docs/build-plan.md G2).
//!
//! Needs the release wasm and a pocket-ic server binary; driven by
//! scripts/test-canister.sh, hence the #[ignore] markers.

mod common;

use candid::Encode;
use common::*;
use conditional_tasks::api::{ActionArg, CertifiedTask, ProfileArg, RegisterArg, VoteArg};
use conditional_tasks::{ChoiceView, ProfileRecord, auth};
use conditional_tasks_logic as logic;
use serde_bytes::ByteBuf;

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn many_simultaneous_deadlines_all_finalize() {
    // A burst of tasks all coming due in one window must not wedge the timer:
    // process_due caps its work per tick and drains the rest on the
    // near-immediate follow-up tick, so every one still finalizes.
    let (pic, canister) = setup();
    let donor = wallet(1);
    let recipient = wallet(2);

    let n: u64 = 120; // > MAX_DUE_PER_TICK (50): forces multi-tick draining.
    let ids: Vec<Vec<u8>> = (0..n)
        .map(|i| {
            register(&pic, canister, &donor, &recipient.address, i + 1)
                .unwrap()
                .task_id
        })
        .collect();

    pic.advance_time(std::time::Duration::from_secs(DURATION + 5));
    // Several ticks: the first caps out, each schedules a 1s follow-up. Advance
    // a second between ticks so the re-armed timer is due.
    for _ in 0..6 {
        pic.tick();
        pic.advance_time(std::time::Duration::from_secs(2));
    }

    for id in &ids {
        assert_eq!(
            task_state(&fetch_task(&pic, canister, id)).state,
            conditional_tasks::StateView::Decided {
                outcome: conditional_tasks::OutcomeView::Cancel
            },
            "every task in the burst finalized"
        );
    }
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn full_flow_with_certificates() {
    let (pic, canister) = setup();
    let donor = wallet(1);
    let recipient = wallet(2);

    let registered = register(&pic, canister, &donor, &recipient.address, 1).unwrap();
    let task = fetch_task(&pic, canister, &registered.task_id);
    let record = task_state(&task);
    assert_eq!(record.state, conditional_tasks::StateView::Created);
    assert_eq!(record.donor.as_slice(), donor.address.as_slice());
    verify_certified_task(&pic, canister, &task);

    recipient_call(
        &pic,
        canister,
        "accept",
        auth::Action::Accept,
        &registered.task_id,
        &recipient,
    )
    .unwrap();
    let task = fetch_task(&pic, canister, &registered.task_id);
    assert_eq!(
        task_state(&task).state,
        conditional_tasks::StateView::Accepted
    );
    verify_certified_task(&pic, canister, &task);

    recipient_call(
        &pic,
        canister,
        "ready",
        auth::Action::Ready,
        &registered.task_id,
        &recipient,
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
        Encode!(
            &CHAIN.to_string(),
            &ByteBuf::from(recipient.address.clone())
        )
        .unwrap(),
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
    let recipient = wallet(2);
    let stranger = wallet(3);

    let a = register(&pic, canister, &donor, &recipient.address, 1).unwrap();
    let b = register(&pic, canister, &donor, &recipient.address, 2).unwrap();

    // A stranger's key is not the recipient.
    let error = recipient_call(
        &pic,
        canister,
        "accept",
        auth::Action::Accept,
        &a.task_id,
        &stranger,
    )
    .unwrap_err();
    assert_eq!(error, "bad signature");
    // The donor's key is not the recipient either.
    let error = recipient_call(
        &pic,
        canister,
        "accept",
        auth::Action::Accept,
        &a.task_id,
        &donor,
    )
    .unwrap_err();
    assert_eq!(error, "bad signature");

    // A signature for task B does not open task A: sign B's message, send to A.
    let message = auth::task_message(
        CHAIN,
        &canister.to_text(),
        &b.task_id,
        &auth::Action::Accept,
    );
    let arg = ActionArg {
        chain: CHAIN.to_string(),
        task_id: ByteBuf::from(a.task_id.clone()),
        signature: ByteBuf::from(sign(&recipient, message.as_bytes())),
    };
    let (result,): (Result<(), String>,) = update(&pic, canister, "accept", Encode!(&arg).unwrap());
    assert_eq!(result.unwrap_err(), "bad signature");

    // A decline signature does not accept.
    let message = auth::task_message(
        CHAIN,
        &canister.to_text(),
        &a.task_id,
        &auth::Action::Decline,
    );
    let arg = ActionArg {
        chain: CHAIN.to_string(),
        task_id: ByteBuf::from(a.task_id.clone()),
        signature: ByteBuf::from(sign(&recipient, message.as_bytes())),
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
    let recipient = wallet(2);

    register(&pic, canister, &donor, &recipient.address, 1).unwrap();
    let error = register(&pic, canister, &donor, &recipient.address, 1).unwrap_err();
    assert_eq!(error, "task already registered");

    // Deadline below registration + duration + voting + margin.
    let spec = auth::spec_of(CHAIN).unwrap();
    let now = now_seconds(&pic);
    let tight = now + DURATION + VOTING_PERIOD + logic::DEADLINE_MARGIN - 10;
    let resolver = resolver(&pic, canister);
    let task_id = auth::derive_task_id(
        spec,
        &donor.address,
        &recipient.address,
        1_000_000,
        tight,
        &resolver,
        9,
    )
    .unwrap();
    let text_hash = [0x42u8; 32].to_vec();
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
        deadline: tight,
        resolver: ByteBuf::from(resolver.to_vec()),
        nonce: 9,
        duration: DURATION,
        text_hash: ByteBuf::from(text_hash),
        signature: ByteBuf::from(sign(&donor, message.as_bytes())),
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
    let recipient = wallet(2);
    let spec = auth::spec_of(CHAIN).unwrap();
    let now = now_seconds(&pic);
    let gross = 1_000_000;
    let deadline = now + DURATION + VOTING_PERIOD + logic::DEADLINE_MARGIN + 60;
    let resolver = resolver(&pic, canister);
    let task_id = auth::derive_task_id(
        spec,
        &donor.address,
        &recipient.address,
        gross,
        deadline,
        &resolver,
        1,
    )
    .unwrap();
    let text_hash = [0x42u8; 32].to_vec();
    let message = auth::task_message(
        CHAIN,
        &canister.to_text(),
        &task_id,
        &auth::Action::Register {
            text_hash: &text_hash,
            duration: DURATION,
        },
    );
    // A relayer doubles the declared duration after the donor signed.
    let arg = RegisterArg {
        chain: CHAIN.to_string(),
        donor: ByteBuf::from(donor.address.clone()),
        recipient: ByteBuf::from(recipient.address.clone()),
        gross,
        deadline,
        resolver: ByteBuf::from(resolver.to_vec()),
        nonce: 1,
        duration: DURATION * 2,
        text_hash: ByteBuf::from(text_hash),
        signature: ByteBuf::from(sign(&donor, message.as_bytes())),
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
    let recipient = wallet(2);

    // Task A dies by the global timer alone.
    let a = register(&pic, canister, &donor, &recipient.address, 1).unwrap();
    // Task B dies inside the rejected accept (time first), timer or not.
    let b = register(&pic, canister, &donor, &recipient.address, 2).unwrap();

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

    let error = recipient_call(
        &pic,
        canister,
        "accept",
        auth::Action::Accept,
        &b.task_id,
        &recipient,
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
    let recipient = wallet(2);

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
    let recipient = wallet(2);

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
        "decline",
        auth::Action::Decline,
        &r.task_id,
        &recipient,
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
    let error = recipient_call(
        &pic,
        canister,
        "decline",
        auth::Action::Decline,
        &r.task_id,
        &recipient,
    )
    .unwrap_err();
    assert_eq!(error, "invalid transition");
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn channel_params_counter_and_floor() {
    let (pic, canister) = setup();
    let donor = wallet(1);
    let recipient = wallet(2);

    let set = |min_gross: u64, min_reputation: u128, enabled: bool, counter: u64| {
        let message = auth::profile_message(
            CHAIN,
            &canister.to_text(),
            &recipient.address,
            min_gross,
            min_reputation,
            enabled,
            counter,
        );
        let arg = ProfileArg {
            chain: CHAIN.to_string(),
            recipient: ByteBuf::from(recipient.address.clone()),
            min_gross,
            min_reputation,
            enabled,
            counter,
            signature: ByteBuf::from(sign(&recipient, message.as_bytes())),
        };
        let (result,): (Result<(), String>,) =
            update(&pic, canister, "set_profile", Encode!(&arg).unwrap());
        result
    };

    set(2_000_000, 0, true, 1).unwrap();
    let (profile,): (Option<ProfileRecord>,) = query(
        &pic,
        canister,
        "get_profile",
        Encode!(
            &CHAIN.to_string(),
            &ByteBuf::from(recipient.address.clone())
        )
        .unwrap(),
    );
    let profile = profile.unwrap();
    assert_eq!((profile.min_gross, profile.counter), (2_000_000, 1));

    // Same counter replays are dead.
    assert_eq!(set(3_000_000, 0, true, 1).unwrap_err(), "stale counter");
    // The profile knob can never undercut the shape floor.
    assert_eq!(
        set(10, 0, true, 2).unwrap_err(),
        "profile minimum below the shape floor"
    );

    // gross below the profile minimum is rejected at registration.
    let error = register(&pic, canister, &donor, &recipient.address, 1).unwrap_err();
    assert_eq!(error, "gross below the profile minimum");

    // A disabled profile registers nothing.
    set(2_000_000, 0, false, 2).unwrap();
    let error = register(&pic, canister, &donor, &recipient.address, 2).unwrap_err();
    assert_eq!(error, "profile disabled");
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn operator_refund_cancels_and_attributes() {
    let (pic, canister) = setup();
    let donor = wallet(1);
    let recipient = wallet(2);

    let r = register(&pic, canister, &donor, &recipient.address, 1).unwrap();
    recipient_call(
        &pic,
        canister,
        "operator_refund",
        auth::Action::OperatorRefund,
        &r.task_id,
        &operator(),
    )
    .unwrap();
    let task = fetch_task(&pic, canister, &r.task_id);
    let record = task_state(&task);
    assert_eq!(
        record.state,
        conditional_tasks::StateView::Decided {
            outcome: conditional_tasks::OutcomeView::Cancel
        }
    );
    // Attributed forever: this cancel names the operator, not the recipient.
    assert!(record.operator_refunded_at.is_some());
    verify_certified_task(&pic, canister, &task);

    // The cancel signature arrives by the ordinary sweep — no special path.
    let mut signed = false;
    for _ in 0..40 {
        pic.advance_time(std::time::Duration::from_secs(1));
        pic.tick();
        if task_state(&fetch_task(&pic, canister, &r.task_id))
            .verdict_signature
            .is_some()
        {
            signed = true;
            break;
        }
    }
    assert!(signed, "verdict signature never swept");

    // Replay is a no-op on the dead task; the attribution stays.
    let error = recipient_call(
        &pic,
        canister,
        "operator_refund",
        auth::Action::OperatorRefund,
        &r.task_id,
        &operator(),
    )
    .unwrap_err();
    assert_eq!(error, "invalid transition");
    assert!(
        task_state(&fetch_task(&pic, canister, &r.task_id))
            .operator_refunded_at
            .is_some()
    );
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn operator_refund_works_mid_voting() {
    let (pic, canister) = setup();
    let donor = wallet(1);
    let recipient = wallet(2);

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

    // VOTING is closed to the recipient's decline but open to the operator.
    let error = recipient_call(
        &pic,
        canister,
        "decline",
        auth::Action::Decline,
        &r.task_id,
        &recipient,
    )
    .unwrap_err();
    assert_eq!(error, "invalid transition");
    recipient_call(
        &pic,
        canister,
        "operator_refund",
        auth::Action::OperatorRefund,
        &r.task_id,
        &operator(),
    )
    .unwrap();
    let record = task_state(&fetch_task(&pic, canister, &r.task_id));
    assert_eq!(
        record.state,
        conditional_tasks::StateView::Decided {
            outcome: conditional_tasks::OutcomeView::Cancel
        }
    );
    assert!(record.operator_refunded_at.is_some());
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn operator_refund_rejects_foreign_wallets() {
    let (pic, canister) = setup();
    let donor = wallet(1);
    let recipient = wallet(2);

    let r = register(&pic, canister, &donor, &recipient.address, 1).unwrap();
    // Neither the recipient nor a stranger holds the operator's pen.
    for signer in [&recipient, &wallet(9)] {
        let error = recipient_call(
            &pic,
            canister,
            "operator_refund",
            auth::Action::OperatorRefund,
            &r.task_id,
            signer,
        )
        .unwrap_err();
        assert_eq!(error, "bad signature");
    }
    // The rejected calls left the machine untouched.
    let record = task_state(&fetch_task(&pic, canister, &r.task_id));
    assert_eq!(record.state, conditional_tasks::StateView::Created);
    assert!(record.operator_refunded_at.is_none());
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn unknown_tasks_are_refused_and_leave_nothing() {
    // Every task-scoped update must bounce off a task_id nobody registered,
    // and must not conjure a record on the way out. A method that
    // synthesized one instead would let anyone mint tasks — and eventually
    // verdicts — for escrows the game never saw born.
    let (pic, canister) = setup();
    let recipient = wallet(2);
    let unknown = [0x5Au8; 32];

    for (method, action) in [
        ("accept", auth::Action::Accept),
        ("decline", auth::Action::Decline),
        ("ready", auth::Action::Ready),
    ] {
        let error =
            recipient_call(&pic, canister, method, action, &unknown, &recipient).unwrap_err();
        assert_eq!(error, "unknown task", "{method}");
    }
    // The operator is no exception: the task is looked up before the wallet.
    let error = recipient_call(
        &pic,
        canister,
        "operator_refund",
        auth::Action::OperatorRefund,
        &unknown,
        &operator(),
    )
    .unwrap_err();
    assert_eq!(error, "unknown task");

    // vote refuses at the same gate, before it ever pays the book for weight.
    let message = auth::task_message(
        CHAIN,
        &canister.to_text(),
        &unknown,
        &auth::Action::Vote(auth::Choice::Done),
    );
    let arg = VoteArg {
        chain: CHAIN.to_string(),
        task_id: ByteBuf::from(unknown.to_vec()),
        voter: ByteBuf::from(recipient.address.clone()),
        choice: ChoiceView::Done,
        signature: ByteBuf::from(sign(&recipient, message.as_bytes())),
    };
    let (result,): (Result<(), String>,) = update(&pic, canister, "vote", Encode!(&arg).unwrap());
    assert_eq!(result.unwrap_err(), "unknown task");

    // Nothing was written by any of them.
    let (task,): (Option<CertifiedTask>,) = query(
        &pic,
        canister,
        "get_task",
        Encode!(&CHAIN.to_string(), &ByteBuf::from(unknown.to_vec())).unwrap(),
    );
    assert!(task.is_none(), "a refused call created a task");
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn text_hash_is_stored_verbatim() {
    // The commitment is the whole of what the canister knows about the task
    // text, and the donor's signature covers exactly these bytes. Stored or
    // served altered, no one could prove the server's text is the text the
    // donor paid for — and the donor's signature would verify against
    // nothing.
    let (pic, canister) = setup();
    let donor = wallet(1);
    let recipient = wallet(2);

    let r = register(&pic, canister, &donor, &recipient.address, 1).unwrap();
    assert_eq!(r.text_hash.len(), 32);
    let record = task_state(&fetch_task(&pic, canister, &r.task_id));
    assert_eq!(record.text_hash.as_slice(), r.text_hash.as_slice());

    // It survives the rest of the task's life untouched.
    recipient_call(
        &pic,
        canister,
        "decline",
        auth::Action::Decline,
        &r.task_id,
        &recipient,
    )
    .unwrap();
    let record = task_state(&fetch_task(&pic, canister, &r.task_id));
    assert_eq!(record.text_hash.as_slice(), r.text_hash.as_slice());
}
