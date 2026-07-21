//! The task state machine: one diagram, time first (docs/game-spec.md §3).
//!
//! Every `step` applies due time transitions before the action, so a late
//! canister timer can never let an action sneak past an expired clock.
//! `Tick` is the identity action: pure time, nothing else. A failed action
//! therefore still applies due time transitions — the caller relies on it.

use crate::verdict::{Outcome, verdict};
use crate::vote::{MIN_VOTE_WEIGHT, Vote};

/// Version of the game rules. Bumped only by a conscious change to the
/// machine or the verdict rule; the canister reports it via query.
pub const LOGIC_VERSION: u32 = 3;

/// All times are unix seconds; time is always an argument, never a syscall.
/// The voting period is a birth parameter of the task (profile-scoped in the
/// canister config); the rest are constants of the rules.
pub const MIN_DURATION: u64 = 60; // 1 minute
pub const MAX_DURATION: u64 = 2_592_000; // 30 days
pub const DEADLINE_MARGIN: u64 = 259_200; // 72 hours

/// The recipient's parameters, fixed into a task at registration
/// (docs/game-spec.md §7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileParams {
    pub min_gross: u64,
    pub min_reputation: u128,
    pub enabled: bool,
}

/// What the donor declares at registration. `donor_reputation` is the book
/// value supplied by the caller; this crate does not know where books live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    pub gross: u64,
    pub duration: u64,
    pub deadline: u64,
    pub donor_reputation: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Created,
    Accepted,
    Voting { started_at: u64 },
    Decided { outcome: Outcome },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Task {
    pub registered_at: u64,
    pub duration: u64,
    /// Fixed at registration from the canister's profile; a task carries its
    /// own clock rules forever.
    pub voting_period: u64,
    pub state: State,
    /// Non-empty only from VOTING on; published forever after the verdict.
    pub votes: Vec<Vote>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Recipient takes the task; the text becomes public.
    Accept,
    /// Recipient bows out — allowed from CREATED and ACCEPTED, costs nothing.
    Decline,
    /// Recipient claims completion; voting starts.
    Ready,
    /// A reputation holder votes.
    Vote(Vote),
    /// The platform operator forces the refund verdict — the censorship
    /// move. Its only power is returning the donor's own money: allowed
    /// from any state the clock has not yet decided, never out of Decided.
    OperatorRefund,
    /// Pure time: due transitions only.
    Tick,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterError {
    ProfileDisabled,
    GrossBelowFloor,
    GrossBelowMinimum,
    ReputationBelowMinimum,
    DurationOutOfRange,
    DeadlineTooTight,
    TimeOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepError {
    /// The transition is not drawn on the diagram (or the clock closed it).
    InvalidTransition,
    WeightBelowThreshold,
    DuplicateVoter,
    Overflow,
}

/// Validates a registration and births the task in CREATED. On `Err` no
/// task exists. `floor` is the game's own acceptance floor (config
/// `min_gross`); the profile's own `min_gross` may only be stricter.
pub fn register(
    now: u64,
    profile: &ProfileParams,
    floor: u64,
    voting_period: u64,
    registration: &Registration,
) -> Result<Task, RegisterError> {
    if !profile.enabled {
        return Err(RegisterError::ProfileDisabled);
    }
    if registration.gross < floor {
        return Err(RegisterError::GrossBelowFloor);
    }
    if registration.gross < profile.min_gross {
        return Err(RegisterError::GrossBelowMinimum);
    }
    if registration.donor_reputation < profile.min_reputation {
        return Err(RegisterError::ReputationBelowMinimum);
    }
    if registration.duration < MIN_DURATION || registration.duration > MAX_DURATION {
        return Err(RegisterError::DurationOutOfRange);
    }
    let earliest_deadline = now
        .checked_add(registration.duration)
        .and_then(|t| t.checked_add(voting_period))
        .and_then(|t| t.checked_add(DEADLINE_MARGIN))
        .ok_or(RegisterError::TimeOverflow)?;
    if registration.deadline < earliest_deadline {
        return Err(RegisterError::DeadlineTooTight);
    }
    Ok(Task {
        registered_at: now,
        duration: registration.duration,
        voting_period,
        state: State::Created,
        votes: Vec::new(),
    })
}

/// Applies one action at time `now`. Due time transitions happen first and
/// persist even when the action itself fails; `Decided` is absorbing.
pub fn step(task: &mut Task, action: Action, now: u64) -> Result<(), StepError> {
    advance(task, now)?;
    let next = match (task.state.clone(), action) {
        (State::Created, Action::Accept) => Some(State::Accepted),
        (State::Created, Action::Decline) | (State::Accepted, Action::Decline) => {
            Some(State::Decided {
                outcome: Outcome::Cancel,
            })
        }
        (State::Accepted, Action::Ready) => Some(State::Voting { started_at: now }),
        (State::Created, Action::OperatorRefund)
        | (State::Accepted, Action::OperatorRefund)
        | (State::Voting { .. }, Action::OperatorRefund) => Some(State::Decided {
            outcome: Outcome::Cancel,
        }),
        (State::Voting { .. }, Action::Vote(vote)) => {
            if vote.weight < MIN_VOTE_WEIGHT {
                return Err(StepError::WeightBelowThreshold);
            }
            if task.votes.iter().any(|v| v.voter == vote.voter) {
                return Err(StepError::DuplicateVoter);
            }
            task.votes.push(vote);
            None
        }
        (State::Created, Action::Tick)
        | (State::Accepted, Action::Tick)
        | (State::Voting { .. }, Action::Tick)
        | (State::Decided { .. }, Action::Tick) => None,
        // Everything not drawn on the diagram (docs/game-spec.md §3).
        (State::Created, Action::Ready)
        | (State::Created, Action::Vote(_))
        | (State::Accepted, Action::Accept)
        | (State::Accepted, Action::Vote(_))
        | (State::Voting { .. }, Action::Accept)
        | (State::Voting { .. }, Action::Decline)
        | (State::Voting { .. }, Action::Ready)
        | (State::Decided { .. }, Action::Accept)
        | (State::Decided { .. }, Action::Decline)
        | (State::Decided { .. }, Action::Ready)
        | (State::Decided { .. }, Action::Vote(_))
        | (State::Decided { .. }, Action::OperatorRefund) => {
            return Err(StepError::InvalidTransition);
        }
    };
    if let Some(state) = next {
        task.state = state;
    }
    Ok(())
}

/// Due time transitions: expiry cancels an unfinished task, the end of the
/// voting period tallies the verdict. `Decided` never changes again.
fn advance(task: &mut Task, now: u64) -> Result<(), StepError> {
    match task.state.clone() {
        State::Created | State::Accepted => {
            let expiry = task
                .registered_at
                .checked_add(task.duration)
                .ok_or(StepError::Overflow)?;
            if now >= expiry {
                task.state = State::Decided {
                    outcome: Outcome::Cancel,
                };
            }
            Ok(())
        }
        State::Voting { started_at } => {
            let end = started_at
                .checked_add(task.voting_period)
                .ok_or(StepError::Overflow)?;
            if now >= end {
                // Infallible: a voting task always finalizes at period end —
                // even an overflowing tally decides (Cancel), never strands
                // (verdict.rs).
                task.state = State::Decided {
                    outcome: verdict(&task.votes),
                };
            }
            Ok(())
        }
        State::Decided { .. } => Ok(()),
    }
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
    use proptest::prelude::*;

    use super::*;
    use crate::vote::{Choice, Voter};

    const T0: u64 = 1_700_000_000;
    const DURATION: u64 = 86_400; // 1 day
    const VOTING_PERIOD: u64 = 3_600;

    fn profile() -> ProfileParams {
        ProfileParams {
            min_gross: 34,
            min_reputation: 0,
            enabled: true,
        }
    }

    fn registration() -> Registration {
        Registration {
            gross: 1_000_000,
            duration: DURATION,
            deadline: T0 + DURATION + VOTING_PERIOD + DEADLINE_MARGIN,
            donor_reputation: 0,
        }
    }

    fn fresh() -> Task {
        register(T0, &profile(), 34, VOTING_PERIOD, &registration()).unwrap()
    }

    fn vote(voter: u8, choice: Choice, weight: u128) -> Vote {
        Vote {
            voter: Voter(vec![voter]),
            choice,
            weight,
        }
    }

    fn valid_vote(voter: u8, choice: Choice) -> Vote {
        vote(voter, choice, MIN_VOTE_WEIGHT)
    }

    /// A scripted run: monotonically growing time, errors ignored — exactly
    /// how a canister replays ingress against the machine.
    fn run(task: &mut Task, script: &[(Action, u64)]) {
        let mut now = task.registered_at;
        for (action, dt) in script {
            now += dt;
            let _ = step(task, action.clone(), now);
        }
    }

    fn action() -> impl Strategy<Value = Action> {
        prop_oneof![
            Just(Action::Accept),
            Just(Action::Decline),
            Just(Action::Ready),
            Just(Action::OperatorRefund),
            Just(Action::Tick),
            (0u8..4, any::<bool>(), 0u128..=u128::from(u64::MAX)).prop_map(
                |(voter, done, weight)| {
                    let choice = if done { Choice::Done } else { Choice::NotDone };
                    Action::Vote(vote(voter, choice, weight))
                }
            ),
        ]
    }

    /// Steps dense enough to hit every phase: offsets up to 2 hours around a
    /// 1-day duration and a 1-hour voting period.
    fn script() -> impl Strategy<Value = Vec<(Action, u64)>> {
        proptest::collection::vec((action(), 0u64..7_200), 0..40)
    }

    // ---- the diagram, transition by transition -------------------------

    #[test]
    fn created_accept_moves_to_accepted() {
        let mut task = fresh();
        step(&mut task, Action::Accept, T0 + 1).unwrap();
        assert_eq!(task.state, State::Accepted);
    }

    #[test]
    fn decline_cancels_from_created_and_accepted() {
        let mut task = fresh();
        step(&mut task, Action::Decline, T0 + 1).unwrap();
        assert_eq!(
            task.state,
            State::Decided {
                outcome: Outcome::Cancel
            }
        );

        let mut task = fresh();
        step(&mut task, Action::Accept, T0 + 1).unwrap();
        step(&mut task, Action::Decline, T0 + 2).unwrap();
        assert_eq!(
            task.state,
            State::Decided {
                outcome: Outcome::Cancel
            }
        );
    }

    #[test]
    fn ready_opens_voting() {
        let mut task = fresh();
        step(&mut task, Action::Accept, T0 + 1).unwrap();
        step(&mut task, Action::Ready, T0 + 2).unwrap();
        assert_eq!(task.state, State::Voting { started_at: T0 + 2 });
    }

    #[test]
    fn exactly_the_allowed_actions_succeed_per_state() {
        let now = T0 + 1;
        // (state builder, allowed actions)
        let created = fresh;
        let accepted = || {
            let mut t = fresh();
            step(&mut t, Action::Accept, now).unwrap();
            t
        };
        let voting = || {
            let mut t = accepted();
            step(&mut t, Action::Ready, now).unwrap();
            t
        };
        let decided = || {
            let mut t = fresh();
            step(&mut t, Action::Decline, now).unwrap();
            t
        };
        let all = || {
            vec![
                Action::Accept,
                Action::Decline,
                Action::Ready,
                Action::Vote(valid_vote(0, Choice::Done)),
                Action::OperatorRefund,
                Action::Tick,
            ]
        };
        let cases: Vec<(Task, Vec<Action>)> = vec![
            (
                created(),
                vec![
                    Action::Accept,
                    Action::Decline,
                    Action::OperatorRefund,
                    Action::Tick,
                ],
            ),
            (
                accepted(),
                vec![
                    Action::Decline,
                    Action::Ready,
                    Action::OperatorRefund,
                    Action::Tick,
                ],
            ),
            (
                voting(),
                vec![
                    Action::Vote(valid_vote(0, Choice::Done)),
                    Action::OperatorRefund,
                    Action::Tick,
                ],
            ),
            (decided(), vec![Action::Tick]),
        ];
        for (task, allowed) in cases {
            for action in all() {
                let mut probe = task.clone();
                let result = step(&mut probe, action.clone(), now);
                assert_eq!(
                    result.is_ok(),
                    allowed.contains(&action),
                    "state {:?}, action {:?}",
                    task.state,
                    action
                );
            }
        }
    }

    // ---- time ----------------------------------------------------------

    #[test]
    fn expiry_cancels_created_and_accepted() {
        let expiry = T0 + DURATION;

        let mut task = fresh();
        assert_eq!(
            step(&mut task, Action::Accept, expiry),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(
            task.state,
            State::Decided {
                outcome: Outcome::Cancel
            }
        );

        let mut task = fresh();
        step(&mut task, Action::Accept, expiry - 1).unwrap();
        assert_eq!(
            step(&mut task, Action::Ready, expiry),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(
            task.state,
            State::Decided {
                outcome: Outcome::Cancel
            }
        );
    }

    #[test]
    fn accept_works_until_the_last_second() {
        let mut task = fresh();
        step(&mut task, Action::Accept, T0 + DURATION - 1).unwrap();
        assert_eq!(task.state, State::Accepted);
    }

    #[test]
    fn voting_end_tallies_and_rejects_late_votes() {
        let mut task = fresh();
        step(&mut task, Action::Accept, T0 + 1).unwrap();
        step(&mut task, Action::Ready, T0 + 2).unwrap();
        step(&mut task, Action::Vote(valid_vote(0, Choice::Done)), T0 + 3).unwrap();
        let end = T0 + 2 + VOTING_PERIOD;
        assert_eq!(
            step(&mut task, Action::Vote(valid_vote(1, Choice::NotDone)), end),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(
            task.state,
            State::Decided {
                outcome: Outcome::Settle
            }
        );
        assert_eq!(task.votes.len(), 1);
    }

    #[test]
    fn empty_voting_cancels_on_tick() {
        let mut task = fresh();
        step(&mut task, Action::Accept, T0 + 1).unwrap();
        step(&mut task, Action::Ready, T0 + 2).unwrap();
        step(&mut task, Action::Tick, T0 + 2 + VOTING_PERIOD).unwrap();
        assert_eq!(
            task.state,
            State::Decided {
                outcome: Outcome::Cancel
            }
        );
    }

    /// The clock arithmetic is checked, never wrapping. A due moment that
    /// does not fit u64 must be reported and leave the task exactly as it
    /// was: a wrapping add lands the due moment in the past, which decides
    /// a live task on the spot — cancelling a CREATED one, or tallying a
    /// voting window that never ended.
    #[test]
    fn overflowing_due_times_are_reported_not_wrapped() {
        let mut task = fresh();
        task.registered_at = u64::MAX;
        task.duration = 1;
        let before = task.clone();
        assert_eq!(step(&mut task, Action::Accept, 0), Err(StepError::Overflow));
        assert_eq!(task, before);

        let mut task = fresh();
        task.state = State::Voting {
            started_at: u64::MAX,
        };
        task.voting_period = 1;
        let before = task.clone();
        assert_eq!(step(&mut task, Action::Tick, 0), Err(StepError::Overflow));
        assert_eq!(task, before);
    }

    // ---- operator -------------------------------------------------------

    #[test]
    fn operator_refund_cancels_every_live_state() {
        // CREATED, ACCEPTED and VOTING all collapse to Cancel; recorded
        // votes stay published.
        let mut task = fresh();
        step(&mut task, Action::OperatorRefund, T0 + 1).unwrap();
        assert_eq!(
            task.state,
            State::Decided {
                outcome: Outcome::Cancel
            }
        );

        let mut task = fresh();
        step(&mut task, Action::Accept, T0 + 1).unwrap();
        step(&mut task, Action::OperatorRefund, T0 + 2).unwrap();
        assert_eq!(
            task.state,
            State::Decided {
                outcome: Outcome::Cancel
            }
        );

        let mut task = fresh();
        step(&mut task, Action::Accept, T0 + 1).unwrap();
        step(&mut task, Action::Ready, T0 + 2).unwrap();
        step(&mut task, Action::Vote(valid_vote(0, Choice::Done)), T0 + 3).unwrap();
        step(&mut task, Action::OperatorRefund, T0 + 4).unwrap();
        assert_eq!(
            task.state,
            State::Decided {
                outcome: Outcome::Cancel
            }
        );
        assert_eq!(task.votes.len(), 1);
    }

    #[test]
    fn operator_refund_never_beats_the_clock() {
        // A voting window that already ended tallies first; the operator
        // cannot flip the tallied settle.
        let mut task = fresh();
        step(&mut task, Action::Accept, T0 + 1).unwrap();
        step(&mut task, Action::Ready, T0 + 2).unwrap();
        step(&mut task, Action::Vote(valid_vote(0, Choice::Done)), T0 + 3).unwrap();
        let end = T0 + 2 + VOTING_PERIOD;
        assert_eq!(
            step(&mut task, Action::OperatorRefund, end),
            Err(StepError::InvalidTransition)
        );
        assert_eq!(
            task.state,
            State::Decided {
                outcome: Outcome::Settle
            }
        );
    }

    // ---- votes ----------------------------------------------------------

    #[test]
    fn vote_below_threshold_and_duplicates_are_rejected() {
        let mut task = fresh();
        step(&mut task, Action::Accept, T0 + 1).unwrap();
        step(&mut task, Action::Ready, T0 + 2).unwrap();

        assert_eq!(
            step(
                &mut task,
                Action::Vote(vote(0, Choice::Done, MIN_VOTE_WEIGHT - 1)),
                T0 + 3
            ),
            Err(StepError::WeightBelowThreshold)
        );
        assert!(task.votes.is_empty());

        step(&mut task, Action::Vote(valid_vote(0, Choice::Done)), T0 + 4).unwrap();
        assert_eq!(
            step(
                &mut task,
                Action::Vote(valid_vote(0, Choice::NotDone)),
                T0 + 5
            ),
            Err(StepError::DuplicateVoter)
        );
        assert_eq!(task.votes.len(), 1);
    }

    // ---- registration ----------------------------------------------------

    #[test]
    fn registration_rejections_and_boundaries() {
        let params = profile();
        let reg = registration();

        let disabled = ProfileParams {
            enabled: false,
            ..params.clone()
        };
        assert_eq!(
            register(T0, &disabled, 34, VOTING_PERIOD, &reg),
            Err(RegisterError::ProfileDisabled)
        );

        let below_floor = Registration {
            gross: 33,
            ..reg.clone()
        };
        assert_eq!(
            register(T0, &params, 34, VOTING_PERIOD, &below_floor),
            Err(RegisterError::GrossBelowFloor)
        );

        let strict = ProfileParams {
            min_gross: 1_000_000,
            ..params.clone()
        };
        let below_min = Registration {
            gross: 999_999,
            ..reg.clone()
        };
        assert_eq!(
            register(T0, &strict, 34, VOTING_PERIOD, &below_min),
            Err(RegisterError::GrossBelowMinimum)
        );

        let reputable = ProfileParams {
            min_reputation: 1,
            ..params.clone()
        };
        assert_eq!(
            register(T0, &reputable, 34, VOTING_PERIOD, &reg),
            Err(RegisterError::ReputationBelowMinimum)
        );

        let short = Registration {
            duration: MIN_DURATION - 1,
            ..reg.clone()
        };
        assert_eq!(
            register(T0, &params, 34, VOTING_PERIOD, &short),
            Err(RegisterError::DurationOutOfRange)
        );
        let long = Registration {
            duration: MAX_DURATION + 1,
            ..reg.clone()
        };
        assert_eq!(
            register(T0, &params, 34, VOTING_PERIOD, &long),
            Err(RegisterError::DurationOutOfRange)
        );

        // Deadline boundary: the exact minimum passes, one second less fails.
        let exact = Registration {
            deadline: T0 + DURATION + VOTING_PERIOD + DEADLINE_MARGIN,
            ..reg.clone()
        };
        assert!(register(T0, &params, 34, VOTING_PERIOD, &exact).is_ok());
        let tight = Registration {
            deadline: T0 + DURATION + VOTING_PERIOD + DEADLINE_MARGIN - 1,
            ..reg
        };
        assert_eq!(
            register(T0, &params, 34, VOTING_PERIOD, &tight),
            Err(RegisterError::DeadlineTooTight)
        );
    }

    /// The earliest legal deadline is computed with checked arithmetic. If
    /// it wrapped, a clock this far out would produce a tiny earliest
    /// deadline that any declared deadline clears — birthing a task whose
    /// escrow expires before the voting window it promises.
    #[test]
    fn registration_refuses_a_clock_that_does_not_fit() {
        assert_eq!(
            register(u64::MAX, &profile(), 34, VOTING_PERIOD, &registration()),
            Err(RegisterError::TimeOverflow)
        );
    }

    // ---- properties ------------------------------------------------------

    proptest! {
        // Unreachability: whatever the reachable state, a failed action is
        // exactly a Tick — time may have moved the machine, the action never.
        #[test]
        fn failed_action_is_a_tick(prefix in script(), action in action(), dt in 0u64..7_200) {
            let mut task = fresh();
            run(&mut task, &prefix);
            let now = task.registered_at
                + prefix.iter().map(|(_, dt)| dt).sum::<u64>()
                + dt;
            let mut ticked = task.clone();
            step(&mut ticked, Action::Tick, now).unwrap();
            if step(&mut task, action, now).is_err() {
                prop_assert_eq!(task, ticked);
            }
        }

        // Verdict uniqueness: Decided is absorbing — no further script
        // changes the outcome or the recorded votes.
        #[test]
        fn decided_is_absorbing(prefix in script(), suffix in script()) {
            let mut task = fresh();
            run(&mut task, &prefix);
            let elapsed: u64 = prefix.iter().map(|(_, dt)| dt).sum();
            // Force a decision if not reached: expiry or voting end.
            let far = task.registered_at + elapsed + DURATION + VOTING_PERIOD;
            step(&mut task, Action::Tick, far).unwrap();
            let decided = matches!(task.state, State::Decided { .. });
            prop_assert!(decided);

            let snapshot = task.clone();
            let mut now = far;
            for (action, dt) in suffix {
                now += dt;
                let _ = step(&mut task, action, now);
            }
            prop_assert_eq!(task, snapshot);
        }

        // Voting can only have started before expiry, and voters are unique.
        #[test]
        fn invariants_hold_on_every_reachable_state(prefix in script()) {
            let mut task = fresh();
            run(&mut task, &prefix);
            if let State::Voting { started_at } = task.state {
                prop_assert!(started_at < task.registered_at + task.duration);
            }
            let mut voters: Vec<_> = task.votes.iter().map(|v| v.voter.clone()).collect();
            voters.sort();
            voters.dedup();
            prop_assert_eq!(voters.len(), task.votes.len());
            for v in &task.votes {
                prop_assert!(v.weight >= MIN_VOTE_WEIGHT);
            }
        }

        // Determinism: the same script replays into the bitwise same task.
        #[test]
        fn replay_is_deterministic(s in script()) {
            let mut a = fresh();
            let mut b = fresh();
            run(&mut a, &s);
            run(&mut b, &s);
            prop_assert_eq!(a, b);
        }
    }

    // The rules are versioned; changing semantics without bumping is a bug.
    #[test]
    fn logic_version_is_pinned() {
        assert_eq!(LOGIC_VERSION, 3);
    }
}
