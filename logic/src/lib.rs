//! conditional-tasks-logic: the pure state machine of the game.
//!
//! Zero dependencies, no I/O, no clock — time arrives as an argument.
//! Addresses and keys are opaque bytes; this crate knows nothing about
//! chains, cryptography or the canister hosting it (docs/game-spec.md §3, §6).

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

pub mod task;
pub mod verdict;
pub mod vote;

pub use task::{
    Action, ChannelParams, DEADLINE_MARGIN, LOGIC_VERSION, MAX_DURATION, MIN_DURATION,
    RegisterError, Registration, State, StepError, Task, register, step,
};
pub use verdict::{Outcome, VerdictError, verdict};
pub use vote::{Choice, MIN_VOTE_WEIGHT, Vote, Voter};
