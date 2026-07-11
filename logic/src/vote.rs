//! Votes: an opaque voter, a binary choice, a book weight (docs/game-spec.md §6).

/// Minimal book value to vote, in minor units of reputation (the book is
/// denominated in USDC, 6 decimals).
pub const MIN_VOTE_WEIGHT: u128 = 100_000;

/// Opaque wallet bytes on the chain the escrow lives on. The canister
/// normalizes encodings; this crate only compares them.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Voter(pub Vec<u8>);

/// What the voter asserts about the task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    Done,
    NotDone,
}

/// One recorded vote. `weight` is book[(chain, voter, streamer)] at the
/// moment the vote was processed — there is no snapshot (game-spec §6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub voter: Voter,
    pub choice: Choice,
    pub weight: u128,
}
