//! The verdict rule: strict majority by weight, silence cancels
//! (docs/game-spec.md §6).

use crate::vote::{Choice, Vote};

/// The two paths fixed at the escrow's birth. The canister maps them to the
/// shape's outcome indices; this crate knows no contracts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Settle,
    Cancel,
}

/// The only failure the rule can produce: the u128 total would overflow.
/// An error is a value here, never a panic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerdictError {
    Overflow,
}

/// `Settle` iff Σweight(done) strictly exceeds Σweight(not done).
/// Ties and an empty vote cancel: silence does not move other people's money.
pub fn verdict(votes: &[Vote]) -> Result<Outcome, VerdictError> {
    let mut done: u128 = 0;
    let mut not_done: u128 = 0;
    for vote in votes {
        let total = match vote.choice {
            Choice::Done => &mut done,
            Choice::NotDone => &mut not_done,
        };
        *total = total
            .checked_add(vote.weight)
            .ok_or(VerdictError::Overflow)?;
    }
    Ok(if done > not_done {
        Outcome::Settle
    } else {
        Outcome::Cancel
    })
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
    use crate::vote::Voter;

    fn vote(voter: u8, choice: Choice, weight: u128) -> Vote {
        Vote {
            voter: Voter(vec![voter]),
            choice,
            weight,
        }
    }

    /// Unique voters by construction; weights bounded so honest sums fit.
    fn votes() -> impl Strategy<Value = Vec<Vote>> {
        proptest::collection::vec((any::<bool>(), 0u128..=u128::from(u64::MAX)), 0..32).prop_map(
            |entries| {
                entries
                    .into_iter()
                    .enumerate()
                    .map(|(i, (done, weight))| {
                        let choice = if done { Choice::Done } else { Choice::NotDone };
                        vote(i as u8, choice, weight)
                    })
                    .collect()
            },
        )
    }

    proptest! {
        // Majority: the verdict is exactly the recount of the two sums.
        #[test]
        fn verdict_equals_recount(vs in votes()) {
            let done: u128 = vs
                .iter()
                .filter(|v| v.choice == Choice::Done)
                .map(|v| v.weight)
                .sum();
            let not_done: u128 = vs
                .iter()
                .filter(|v| v.choice == Choice::NotDone)
                .map(|v| v.weight)
                .sum();
            let expected = if done > not_done {
                Outcome::Settle
            } else {
                Outcome::Cancel
            };
            prop_assert_eq!(verdict(&vs).unwrap(), expected);
        }

        // Determinism: same votes, same verdict.
        #[test]
        fn verdict_is_deterministic(vs in votes()) {
            prop_assert_eq!(verdict(&vs), verdict(&vs));
        }
    }

    #[test]
    fn empty_vote_cancels() {
        assert_eq!(verdict(&[]).unwrap(), Outcome::Cancel);
    }

    #[test]
    fn tie_cancels() {
        let vs = [
            vote(0, Choice::Done, 500_000),
            vote(1, Choice::NotDone, 500_000),
        ];
        assert_eq!(verdict(&vs).unwrap(), Outcome::Cancel);
    }

    #[test]
    fn strict_majority_settles() {
        let vs = [
            vote(0, Choice::Done, 500_001),
            vote(1, Choice::NotDone, 500_000),
        ];
        assert_eq!(verdict(&vs).unwrap(), Outcome::Settle);
    }

    #[test]
    fn overflow_is_an_error() {
        let vs = [vote(0, Choice::Done, u128::MAX), vote(1, Choice::Done, 1)];
        assert_eq!(verdict(&vs), Err(VerdictError::Overflow));
    }
}
