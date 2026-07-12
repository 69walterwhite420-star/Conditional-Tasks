//! conditional-tasks canister: tasks, participant signatures, vote weight,
//! threshold verdict, certified state (docs/game-spec.md).
//!
//! The update surface is frozen by the .did allowlist lint. Authorization is
//! a wallet signature, never a principal. The canister moves no money and
//! reads no external chains; its clock drives the logic crate's machine.

pub mod api;
pub mod auth;
pub mod certify;
pub mod sign;
pub mod weight;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::time::Duration;

use candid::{CandidType, Decode, Encode};
use conditional_tasks_logic as logic;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{DefaultMemoryImpl, StableBTreeMap, StableCell};
use serde::Deserialize;

/// One chain the game serves; baked from config/ at build time.
pub struct ChainSpec {
    pub id: &'static str,
    pub factory: &'static str,
    /// Cluster-scoped verdict domain, part of the signed message.
    pub domain: &'static str,
    /// The shape's on-chain floor in USDC minor units.
    pub min_gross: u64,
}

include!(concat!(env!("OUT_DIR"), "/profile.rs"));

pub(crate) type Memory = VirtualMemory<DefaultMemoryImpl>;

pub(crate) const TASKS_MEMORY: MemoryId = MemoryId::new(0);
pub(crate) const CHANNELS_MEMORY: MemoryId = MemoryId::new(1);
pub(crate) const CROWN_INDEX_MEMORY: MemoryId = MemoryId::new(2);
pub(crate) const SCHNORR_KEY_MEMORY: MemoryId = MemoryId::new(3);

/// The timer only backstops "time first" inside every step: a late tick can
/// delay a due transition, never corrupt it.
const TICK_INTERVAL: Duration = Duration::from_secs(30);

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    /// Stored candid bytes of TaskRecord / ChannelRecord, keyed by the
    /// length-prefixed (chain, task_id) / (chain, streamer) pairs.
    static TASKS: RefCell<StableBTreeMap<Vec<u8>, Vec<u8>, Memory>> =
        RefCell::new(StableBTreeMap::init(memory(TASKS_MEMORY)));
    static CHANNELS: RefCell<StableBTreeMap<Vec<u8>, Vec<u8>, Memory>> =
        RefCell::new(StableBTreeMap::init(memory(CHANNELS_MEMORY)));

    /// (due time, task key) of every undecided task; heap index over stable
    /// truth, rebuilt on upgrade. Stale entries are harmless: processing a
    /// task recomputes its real due time.
    static DUE: RefCell<BTreeSet<(u64, Vec<u8>)>> = const { RefCell::new(BTreeSet::new()) };

    /// Local-testing override of the crown-index principal; empty on real
    /// deploys, where the baked config value is the only authority.
    static CROWN_INDEX_OVERRIDE: RefCell<StableCell<Vec<u8>, Memory>> =
        RefCell::new(StableCell::init(memory(CROWN_INDEX_MEMORY), Vec::new()));

    /// Cached threshold public key (ed25519); fetched by the timer once and
    /// then immutable — the key derives from canister_id.
    static SCHNORR_PUBLIC_KEY: RefCell<StableCell<Vec<u8>, Memory>> =
        RefCell::new(StableCell::init(memory(SCHNORR_KEY_MEMORY), Vec::new()));

    /// Task keys with a recorded verdict awaiting the threshold signature;
    /// heap index over stable truth, rebuilt on upgrade.
    static PENDING_SIGN: RefCell<BTreeSet<Vec<u8>>> = const { RefCell::new(BTreeSet::new()) };

    /// One sweep at a time; a trapped round never wedges the next.
    static SWEEPING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(crate) fn memory(id: MemoryId) -> Memory {
    MEMORY_MANAGER.with_borrow(|manager| manager.get(id))
}

// ---- records ---------------------------------------------------------------

/// Candid mirror of logic::State; conversion at the boundary, like every
/// foreign type (the logic crate knows no candid).
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum StateView {
    #[serde(rename = "created")]
    Created,
    #[serde(rename = "accepted")]
    Accepted,
    #[serde(rename = "voting")]
    Voting { started_at: u64 },
    #[serde(rename = "decided")]
    Decided { outcome: OutcomeView },
}

#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutcomeView {
    #[serde(rename = "settle")]
    Settle,
    #[serde(rename = "cancel")]
    Cancel,
}

#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChoiceView {
    #[serde(rename = "done")]
    Done,
    #[serde(rename = "not_done")]
    NotDone,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct VoteView {
    pub voter: serde_bytes::ByteBuf,
    pub choice: ChoiceView,
    pub weight: u128,
}

/// The whole stored truth about one task. `data` of `get_task` returns the
/// exact candid bytes of this record; the witness hash pins them.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TaskRecord {
    pub chain: String,
    pub task_id: serde_bytes::ByteBuf,
    pub donor: serde_bytes::ByteBuf,
    pub streamer: serde_bytes::ByteBuf,
    pub gross: u64,
    pub deadline: u64,
    pub resolver: serde_bytes::ByteBuf,
    pub nonce: u64,
    pub text_hash: serde_bytes::ByteBuf,
    pub registered_at: u64,
    pub duration: u64,
    pub voting_period: u64,
    pub state: StateView,
    pub votes: Vec<VoteView>,
    /// The threshold signature of the recorded verdict; appears once, soon
    /// after the decision, and never changes (game-spec §8).
    pub verdict_signature: Option<serde_bytes::ByteBuf>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ChannelRecord {
    pub min_gross: u64,
    pub min_reputation: u128,
    pub enabled: bool,
    pub counter: u64,
}

pub(crate) fn state_to_view(state: &logic::State) -> StateView {
    match state {
        logic::State::Created => StateView::Created,
        logic::State::Accepted => StateView::Accepted,
        logic::State::Voting { started_at } => StateView::Voting {
            started_at: *started_at,
        },
        logic::State::Decided { outcome } => StateView::Decided {
            outcome: match outcome {
                logic::Outcome::Settle => OutcomeView::Settle,
                logic::Outcome::Cancel => OutcomeView::Cancel,
            },
        },
    }
}

fn state_from_view(view: &StateView) -> logic::State {
    match view {
        StateView::Created => logic::State::Created,
        StateView::Accepted => logic::State::Accepted,
        StateView::Voting { started_at } => logic::State::Voting {
            started_at: *started_at,
        },
        StateView::Decided { outcome } => logic::State::Decided {
            outcome: match outcome {
                OutcomeView::Settle => logic::Outcome::Settle,
                OutcomeView::Cancel => logic::Outcome::Cancel,
            },
        },
    }
}

impl TaskRecord {
    pub(crate) fn to_logic(&self) -> logic::Task {
        logic::Task {
            registered_at: self.registered_at,
            duration: self.duration,
            voting_period: self.voting_period,
            state: state_from_view(&self.state),
            votes: self
                .votes
                .iter()
                .map(|vote| logic::Vote {
                    voter: logic::Voter(vote.voter.to_vec()),
                    choice: match vote.choice {
                        ChoiceView::Done => logic::Choice::Done,
                        ChoiceView::NotDone => logic::Choice::NotDone,
                    },
                    weight: vote.weight,
                })
                .collect(),
        }
    }

    pub(crate) fn absorb(&mut self, task: &logic::Task) {
        self.state = state_to_view(&task.state);
        self.votes = task
            .votes
            .iter()
            .map(|vote| VoteView {
                voter: serde_bytes::ByteBuf::from(vote.voter.0.clone()),
                choice: match vote.choice {
                    logic::Choice::Done => ChoiceView::Done,
                    logic::Choice::NotDone => ChoiceView::NotDone,
                },
                weight: vote.weight,
            })
            .collect();
    }
}

// ---- storage ---------------------------------------------------------------

fn composite_key(first: &str, second: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in [first.as_bytes(), second] {
        out.extend((part.len() as u32).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// The certified-tree key of a task: lp(chain) ‖ lp(task_id), u32 le
/// length prefixes. Public — a witness verifier must rebuild it.
pub fn task_key(chain: &str, task_id: &[u8]) -> Vec<u8> {
    composite_key(chain, task_id)
}

pub(crate) fn channel_key(chain: &str, streamer: &[u8]) -> Vec<u8> {
    composite_key(chain, streamer)
}

pub(crate) fn task_exists(key: &[u8]) -> bool {
    TASKS.with_borrow(|tasks| tasks.contains_key(&key.to_vec()))
}

pub(crate) fn load_task_bytes(key: &[u8]) -> Option<Vec<u8>> {
    TASKS.with_borrow(|tasks| tasks.get(&key.to_vec()))
}

pub(crate) fn load_task(key: &[u8]) -> Option<TaskRecord> {
    load_task_bytes(key).map(|bytes| decode_task(&bytes))
}

fn decode_task(bytes: &[u8]) -> TaskRecord {
    match Decode!(bytes, TaskRecord) {
        Ok(record) => record,
        Err(_) => ic_cdk::trap("stable tasks: undecodable record"),
    }
}

/// Persists a record, refreshes the certified tree and the due index.
/// The single write path: every task mutation ends here.
pub(crate) fn save_task(record: &TaskRecord) {
    let key = task_key(&record.chain, &record.task_id);
    let bytes = match Encode!(record) {
        Ok(bytes) => bytes,
        Err(_) => ic_cdk::trap("task record: encode failed"),
    };
    TASKS.with_borrow_mut(|tasks| tasks.insert(key.clone(), bytes.clone()));
    certify::upsert(&key, &bytes);
    if let Some(due) = due_of(record) {
        DUE.with_borrow_mut(|set| set.insert((due, key)));
    } else if record.verdict_signature.is_none() {
        PENDING_SIGN.with_borrow_mut(|set| {
            set.insert(key);
        });
    }
}

pub(crate) fn take_pending_signatures() -> Vec<Vec<u8>> {
    PENDING_SIGN.with_borrow_mut(|set| std::mem::take(set).into_iter().collect())
}

pub(crate) fn requeue_signature(key: Vec<u8>) {
    PENDING_SIGN.with_borrow_mut(|set| {
        set.insert(key);
    });
}

pub(crate) fn schnorr_public_key_bytes() -> Vec<u8> {
    SCHNORR_PUBLIC_KEY.with_borrow(|cell| cell.get().clone())
}

pub(crate) fn set_schnorr_public_key(key: Vec<u8>) {
    SCHNORR_PUBLIC_KEY.with_borrow_mut(|cell| cell.set(key));
}

fn due_of(record: &TaskRecord) -> Option<u64> {
    match record.state {
        StateView::Created | StateView::Accepted => {
            Some(record.registered_at.saturating_add(record.duration))
        }
        StateView::Voting { started_at } => Some(started_at.saturating_add(record.voting_period)),
        StateView::Decided { .. } => None,
    }
}

pub(crate) fn load_channel(chain: &str, streamer: &[u8], floor: u64) -> ChannelRecord {
    CHANNELS
        .with_borrow(|channels| channels.get(&channel_key(chain, streamer)))
        .map(|bytes| match Decode!(&bytes, ChannelRecord) {
            Ok(record) => record,
            Err(_) => ic_cdk::trap("stable channels: undecodable record"),
        })
        // A channel nobody configured accepts tasks at the shape floor:
        // permissionless by default, the streamer simply never accepts.
        .unwrap_or(ChannelRecord {
            min_gross: floor,
            min_reputation: 0,
            enabled: true,
            counter: 0,
        })
}

pub(crate) fn save_channel(chain: &str, streamer: &[u8], record: &ChannelRecord) {
    let bytes = match Encode!(record) {
        Ok(bytes) => bytes,
        Err(_) => ic_cdk::trap("channel record: encode failed"),
    };
    CHANNELS.with_borrow_mut(|channels| channels.insert(channel_key(chain, streamer), bytes));
}

pub(crate) fn tasks_of_streamer(chain: &str, streamer: &[u8]) -> Vec<Vec<u8>> {
    TASKS.with_borrow(|tasks| {
        tasks
            .iter()
            .map(|entry| decode_task(&entry.value()))
            .filter(|record| record.chain == chain && record.streamer.as_slice() == streamer)
            .map(|record| record.task_id.to_vec())
            .collect()
    })
}

// ---- time ------------------------------------------------------------------

pub(crate) fn now_seconds() -> u64 {
    ic_cdk::api::time() / 1_000_000_000
}

/// Applies due time transitions to every task whose due moment has passed.
/// Saving re-inserts the task's next due time, so a task that expires and
/// then finishes voting is handled in one sweep.
fn process_due(now: u64) {
    loop {
        let entry = DUE.with_borrow(|set| set.first().cloned());
        let Some((due, key)) = entry else { break };
        if due > now {
            break;
        }
        DUE.with_borrow_mut(|set| set.remove(&(due, key.clone())));
        let Some(mut record) = load_task(&key) else {
            continue;
        };
        let mut task = record.to_logic();
        // On success the state always advances to Decided and is re-saved. A
        // failed tick (only an unreachable arithmetic overflow) leaves the
        // record untouched and out of the due index — never re-inserting a
        // past-due entry that would spin this loop.
        if logic::step(&mut task, logic::Action::Tick, now).is_ok() {
            record.absorb(&task);
            save_task(&record);
        }
    }
}

fn schedule_tick(delay: Duration) {
    let now = ic_cdk::api::time();
    ic_cdk::api::global_timer_set(now.saturating_add(delay.as_nanos() as u64));
}

pub(crate) fn crown_index() -> Option<candid::Principal> {
    CROWN_INDEX_OVERRIDE.with_borrow(|cell| weight::resolve(cell.get(), CROWN_INDEX))
}

// ---- lifecycle ---------------------------------------------------------------

/// Local-testing overrides, for replicas where the real crown-index does not
/// exist. Forbidden on mainnet: there the baked config is the only truth.
#[derive(CandidType, Deserialize)]
pub struct Overrides {
    pub crown_index: Option<candid::Principal>,
}

#[ic_cdk::init]
fn init(overrides: Option<Overrides>) {
    if let Err(error) = auth::validate_config() {
        ic_cdk::trap(error.text());
    }
    if let Some(overrides) = overrides {
        if PROFILE == "mainnet" {
            ic_cdk::trap("mainnet profile: overrides are forbidden");
        }
        if let Some(principal) = overrides.crown_index {
            CROWN_INDEX_OVERRIDE.with_borrow_mut(|cell| cell.set(principal.as_slice().to_vec()));
        }
    }
    certify::recertify();
    schedule_tick(Duration::from_secs(1));
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    if let Err(error) = auth::validate_config() {
        ic_cdk::trap(error.text());
    }
    certify::rebuild(TASKS.with_borrow(|tasks| {
        tasks
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect::<Vec<_>>()
            .into_iter()
    }));
    TASKS.with_borrow(|tasks| {
        for entry in tasks.iter() {
            let record = decode_task(&entry.value());
            if let Some(due) = due_of(&record) {
                DUE.with_borrow_mut(|set| {
                    set.insert((due, entry.key().clone()));
                });
            } else if record.verdict_signature.is_none() {
                PENDING_SIGN.with_borrow_mut(|set| {
                    set.insert(entry.key().clone());
                });
            }
        }
    });
    schedule_tick(Duration::from_secs(1));
}

/// Resets the sweep flag even when the round's task is cancelled by a trap,
/// so one failed round can never wedge the sweeps forever.
struct SweepGuard;

impl Drop for SweepGuard {
    fn drop(&mut self) {
        SWEEPING.with(|flag| flag.set(false));
    }
}

async fn sweep() {
    if SWEEPING.with(|flag| flag.replace(true)) {
        return;
    }
    let _guard = SweepGuard;
    sign::ensure_resolver_keys().await;
    process_due(now_seconds());
    sign::sign_pending().await;
}

#[cfg_attr(target_family = "wasm", unsafe(export_name = "canister_global_timer"))]
#[allow(dead_code)]
fn global_timer() {
    // Re-arm first: a trap inside the sweep must not stop the schedule.
    schedule_tick(TICK_INTERVAL);
    ic_cdk::futures::internals::in_executor_context(|| {
        ic_cdk::futures::spawn(sweep());
    });
}
