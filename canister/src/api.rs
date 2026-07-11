//! The Candid surface. Updates are exactly the frozen allowlist; every one
//! authorizes by wallet signature, never by principal. Queries are free,
//! permissionless, and `get_task` carries certificate + witness.

use candid::CandidType;
use conditional_tasks_logic as logic;
use serde::Deserialize;
use serde_bytes::ByteBuf;

use crate::auth;

fn step_error_text(error: logic::StepError) -> String {
    match error {
        logic::StepError::InvalidTransition => "invalid transition",
        logic::StepError::WeightBelowThreshold => "vote weight below threshold",
        logic::StepError::DuplicateVoter => "duplicate voter",
        logic::StepError::Overflow => "arithmetic overflow",
    }
    .to_string()
}

fn register_error_text(error: logic::RegisterError) -> String {
    match error {
        logic::RegisterError::ChannelDisabled => "channel disabled",
        logic::RegisterError::GrossBelowFloor => "gross below the shape floor",
        logic::RegisterError::GrossBelowChannelMinimum => "gross below the channel minimum",
        logic::RegisterError::ReputationBelowMinimum => {
            "donor reputation below the channel minimum"
        }
        logic::RegisterError::DurationOutOfRange => "duration out of range",
        logic::RegisterError::DeadlineTooTight => "deadline too tight",
        logic::RegisterError::TimeOverflow => "time overflow",
    }
    .to_string()
}

fn canister_id() -> Vec<u8> {
    ic_cdk::api::canister_self().as_slice().to_vec()
}

// ---- updates -----------------------------------------------------------------

#[derive(CandidType, Deserialize)]
pub struct RegisterArg {
    pub chain: String,
    pub donor: ByteBuf,
    pub streamer: ByteBuf,
    pub gross: u64,
    pub deadline: u64,
    pub resolver: ByteBuf,
    pub nonce: u64,
    pub duration: u64,
    pub text_hash: ByteBuf,
    pub signature: ByteBuf,
}

/// Registers a task: derives task_id from the declared birth fields, checks
/// the donor's signature over (task_id, text commitment, duration), validates
/// against the channel knobs and births the machine in CREATED.
#[ic_cdk::update]
fn register_task(arg: RegisterArg) -> Result<ByteBuf, String> {
    let spec = auth::spec_of(&arg.chain).map_err(|e| e.text().to_string())?;
    if arg.text_hash.len() != 32 {
        return Err("text hash must be 32 bytes".to_string());
    }
    let task_id = auth::derive_task_id(
        spec,
        &arg.donor,
        &arg.streamer,
        arg.gross,
        arg.deadline,
        &arg.resolver,
        arg.nonce,
    )
    .map_err(|e| e.text().to_string())?;
    let key = crate::task_key(&arg.chain, &task_id);
    if crate::task_exists(&key) {
        return Err("task already registered".to_string());
    }

    let message = auth::task_message(
        &arg.chain,
        &canister_id(),
        &task_id,
        auth::ACTION_REGISTER,
        &auth::register_payload(&arg.text_hash, arg.duration),
    );
    auth::verify_wallet_signature(spec.kind(), &message, &arg.signature, &arg.donor)
        .map_err(|e| e.text().to_string())?;

    let channel = crate::load_channel(&arg.chain, &arg.streamer, spec.min_gross);
    let now = crate::now_seconds();
    let task = logic::register(
        now,
        &logic::ChannelParams {
            min_gross: channel.min_gross,
            min_reputation: channel.min_reputation,
            enabled: channel.enabled,
        },
        spec.min_gross,
        &logic::Registration {
            gross: arg.gross,
            duration: arg.duration,
            deadline: arg.deadline,
            // G3 wires the real book value; zero rejects every registration
            // on channels that demand reputation — conservative until then.
            donor_reputation: 0,
        },
    )
    .map_err(register_error_text)?;

    let mut record = crate::TaskRecord {
        chain: arg.chain,
        task_id: ByteBuf::from(task_id.clone()),
        donor: arg.donor,
        streamer: arg.streamer,
        gross: arg.gross,
        deadline: arg.deadline,
        resolver: arg.resolver,
        nonce: arg.nonce,
        text_hash: arg.text_hash,
        registered_at: task.registered_at,
        duration: task.duration,
        state: crate::state_to_view(&task.state),
        votes: Vec::new(),
    };
    record.absorb(&task);
    crate::save_task(&record);
    Ok(ByteBuf::from(task_id))
}

#[derive(CandidType, Deserialize)]
pub struct ActionArg {
    pub chain: String,
    pub task_id: ByteBuf,
    pub signature: ByteBuf,
}

#[ic_cdk::update]
fn accept(arg: ActionArg) -> Result<(), String> {
    streamer_action(arg, logic::Action::Accept, auth::ACTION_ACCEPT)
}

#[ic_cdk::update]
fn decline(arg: ActionArg) -> Result<(), String> {
    streamer_action(arg, logic::Action::Decline, auth::ACTION_DECLINE)
}

#[ic_cdk::update]
fn done(arg: ActionArg) -> Result<(), String> {
    streamer_action(arg, logic::Action::Done, auth::ACTION_DONE)
}

/// The three streamer moves share one path: load, verify the streamer's
/// signature over (task, action), step the machine. Time transitions that
/// became due persist even when the action itself is rejected.
fn streamer_action(arg: ActionArg, action: logic::Action, action_byte: u8) -> Result<(), String> {
    let spec = auth::spec_of(&arg.chain).map_err(|e| e.text().to_string())?;
    let key = crate::task_key(&arg.chain, &arg.task_id);
    let mut record = crate::load_task(&key).ok_or_else(|| "unknown task".to_string())?;

    let message = auth::task_message(&arg.chain, &canister_id(), &arg.task_id, action_byte, &[]);
    auth::verify_wallet_signature(spec.kind(), &message, &arg.signature, &record.streamer)
        .map_err(|e| e.text().to_string())?;

    let mut task = record.to_logic();
    let result = logic::step(&mut task, action, crate::now_seconds());
    record.absorb(&task);
    crate::save_task(&record);
    result.map_err(step_error_text)
}

#[derive(CandidType, Deserialize)]
pub struct ChannelArg {
    pub chain: String,
    pub streamer: ByteBuf,
    pub min_gross: u64,
    pub min_reputation: u128,
    pub enabled: bool,
    pub counter: u64,
    pub signature: ByteBuf,
}

/// Streamer knobs. The counter must strictly grow — an old signature can
/// never be replayed. Changes affect future registrations only.
#[ic_cdk::update]
fn set_channel_params(arg: ChannelArg) -> Result<(), String> {
    let spec = auth::spec_of(&arg.chain).map_err(|e| e.text().to_string())?;
    if arg.min_gross < spec.min_gross {
        return Err("channel minimum below the shape floor".to_string());
    }
    let current = crate::load_channel(&arg.chain, &arg.streamer, spec.min_gross);
    if arg.counter <= current.counter {
        return Err("stale counter".to_string());
    }
    let message = auth::channel_message(
        &arg.chain,
        &canister_id(),
        &arg.streamer,
        arg.min_gross,
        arg.min_reputation,
        arg.enabled,
        arg.counter,
    );
    auth::verify_wallet_signature(spec.kind(), &message, &arg.signature, &arg.streamer)
        .map_err(|e| e.text().to_string())?;
    crate::save_channel(
        &arg.chain,
        &arg.streamer,
        &crate::ChannelRecord {
            min_gross: arg.min_gross,
            min_reputation: arg.min_reputation,
            enabled: arg.enabled,
            counter: arg.counter,
        },
    );
    Ok(())
}

// ---- queries -----------------------------------------------------------------

#[derive(CandidType, Deserialize)]
pub struct CertifiedTask {
    /// The exact stored candid bytes of TaskRecord; the witness pins their
    /// sha256, the certificate signs the witness root.
    pub data: ByteBuf,
    pub certificate: Option<ByteBuf>,
    pub witness: ByteBuf,
}

#[ic_cdk::query]
fn get_task(chain: String, task_id: ByteBuf) -> Option<CertifiedTask> {
    let key = crate::task_key(&chain, &task_id);
    let data = crate::load_task_bytes(&key)?;
    Some(CertifiedTask {
        data: ByteBuf::from(data),
        certificate: ic_cdk::api::data_certificate().map(ByteBuf::from),
        witness: ByteBuf::from(crate::certify::witness(&key)),
    })
}

#[ic_cdk::query]
fn list_tasks(chain: String, streamer: ByteBuf) -> Vec<ByteBuf> {
    crate::tasks_of_streamer(&chain, &streamer)
        .into_iter()
        .map(ByteBuf::from)
        .collect()
}

#[ic_cdk::query]
fn get_channel(chain: String, streamer: ByteBuf) -> Option<crate::ChannelRecord> {
    let spec = auth::spec_of(&chain).ok()?;
    Some(crate::load_channel(&chain, &streamer, spec.min_gross))
}

#[ic_cdk::query]
fn get_logic_version() -> u32 {
    logic::LOGIC_VERSION
}
