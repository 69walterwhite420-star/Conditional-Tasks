//! G2 integration: the canister inside PocketIC — registration, streamer
//! signatures, timer transitions, certified state (docs/build-plan.md G2).
//!
//! Needs the release wasm and a pocket-ic server binary; driven by
//! scripts/test-canister.sh, hence the #[ignore] markers.

use candid::{Decode, Encode, Principal};
use conditional_tasks::api::{ActionArg, CertifiedTask, ChannelArg, RegisterArg};
use conditional_tasks::{ChannelRecord, TaskRecord, auth, task_key};
use conditional_tasks_logic as logic;
use ic_certification::{Certificate, HashTree, LookupResult};
use pocket_ic::{PocketIc, PocketIcBuilder};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

const EVM: &str = "eth-sepolia";
const SOL: &str = "solana-devnet";
const DURATION: u64 = 3_600;

// ---- harness ----------------------------------------------------------------

fn setup() -> (PocketIc, Principal) {
    // The canister sits on the NNS subnet so its certificates carry no
    // delegation and verify directly against the instance root key.
    let pic = PocketIcBuilder::new().with_nns_subnet().build();
    let nns = pic.topology().get_nns().expect("nns subnet");
    let canister = pic.create_canister_on_subnet(None, None, nns);
    pic.add_cycles(canister, 10_000_000_000_000);
    let wasm_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/wasm32-unknown-unknown/release/conditional_tasks.wasm"
    );
    let wasm = std::fs::read(wasm_path)
        .expect("wasm missing: cargo build --target wasm32-unknown-unknown --release");
    pic.install_canister(canister, wasm, Encode!().unwrap(), None);
    (pic, canister)
}

fn now_seconds(pic: &PocketIc) -> u64 {
    pic.get_time().as_nanos_since_unix_epoch() / 1_000_000_000
}

fn update<R: for<'a> candid::utils::ArgumentDecoder<'a>>(
    pic: &PocketIc,
    canister: Principal,
    method: &str,
    arg: Vec<u8>,
) -> R {
    let reply = pic
        .update_call(canister, Principal::anonymous(), method, arg)
        .unwrap_or_else(|reject| panic!("{method} rejected: {reject:?}"));
    candid::utils::decode_args(&reply).expect("reply decodes")
}

fn query<R: for<'a> candid::utils::ArgumentDecoder<'a>>(
    pic: &PocketIc,
    canister: Principal,
    method: &str,
    arg: Vec<u8>,
) -> R {
    let reply = pic
        .query_call(canister, Principal::anonymous(), method, arg)
        .unwrap_or_else(|reject| panic!("{method} rejected: {reject:?}"));
    candid::utils::decode_args(&reply).expect("reply decodes")
}

// ---- wallets ------------------------------------------------------------------

struct EvmWallet {
    key: k256::ecdsa::SigningKey,
    address: Vec<u8>,
}

fn evm_wallet(seed: u8) -> EvmWallet {
    let key = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
    // Independent re-derivation of the address (the protocol pin lives in
    // auth's unit tests; here we just need matching keys).
    let point = key.verifying_key().to_encoded_point(false);
    let digest: [u8; 32] = Keccak256::digest(&point.as_bytes()[1..]).into();
    EvmWallet {
        key,
        address: digest[12..].to_vec(),
    }
}

/// EIP-191 personal_sign, re-implemented independently of auth.rs.
fn evm_sign(wallet: &EvmWallet, message: &[u8]) -> Vec<u8> {
    let mut hasher = Keccak256::new();
    hasher.update(b"\x19Ethereum Signed Message:\n");
    hasher.update(message.len().to_string().as_bytes());
    hasher.update(message);
    let digest: [u8; 32] = hasher.finalize().into();
    let (sig, recovery) = wallet.key.sign_prehash_recoverable(&digest).unwrap();
    let mut out = sig.to_bytes().to_vec();
    out.push(27 + recovery.to_byte());
    out
}

struct SolWallet {
    key: ed25519_dalek::SigningKey,
    address: Vec<u8>,
}

fn sol_wallet(seed: u8) -> SolWallet {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let address = key.verifying_key().to_bytes().to_vec();
    SolWallet { key, address }
}

fn sol_sign(wallet: &SolWallet, message: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer;
    wallet.key.sign(message).to_bytes().to_vec()
}

// ---- flows -------------------------------------------------------------------

#[derive(Debug)]
struct Registered {
    task_id: Vec<u8>,
}

fn register_evm(
    pic: &PocketIc,
    canister: Principal,
    donor: &EvmWallet,
    streamer: &[u8],
    nonce: u64,
) -> Result<Registered, String> {
    let spec = auth::spec_of(EVM).unwrap();
    let now = now_seconds(pic);
    let gross = 1_000_000;
    let deadline = now + DURATION + logic::VOTING_PERIOD + logic::DEADLINE_MARGIN + 60;
    let resolver = [0x77u8; 20];
    let task_id = auth::derive_task_id(
        spec,
        &donor.address,
        streamer,
        gross,
        deadline,
        &resolver,
        nonce,
    )
    .unwrap();
    let text_hash = Sha256::digest(b"do a backflip \x00 salt").to_vec();
    let message = auth::task_message(
        EVM,
        canister.as_slice(),
        &task_id,
        auth::ACTION_REGISTER,
        &auth::register_payload(&text_hash, DURATION),
    );
    let arg = RegisterArg {
        chain: EVM.to_string(),
        donor: ByteBuf::from(donor.address.clone()),
        streamer: ByteBuf::from(streamer.to_vec()),
        gross,
        deadline,
        resolver: ByteBuf::from(resolver.to_vec()),
        nonce,
        duration: DURATION,
        text_hash: ByteBuf::from(text_hash),
        signature: ByteBuf::from(evm_sign(donor, &message)),
    };
    let (result,): (Result<ByteBuf, String>,) =
        update(pic, canister, "register_task", Encode!(&arg).unwrap());
    result.map(|id| {
        assert_eq!(id.as_slice(), task_id.as_slice(), "task_id parity");
        Registered { task_id }
    })
}

fn streamer_call(
    pic: &PocketIc,
    canister: Principal,
    method: &str,
    action_byte: u8,
    task_id: &[u8],
    signer: &EvmWallet,
) -> Result<(), String> {
    let message = auth::task_message(EVM, canister.as_slice(), task_id, action_byte, &[]);
    let arg = ActionArg {
        chain: EVM.to_string(),
        task_id: ByteBuf::from(task_id.to_vec()),
        signature: ByteBuf::from(evm_sign(signer, &message)),
    };
    let (result,): (Result<(), String>,) = update(pic, canister, method, Encode!(&arg).unwrap());
    result
}

fn fetch_task(pic: &PocketIc, canister: Principal, chain: &str, task_id: &[u8]) -> CertifiedTask {
    let (task,): (Option<CertifiedTask>,) = query(
        pic,
        canister,
        "get_task",
        Encode!(&chain.to_string(), &ByteBuf::from(task_id.to_vec())).unwrap(),
    );
    task.expect("task exists")
}

fn task_state(task: &CertifiedTask) -> TaskRecord {
    Decode!(task.data.as_slice(), TaskRecord).expect("record decodes")
}

// ---- certificate verification --------------------------------------------------

/// Full offchain verification: BLS against the instance root key, the
/// certified_data binding, the witness path down to sha256(record bytes).
fn verify_certified_task(pic: &PocketIc, canister: Principal, chain: &str, task: &CertifiedTask) {
    let certificate: Certificate =
        serde_cbor::from_slice(task.certificate.as_ref().expect("certificate present"))
            .expect("certificate decodes");
    assert!(
        certificate.delegation.is_none(),
        "NNS-subnet canister: no delegation"
    );

    // 1. Genuine: signed by the root key ("NNS root key" of the instance).
    let root_key = pic.root_key().expect("instance has a root key");
    let bls_key = &root_key[root_key.len() - 96..];
    let mut message = vec![13u8];
    message.extend_from_slice(b"ic-state-root");
    message.extend_from_slice(&certificate.tree.digest());
    ic_verify_bls_signature::verify_bls_signature(&certificate.signature, &message, bls_key)
        .expect("BLS signature verifies against the root key");

    // 2. Bound: the certificate certifies this canister's certified_data.
    let path = [
        b"canister".as_slice(),
        canister.as_slice(),
        b"certified_data",
    ];
    let LookupResult::Found(certified_data) = certificate.tree.lookup_path(&path) else {
        panic!("certified_data not in certificate");
    };

    // 3. Witnessed: the witness digest is the certified root, and its path
    // [tasks, task_key] holds sha256 of the exact record bytes returned.
    let witness: HashTree = serde_cbor::from_slice(&task.witness).expect("witness decodes");
    assert_eq!(
        witness.digest().as_slice(),
        certified_data,
        "witness root == certified_data"
    );
    let record = task_state(task);
    let key = task_key(chain, &record.task_id);
    let LookupResult::Found(leaf) = witness.lookup_path([b"tasks".as_slice(), &key]) else {
        panic!("task key not witnessed");
    };
    let digest: [u8; 32] = Sha256::digest(task.data.as_slice()).into();
    assert_eq!(leaf, digest, "witness pins the returned bytes");
}

// ---- tests ---------------------------------------------------------------------

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn evm_full_flow_with_certificates() {
    let (pic, canister) = setup();
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);

    let registered = register_evm(&pic, canister, &donor, &streamer.address, 1).unwrap();
    let task = fetch_task(&pic, canister, EVM, &registered.task_id);
    let record = task_state(&task);
    assert_eq!(record.state, conditional_tasks::StateView::Created);
    assert_eq!(record.donor.as_slice(), donor.address.as_slice());
    verify_certified_task(&pic, canister, EVM, &task);

    streamer_call(
        &pic,
        canister,
        "accept",
        auth::ACTION_ACCEPT,
        &registered.task_id,
        &streamer,
    )
    .unwrap();
    let task = fetch_task(&pic, canister, EVM, &registered.task_id);
    assert_eq!(
        task_state(&task).state,
        conditional_tasks::StateView::Accepted
    );
    verify_certified_task(&pic, canister, EVM, &task);

    streamer_call(
        &pic,
        canister,
        "done",
        auth::ACTION_DONE,
        &registered.task_id,
        &streamer,
    )
    .unwrap();
    let task = fetch_task(&pic, canister, EVM, &registered.task_id);
    assert!(matches!(
        task_state(&task).state,
        conditional_tasks::StateView::Voting { .. }
    ));
    verify_certified_task(&pic, canister, EVM, &task);

    let (version,): (u32,) = query(&pic, canister, "get_logic_version", Encode!().unwrap());
    assert_eq!(version, logic::LOGIC_VERSION);
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn foreign_signatures_are_rejected() {
    let (pic, canister) = setup();
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);
    let stranger = evm_wallet(3);

    let a = register_evm(&pic, canister, &donor, &streamer.address, 1).unwrap();
    let b = register_evm(&pic, canister, &donor, &streamer.address, 2).unwrap();

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
        EVM,
        canister.as_slice(),
        &b.task_id,
        auth::ACTION_ACCEPT,
        &[],
    );
    let arg = ActionArg {
        chain: EVM.to_string(),
        task_id: ByteBuf::from(a.task_id.clone()),
        signature: ByteBuf::from(evm_sign(&streamer, &message)),
    };
    let (result,): (Result<(), String>,) = update(&pic, canister, "accept", Encode!(&arg).unwrap());
    assert_eq!(result.unwrap_err(), "bad signature");

    // A decline signature does not accept.
    let message = auth::task_message(
        EVM,
        canister.as_slice(),
        &a.task_id,
        auth::ACTION_DECLINE,
        &[],
    );
    let arg = ActionArg {
        chain: EVM.to_string(),
        task_id: ByteBuf::from(a.task_id.clone()),
        signature: ByteBuf::from(evm_sign(&streamer, &message)),
    };
    let (result,): (Result<(), String>,) = update(&pic, canister, "accept", Encode!(&arg).unwrap());
    assert_eq!(result.unwrap_err(), "bad signature");

    // The state never moved.
    let task = fetch_task(&pic, canister, EVM, &a.task_id);
    assert_eq!(
        task_state(&task).state,
        conditional_tasks::StateView::Created
    );
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn registration_validation_and_duplicates() {
    let (pic, canister) = setup();
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);

    register_evm(&pic, canister, &donor, &streamer.address, 1).unwrap();
    let error = register_evm(&pic, canister, &donor, &streamer.address, 1).unwrap_err();
    assert_eq!(error, "task already registered");

    // Deadline below registration + duration + voting + margin.
    let spec = auth::spec_of(EVM).unwrap();
    let now = now_seconds(&pic);
    let tight = now + DURATION + logic::VOTING_PERIOD + logic::DEADLINE_MARGIN - 10;
    let resolver = [0x77u8; 20];
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
        EVM,
        canister.as_slice(),
        &task_id,
        auth::ACTION_REGISTER,
        &auth::register_payload(&text_hash, DURATION),
    );
    let arg = RegisterArg {
        chain: EVM.to_string(),
        donor: ByteBuf::from(donor.address.clone()),
        streamer: ByteBuf::from(streamer.address.clone()),
        gross: 1_000_000,
        deadline: tight,
        resolver: ByteBuf::from(resolver.to_vec()),
        nonce: 9,
        duration: DURATION,
        text_hash: ByteBuf::from(text_hash),
        signature: ByteBuf::from(evm_sign(&donor, &message)),
    };
    let (result,): (Result<ByteBuf, String>,) =
        update(&pic, canister, "register_task", Encode!(&arg).unwrap());
    assert_eq!(result.unwrap_err(), "deadline too tight");
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn tampered_registration_fields_break_the_signature() {
    let (pic, canister) = setup();
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);
    let spec = auth::spec_of(EVM).unwrap();
    let now = now_seconds(&pic);
    let gross = 1_000_000;
    let deadline = now + DURATION + logic::VOTING_PERIOD + logic::DEADLINE_MARGIN + 60;
    let resolver = [0x77u8; 20];
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
        EVM,
        canister.as_slice(),
        &task_id,
        auth::ACTION_REGISTER,
        &auth::register_payload(&text_hash, DURATION),
    );
    // A relayer doubles the declared duration after the donor signed.
    let arg = RegisterArg {
        chain: EVM.to_string(),
        donor: ByteBuf::from(donor.address.clone()),
        streamer: ByteBuf::from(streamer.address.clone()),
        gross,
        deadline,
        resolver: ByteBuf::from(resolver.to_vec()),
        nonce: 1,
        duration: DURATION * 2,
        text_hash: ByteBuf::from(text_hash),
        signature: ByteBuf::from(evm_sign(&donor, &message)),
    };
    let (result,): (Result<ByteBuf, String>,) =
        update(&pic, canister, "register_task", Encode!(&arg).unwrap());
    assert_eq!(result.unwrap_err(), "bad signature");
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn time_expires_tasks_with_and_without_the_timer() {
    let (pic, canister) = setup();
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);

    // Task A dies by the global timer alone.
    let a = register_evm(&pic, canister, &donor, &streamer.address, 1).unwrap();
    // Task B dies inside the rejected accept (time first), timer or not.
    let b = register_evm(&pic, canister, &donor, &streamer.address, 2).unwrap();

    pic.advance_time(std::time::Duration::from_secs(DURATION + 90));
    pic.tick();
    pic.tick();

    let task = fetch_task(&pic, canister, EVM, &a.task_id);
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
    let task = fetch_task(&pic, canister, EVM, &b.task_id);
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
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);

    let r = register_evm(&pic, canister, &donor, &streamer.address, 1).unwrap();
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

    pic.advance_time(std::time::Duration::from_secs(logic::VOTING_PERIOD + 90));
    pic.tick();
    pic.tick();

    let task = fetch_task(&pic, canister, EVM, &r.task_id);
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
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);

    let r = register_evm(&pic, canister, &donor, &streamer.address, 1).unwrap();
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
    let task = fetch_task(&pic, canister, EVM, &r.task_id);
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
    let donor = evm_wallet(1);
    let streamer = evm_wallet(2);

    let set = |min_gross: u64, min_reputation: u128, enabled: bool, counter: u64| {
        let message = auth::channel_message(
            EVM,
            canister.as_slice(),
            &streamer.address,
            min_gross,
            min_reputation,
            enabled,
            counter,
        );
        let arg = ChannelArg {
            chain: EVM.to_string(),
            streamer: ByteBuf::from(streamer.address.clone()),
            min_gross,
            min_reputation,
            enabled,
            counter,
            signature: ByteBuf::from(evm_sign(&streamer, &message)),
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
        Encode!(&EVM.to_string(), &ByteBuf::from(streamer.address.clone())).unwrap(),
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
    let error = register_evm(&pic, canister, &donor, &streamer.address, 1).unwrap_err();
    assert_eq!(error, "gross below the channel minimum");

    // A disabled channel registers nothing.
    set(2_000_000, 0, false, 2).unwrap();
    let error = register_evm(&pic, canister, &donor, &streamer.address, 2).unwrap_err();
    assert_eq!(error, "channel disabled");
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn solana_flow_mirrors_evm() {
    let (pic, canister) = setup();
    let donor = sol_wallet(1);
    let streamer = sol_wallet(2);
    let resolver = [0x77u8; 32];

    let spec = auth::spec_of(SOL).unwrap();
    let now = now_seconds(&pic);
    let gross = 1_000_000;
    let deadline = now + DURATION + logic::VOTING_PERIOD + logic::DEADLINE_MARGIN + 60;
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
    let text_hash = Sha256::digest(b"sing a song \x00 salt").to_vec();
    let message = auth::task_message(
        SOL,
        canister.as_slice(),
        &task_id,
        auth::ACTION_REGISTER,
        &auth::register_payload(&text_hash, DURATION),
    );
    let arg = RegisterArg {
        chain: SOL.to_string(),
        donor: ByteBuf::from(donor.address.clone()),
        streamer: ByteBuf::from(streamer.address.clone()),
        gross,
        deadline,
        resolver: ByteBuf::from(resolver.to_vec()),
        nonce: 1,
        duration: DURATION,
        text_hash: ByteBuf::from(text_hash),
        signature: ByteBuf::from(sol_sign(&donor, &message)),
    };
    let (result,): (Result<ByteBuf, String>,) =
        update(&pic, canister, "register_task", Encode!(&arg).unwrap());
    let returned = result.unwrap();
    assert_eq!(returned.as_slice(), task_id.as_slice());

    let message = auth::task_message(SOL, canister.as_slice(), &task_id, auth::ACTION_ACCEPT, &[]);
    let arg = ActionArg {
        chain: SOL.to_string(),
        task_id: ByteBuf::from(task_id.clone()),
        signature: ByteBuf::from(sol_sign(&streamer, &message)),
    };
    let (result,): (Result<(), String>,) = update(&pic, canister, "accept", Encode!(&arg).unwrap());
    result.unwrap();

    let task = fetch_task(&pic, canister, SOL, &task_id);
    assert_eq!(
        task_state(&task).state,
        conditional_tasks::StateView::Accepted
    );
    verify_certified_task(&pic, canister, SOL, &task);

    let (ids,): (Vec<ByteBuf>,) = query(
        &pic,
        canister,
        "list_tasks",
        Encode!(&SOL.to_string(), &ByteBuf::from(streamer.address.clone())).unwrap(),
    );
    assert_eq!(ids, vec![ByteBuf::from(task_id)]);
}
