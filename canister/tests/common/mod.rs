//! Shared harness of the PocketIC integration tests: instance setup, wallet
//! signing (an independent re-implementation of the wallet side), task flows
//! and full offchain certificate verification.

#![allow(dead_code)] // each test binary uses its own subset

use candid::{Decode, Encode, Principal};
use conditional_tasks::api::{ActionArg, CertifiedTask, RegisterArg};
use conditional_tasks::{TaskRecord, auth, task_key};
use conditional_tasks_logic as logic;
use ic_certification::{Certificate, HashTree, LookupResult};
use pocket_ic::{PocketIc, PocketIcBuilder};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

pub const CHAIN: &str = "solana-devnet";
pub const DURATION: u64 = 3_600;
/// Mirrors `voting_period` of config/testnet.toml — the profile the test
/// wasm is baked with.
pub const VOTING_PERIOD: u64 = 120;

// ---- instances ----------------------------------------------------------------

fn game_wasm() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/wasm32-unknown-unknown/release/conditional_tasks.wasm"
    );
    std::fs::read(path).expect("wasm missing: run scripts/test-canister.sh")
}

fn new_instance() -> (PocketIc, Principal) {
    // The canister sits on the NNS subnet so its certificates carry no
    // delegation and verify directly against the instance root key; the II
    // subnet provides the threshold keys.
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_ii_subnet()
        .build();
    let nns = pic.topology().get_nns().expect("nns subnet");
    let canister = pic.create_canister_on_subnet(None, None, nns);
    pic.add_cycles(canister, 10_000_000_000_000);
    (pic, canister)
}

/// Lets the first timer sweeps run so the threshold key cache is warm:
/// registration refuses tasks until the canister knows its own resolver.
pub fn warm_up(pic: &PocketIc, canister: Principal) {
    for _ in 0..40 {
        pic.advance_time(std::time::Duration::from_secs(1));
        pic.tick();
        let key: (Option<ByteBuf>,) = query(
            pic,
            canister,
            "get_resolver",
            Encode!(&CHAIN.to_string()).unwrap(),
        );
        if key.0.is_some() {
            return;
        }
    }
    panic!("resolver key never warmed up");
}

pub fn resolver(pic: &PocketIc, canister: Principal) -> Vec<u8> {
    let (resolver,): (Option<ByteBuf>,) = query(
        pic,
        canister,
        "get_resolver",
        Encode!(&CHAIN.to_string()).unwrap(),
    );
    resolver.expect("resolver key ready").into_vec()
}

/// The operator wallet every test instance is installed with, via the init
/// override — the baked testnet key's secret lives outside the repo.
pub fn operator() -> Wallet {
    wallet(0xE0)
}

/// A game canister with no book behind it (G2 surface).
pub fn setup() -> (PocketIc, Principal) {
    let (pic, canister) = new_instance();
    let overrides = conditional_tasks::Overrides {
        crown_index: None,
        operator_wallet: Some(ByteBuf::from(operator().address)),
    };
    pic.install_canister(canister, game_wasm(), Encode!(&Some(overrides)).unwrap(), None);
    warm_up(&pic, canister);
    (pic, canister)
}

/// A game canister wired to the mock book via the init override.
pub fn setup_with_index() -> (PocketIc, Principal, Principal) {
    let (pic, game) = new_instance();
    let nns = pic.topology().get_nns().expect("nns subnet");
    let index = pic.create_canister_on_subnet(None, None, nns);
    pic.add_cycles(index, 10_000_000_000_000);
    let mock_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/mock-index/target/wasm32-unknown-unknown/release/mock_crown_index.wasm"
    );
    let mock = std::fs::read(mock_path).expect("mock wasm missing: run scripts/test-canister.sh");
    pic.install_canister(index, mock, Encode!().unwrap(), None);

    let overrides = conditional_tasks::Overrides {
        crown_index: Some(index),
        operator_wallet: Some(ByteBuf::from(operator().address)),
    };
    pic.install_canister(game, game_wasm(), Encode!(&Some(overrides)).unwrap(), None);
    warm_up(&pic, game);
    (pic, game, index)
}

pub fn seed_reputation(
    pic: &PocketIc,
    index: Principal,
    wallet: &[u8],
    streamer: &[u8],
    value: u128,
) {
    let arg = Encode!(
        &CHAIN.to_string(),
        &ByteBuf::from(wallet.to_vec()),
        &ByteBuf::from(streamer.to_vec()),
        &value
    )
    .unwrap();
    pic.update_call(index, Principal::anonymous(), "set_reputation", arg)
        .expect("seed reputation");
}

pub fn now_seconds(pic: &PocketIc) -> u64 {
    pic.get_time().as_nanos_since_unix_epoch() / 1_000_000_000
}

pub fn update<R: for<'a> candid::utils::ArgumentDecoder<'a>>(
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

pub fn query<R: for<'a> candid::utils::ArgumentDecoder<'a>>(
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

pub struct Wallet {
    pub key: ed25519_dalek::SigningKey,
    pub address: Vec<u8>,
}

pub fn wallet(seed: u8) -> Wallet {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let address = key.verifying_key().to_bytes().to_vec();
    Wallet { key, address }
}

/// Raw Ed25519 over the protocol message, re-implemented independently of
/// auth.rs.
pub fn sign(wallet: &Wallet, message: &[u8]) -> Vec<u8> {
    use ed25519_dalek::Signer;
    wallet.key.sign(message).to_bytes().to_vec()
}

// ---- flows -------------------------------------------------------------------

#[derive(Debug)]
pub struct Registered {
    pub task_id: Vec<u8>,
}

pub fn register(
    pic: &PocketIc,
    canister: Principal,
    donor: &Wallet,
    streamer: &[u8],
    nonce: u64,
) -> Result<Registered, String> {
    let spec = auth::spec_of(CHAIN).unwrap();
    let now = now_seconds(pic);
    let gross = 1_000_000;
    let deadline = now + DURATION + VOTING_PERIOD + logic::DEADLINE_MARGIN + 60;
    let resolver = resolver(pic, canister);
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
        streamer: ByteBuf::from(streamer.to_vec()),
        gross,
        deadline,
        resolver: ByteBuf::from(resolver.to_vec()),
        nonce,
        duration: DURATION,
        text_hash: ByteBuf::from(text_hash),
        signature: ByteBuf::from(sign(donor, message.as_bytes())),
    };
    let (result,): (Result<ByteBuf, String>,) =
        update(pic, canister, "register_task", Encode!(&arg).unwrap());
    result.map(|id| {
        assert_eq!(id.as_slice(), task_id.as_slice(), "task_id parity");
        Registered { task_id }
    })
}

pub fn streamer_call(
    pic: &PocketIc,
    canister: Principal,
    method: &str,
    action: auth::Action<'_>,
    task_id: &[u8],
    signer: &Wallet,
) -> Result<(), String> {
    let message = auth::task_message(CHAIN, &canister.to_text(), task_id, &action);
    let arg = ActionArg {
        chain: CHAIN.to_string(),
        task_id: ByteBuf::from(task_id.to_vec()),
        signature: ByteBuf::from(sign(signer, message.as_bytes())),
    };
    let (result,): (Result<(), String>,) = update(pic, canister, method, Encode!(&arg).unwrap());
    result
}

pub fn fetch_task(pic: &PocketIc, canister: Principal, task_id: &[u8]) -> CertifiedTask {
    let (task,): (Option<CertifiedTask>,) = query(
        pic,
        canister,
        "get_task",
        Encode!(&CHAIN.to_string(), &ByteBuf::from(task_id.to_vec())).unwrap(),
    );
    task.expect("task exists")
}

pub fn task_state(task: &CertifiedTask) -> TaskRecord {
    Decode!(task.data.as_slice(), TaskRecord).expect("record decodes")
}

// ---- certificate verification --------------------------------------------------

/// Full offchain verification: BLS against the instance root key, the
/// certified_data binding, the witness path down to sha256(record bytes).
pub fn verify_certified_task(pic: &PocketIc, canister: Principal, task: &CertifiedTask) {
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
    let key = task_key(CHAIN, &record.task_id);
    let LookupResult::Found(leaf) = witness.lookup_path([b"tasks".as_slice(), &key]) else {
        panic!("task key not witnessed");
    };
    let digest: [u8; 32] = Sha256::digest(task.data.as_slice()).into();
    assert_eq!(leaf, digest, "witness pins the returned bytes");
}
