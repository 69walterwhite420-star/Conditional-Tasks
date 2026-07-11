//! E2e helper: builds the participant protocol messages and signs them with
//! wallet keys, so the shell scripts never re-implement the byte protocol.
//!
//! Usage:
//!   participant task-message <chain> <canister-principal> <task_id_hex> <action_u8> <payload_hex>
//!   participant register-payload <text_hash_hex> <duration_secs>
//!   participant evm-sign <privkey_hex> <message_hex>
//!   participant evm-address <privkey_hex>
//!   participant sol-sign <keypair.json> <message_hex>
//!   participant sol-address <keypair.json>

use candid::Principal;
use conditional_tasks::auth;

fn hex_arg(text: &str) -> Vec<u8> {
    hex::decode(text.strip_prefix("0x").unwrap_or(text)).expect("hex argument")
}

/// Standard solana keypair file: a JSON array of 64 bytes, secret ‖ public.
fn solana_key(path: &str) -> ed25519_dalek::SigningKey {
    let text = std::fs::read_to_string(path).expect("keypair file");
    let bytes: Vec<u8> = text
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|part| part.trim().parse().expect("keypair byte"))
        .collect();
    let secret: [u8; 32] = bytes[..32].try_into().expect("keypair length");
    ed25519_dalek::SigningKey::from_bytes(&secret)
}

fn eip191_digest(message: &[u8]) -> [u8; 32] {
    use sha3::Digest;
    let mut hasher = sha3::Keccak256::new();
    hasher.update(b"\x19Ethereum Signed Message:\n");
    hasher.update(message.len().to_string().as_bytes());
    hasher.update(message);
    hasher.finalize().into()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = match args.get(1).map(String::as_str) {
        Some("task-message") => {
            let [chain, canister, task_id, action, payload] = &args[2..] else {
                panic!("task-message <chain> <canister> <task_id_hex> <action> <payload_hex>");
            };
            let canister = Principal::from_text(canister).expect("principal");
            hex::encode(auth::task_message(
                chain,
                canister.as_slice(),
                &hex_arg(task_id),
                action.parse().expect("action byte"),
                &hex_arg(payload),
            ))
        }
        Some("register-payload") => {
            let [text_hash, duration] = &args[2..] else {
                panic!("register-payload <text_hash_hex> <duration_secs>");
            };
            hex::encode(auth::register_payload(
                &hex_arg(text_hash),
                duration.parse().expect("duration"),
            ))
        }
        Some("evm-sign") => {
            let [key, message] = &args[2..] else {
                panic!("evm-sign <privkey_hex> <message_hex>");
            };
            let key = k256::ecdsa::SigningKey::from_slice(&hex_arg(key)).expect("evm key");
            let digest = eip191_digest(&hex_arg(message));
            let (sig, recovery) = key.sign_prehash_recoverable(&digest).expect("sign");
            let mut out = sig.to_bytes().to_vec();
            out.push(27 + recovery.to_byte());
            hex::encode(out)
        }
        Some("evm-address") => {
            let [key] = &args[2..] else {
                panic!("evm-address <privkey_hex>");
            };
            let key = k256::ecdsa::SigningKey::from_slice(&hex_arg(key)).expect("evm key");
            hex::encode(auth::eth_address(key.verifying_key()))
        }
        Some("sol-sign") => {
            let [keypair, message] = &args[2..] else {
                panic!("sol-sign <keypair.json> <message_hex>");
            };
            use ed25519_dalek::Signer;
            let key = solana_key(keypair);
            hex::encode(key.sign(&hex_arg(message)).to_bytes())
        }
        Some("sol-address") => {
            let [keypair] = &args[2..] else {
                panic!("sol-address <keypair.json>");
            };
            hex::encode(solana_key(keypair).verifying_key().to_bytes())
        }
        _ => panic!("unknown subcommand"),
    };
    println!("{out}");
}
