//! E2e helper: builds the participant protocol messages and signs them with
//! wallet keys, so the shell scripts never re-implement the protocol.
//!
//! Messages are UTF-8 text (auth.rs), so `task-message` prints the text
//! itself and `sol-sign` reads it from a file — a shell argument would mangle
//! the newlines. The wallet signs exactly these bytes.
//!
//! Usage:
//!   participant task-message <chain> <canister-principal> <task_id_hex> <action> [args]
//!       action: register <text_hash_hex> <duration> | accept | decline | done
//!               | vote <done|not_done>
//!   participant channel-message <chain> <canister> <streamer_hex> <min_gross>
//!                               <min_reputation> <enabled> <counter>
//!   participant sol-sign <keypair.json> <message-file>
//!   participant sol-address <keypair.json>

use candid::Principal;
use conditional_tasks::auth::{self, Action, Choice};

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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = match args.get(1).map(String::as_str) {
        Some("task-message") => {
            let (chain, canister, task_id) = (&args[2], &args[3], hex_arg(&args[4]));
            let canister = Principal::from_text(canister).expect("principal");
            let text_hash;
            let action = match args[5].as_str() {
                "register" => {
                    text_hash = hex_arg(&args[6]);
                    Action::Register {
                        text_hash: &text_hash,
                        duration: args[7].parse().expect("duration"),
                    }
                }
                "accept" => Action::Accept,
                "decline" => Action::Decline,
                "done" => Action::Done,
                "vote" => Action::Vote(match args[6].as_str() {
                    "done" => Choice::Done,
                    "not_done" => Choice::NotDone,
                    other => panic!("unknown choice {other}"),
                }),
                other => panic!("unknown action {other}"),
            };
            auth::task_message(chain, &canister.to_text(), &task_id, &action)
        }
        Some("channel-message") => {
            let [
                chain,
                canister,
                streamer,
                min_gross,
                min_reputation,
                enabled,
                counter,
            ] = &args[2..]
            else {
                panic!(
                    "channel-message <chain> <canister> <streamer_hex> <min_gross> \
                     <min_reputation> <enabled> <counter>"
                );
            };
            let canister = Principal::from_text(canister).expect("principal");
            auth::channel_message(
                chain,
                &canister.to_text(),
                &hex_arg(streamer),
                min_gross.parse().expect("min_gross"),
                min_reputation.parse().expect("min_reputation"),
                enabled.parse().expect("enabled"),
                counter.parse().expect("counter"),
            )
        }
        // The message is text with newlines in it, so it travels by file.
        Some("sol-sign") => {
            let [keypair, message_file] = &args[2..] else {
                panic!("sol-sign <keypair.json> <message-file>");
            };
            use ed25519_dalek::Signer;
            let key = solana_key(keypair);
            let message = std::fs::read(message_file).expect("message file");
            hex::encode(key.sign(&message).to_bytes())
        }
        Some("sol-address") => {
            let [keypair] = &args[2..] else {
                panic!("sol-address <keypair.json>");
            };
            hex::encode(solana_key(keypair).verifying_key().to_bytes())
        }
        _ => panic!("unknown subcommand"),
    };
    // No trailing newline: the caller redirects this straight into the file
    // that gets signed, and one stray byte is a different message.
    print!("{out}");
}
