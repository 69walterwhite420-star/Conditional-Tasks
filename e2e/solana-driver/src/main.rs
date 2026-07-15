//! Devnet chain driver for the e2e: the transactions around the game that
//! the game itself never sends. The verdict signature always arrives from
//! the outside — produced by the canister, injected here byte for byte.
//!
//! Usage:
//!   e2e-solana donate  <rpc> <donor.json> <streamer_b58> <gross>
//!   e2e-solana create  <rpc> <donor.json> <streamer_b58> <gross> <deadline> <resolver_hex32> <fee_bps> <fee_wallet_b58> <nonce>
//!   e2e-solana claim   <rpc> <payer.json> <escrow_b58> <outcome> <sig_hex> <resolver_hex32>
//!   e2e-solana refund  <rpc> <payer.json> <escrow_b58>
//!   e2e-solana balance <rpc> <owner_b58>

use std::str::FromStr;

use anchor_lang::{AccountDeserialize, InstructionData, ToAccountMetas};
use anchor_spl::associated_token::get_associated_token_address;
use anchor_spl::associated_token::spl_associated_token_account;
use anchor_spl::token::spl_token;
use solana_rpc_client::rpc_client::RpcClient;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::ed25519_program;
use solana_sdk::instruction::Instruction;
use solana_sdk::program_pack::Pack;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, Signer, read_keypair_file};
use solana_sdk::transaction::Transaction;

fn client(url: &str) -> RpcClient {
    RpcClient::new_with_commitment(url.to_string(), CommitmentConfig::confirmed())
}

fn send(rpc: &RpcClient, payer: &Keypair, instructions: &[Instruction]) {
    let blockhash = rpc.get_latest_blockhash().expect("blockhash");
    let tx = Transaction::new_signed_with_payer(
        instructions,
        Some(&payer.pubkey()),
        &[payer],
        blockhash,
    );
    let signature = rpc.send_and_confirm_transaction(&tx).expect("transaction");
    eprintln!("tx: {signature}");
}

fn ata(owner: &Pubkey) -> Pubkey {
    get_associated_token_address(owner, &factory::USDC_MINT)
}

fn create_ata_ix(payer: &Pubkey, owner: &Pubkey) -> Instruction {
    spl_associated_token_account::instruction::create_associated_token_account_idempotent(
        payer,
        owner,
        &factory::USDC_MINT,
        &spl_token::ID,
    )
}

/// The ed25519_program instruction the escrow demands directly before claim:
/// one self-contained signature entry (docs/game-spec.md §8).
fn verdict_ix(resolver: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> Instruction {
    let mut data = Vec::new();
    data.extend_from_slice(&[1, 0]);
    data.extend_from_slice(&48u16.to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&16u16.to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(&112u16.to_le_bytes());
    data.extend_from_slice(&(message.len() as u16).to_le_bytes());
    data.extend_from_slice(&u16::MAX.to_le_bytes());
    data.extend_from_slice(resolver);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);
    Instruction {
        program_id: ed25519_program::ID,
        accounts: vec![],
        data,
    }
}

fn escrow_state(rpc: &RpcClient, escrow: &Pubkey) -> factory::Escrow {
    let account = rpc.get_account(escrow).expect("escrow account");
    factory::Escrow::try_deserialize(&mut account.data.as_slice()).expect("escrow state")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("donate") => {
            let [rpc, keypair, streamer, gross] = &args[2..] else {
                panic!("donate <rpc> <donor.json> <streamer_b58> <gross>");
            };
            let rpc = client(rpc);
            let donor = read_keypair_file(keypair).expect("donor keypair");
            let streamer = Pubkey::from_str(streamer).expect("streamer");
            let gross: u64 = gross.parse().expect("gross");
            let accounts = splitter::accounts::Donate {
                payer: donor.pubkey(),
                streamer,
                mint: splitter::USDC_MINT,
                payer_usdc: ata(&donor.pubkey()),
                streamer_usdc: ata(&streamer),
                token_program: spl_token::ID,
                event_authority: Pubkey::find_program_address(
                    &[b"__event_authority"],
                    &splitter::ID,
                )
                .0,
                program: splitter::ID,
            };
            send(
                &rpc,
                &donor,
                &[
                    create_ata_ix(&donor.pubkey(), &streamer),
                    Instruction {
                        program_id: splitter::ID,
                        accounts: accounts.to_account_metas(None),
                        data: splitter::instruction::Donate { gross }.data(),
                    },
                ],
            );
        }
        Some("create") => {
            let [rpc, keypair, streamer, gross, deadline, resolver, fee_bps, fee_wallet, nonce] =
                &args[2..]
            else {
                panic!(
                    "create <rpc> <donor.json> <streamer_b58> <gross> <deadline> \
                     <resolver_hex32> <fee_bps> <fee_wallet_b58> <nonce>"
                );
            };
            let rpc = client(rpc);
            let donor = read_keypair_file(keypair).expect("donor keypair");
            let streamer = Pubkey::from_str(streamer).expect("streamer");
            let gross: u64 = gross.parse().expect("gross");
            let deadline: i64 = deadline.parse().expect("deadline");
            let nonce: u64 = nonce.parse().expect("nonce");
            let fee_bps: u16 = fee_bps.parse().expect("fee_bps");
            let fee_wallet = Pubkey::from_str(fee_wallet).expect("fee wallet");
            let resolver =
                Pubkey::new_from_array(hex::decode(resolver).unwrap().try_into().unwrap());
            let salt = factory::birth_salt(
                &donor.pubkey(),
                &streamer,
                gross,
                deadline,
                &resolver,
                fee_bps,
                &fee_wallet,
                nonce,
            );
            let (escrow, _) = Pubkey::find_program_address(&[b"escrow", &salt], &factory::ID);
            let accounts = factory::accounts::CreateEscrow {
                donor: donor.pubkey(),
                streamer,
                mint: factory::USDC_MINT,
                escrow,
                donor_usdc: ata(&donor.pubkey()),
                escrow_usdc: ata(&escrow),
                token_program: spl_token::ID,
                associated_token_program: anchor_spl::associated_token::ID,
                system_program: solana_sdk::system_program::ID,
            };
            send(
                &rpc,
                &donor,
                &[Instruction {
                    program_id: factory::ID,
                    accounts: accounts.to_account_metas(None),
                    data: factory::instruction::CreateEscrow {
                        gross,
                        deadline,
                        resolver,
                        fee_bps,
                        fee_wallet,
                        nonce,
                    }
                    .data(),
                }],
            );
            println!("{escrow}");
        }
        Some("claim") => {
            let [rpc, keypair, escrow, outcome, signature, resolver] = &args[2..] else {
                panic!("claim <rpc> <payer.json> <escrow_b58> <outcome> <sig_hex> <resolver_hex32>");
            };
            let rpc = client(rpc);
            let payer = read_keypair_file(keypair).expect("payer keypair");
            let escrow = Pubkey::from_str(escrow).expect("escrow");
            let outcome: u8 = outcome.parse().expect("outcome");
            let signature: [u8; 64] = hex::decode(signature).unwrap().try_into().unwrap();
            let resolver: [u8; 32] = hex::decode(resolver).unwrap().try_into().unwrap();
            let state = escrow_state(&rpc, &escrow);

            let mut message = Vec::new();
            message.extend_from_slice(factory::DOMAIN);
            message.extend_from_slice(factory::ID.as_ref());
            message.extend_from_slice(escrow.as_ref());
            message.push(outcome);

            let accounts = factory::accounts::Claim {
                escrow,
                mint: factory::USDC_MINT,
                escrow_usdc: ata(&escrow),
                donor: state.donor,
                donor_usdc: ata(&state.donor),
                streamer: state.streamer,
                streamer_usdc: Some(ata(&state.streamer)),
                fee_usdc: Some(ata(&state.fee_wallet)),
                splitter_event_authority: Some(
                    Pubkey::find_program_address(&[b"__event_authority"], &factory::SPLITTER).0,
                ),
                splitter_program: factory::SPLITTER,
                instructions_sysvar: anchor_lang::solana_program::sysvar::instructions::ID,
                token_program: spl_token::ID,
            };
            send(
                &rpc,
                &payer,
                &[
                    create_ata_ix(&payer.pubkey(), &state.streamer),
                    create_ata_ix(&payer.pubkey(), &state.fee_wallet),
                    verdict_ix(&resolver, &signature, &message),
                    Instruction {
                        program_id: factory::ID,
                        accounts: accounts.to_account_metas(None),
                        data: factory::instruction::Claim { outcome }.data(),
                    },
                ],
            );
        }
        Some("refund") => {
            let [rpc, keypair, escrow] = &args[2..] else {
                panic!("refund <rpc> <payer.json> <escrow_b58>");
            };
            let rpc = client(rpc);
            let payer = read_keypair_file(keypair).expect("payer keypair");
            let escrow = Pubkey::from_str(escrow).expect("escrow");
            let state = escrow_state(&rpc, &escrow);
            let accounts = factory::accounts::Refund {
                escrow,
                mint: factory::USDC_MINT,
                escrow_usdc: ata(&escrow),
                donor: state.donor,
                donor_usdc: ata(&state.donor),
                token_program: spl_token::ID,
            };
            send(
                &rpc,
                &payer,
                &[Instruction {
                    program_id: factory::ID,
                    accounts: accounts.to_account_metas(None),
                    data: factory::instruction::Refund {}.data(),
                }],
            );
        }
        Some("balance") => {
            let [rpc, owner] = &args[2..] else {
                panic!("balance <rpc> <owner_b58>");
            };
            let rpc = client(rpc);
            let owner = Pubkey::from_str(owner).expect("owner");
            let amount = match rpc.get_account(&ata(&owner)) {
                Err(_) => 0,
                Ok(account) => spl_token::state::Account::unpack(&account.data)
                    .map(|a| a.amount)
                    .unwrap_or(0),
            };
            println!("{amount}");
        }
        _ => panic!("unknown subcommand"),
    }
}
