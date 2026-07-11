//! Test double of crown-index: the same `get_reputation` query over a book
//! seeded by an update — something the real canister never allows, which is
//! exactly why this mock lives outside the trusted repositories.

use std::cell::RefCell;
use std::collections::BTreeMap;

use candid::Nat;
use serde_bytes::ByteBuf;

thread_local! {
    static BOOK: RefCell<BTreeMap<(String, Vec<u8>, Vec<u8>), u128>> =
        const { RefCell::new(BTreeMap::new()) };
}

#[ic_cdk::update]
fn set_reputation(chain: String, payer: ByteBuf, streamer: ByteBuf, value: u128) {
    BOOK.with_borrow_mut(|book| {
        book.insert((chain, payer.into_vec(), streamer.into_vec()), value);
    });
}

#[ic_cdk::query]
fn get_reputation(chain: String, payer: ByteBuf, streamer: ByteBuf) -> Nat {
    BOOK.with_borrow(|book| {
        Nat::from(
            book.get(&(chain, payer.into_vec(), streamer.into_vec()))
                .copied()
                .unwrap_or(0),
        )
    })
}
