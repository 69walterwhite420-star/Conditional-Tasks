//! Certified task state (docs/game-spec.md §5): a hash tree over the stored
//! task records under the label `tasks`. Every `get_task` answer carries the
//! IC certificate plus a witness, so the server proves one task's state
//! against the NNS root key without mirroring the whole canister.

use std::cell::RefCell;

use ic_certified_map::{AsHashTree, Hash, RbTree, labeled, labeled_hash};
use sha2::{Digest, Sha256};

/// The single label of the certified tree.
pub const LABEL: &[u8] = b"tasks";

thread_local! {
    /// task storage key → sha256(stored record bytes). Rebuilt from stable
    /// memory on upgrade; certified data always mirrors its root.
    static TREE: RefCell<RbTree<Vec<u8>, Hash>> = const { RefCell::new(RbTree::new()) };
}

/// Records the current bytes of a task and re-certifies the root.
pub fn upsert(key: &[u8], record_bytes: &[u8]) {
    let digest: Hash = Sha256::digest(record_bytes).into();
    TREE.with_borrow_mut(|tree| tree.insert(key.to_vec(), digest));
    recertify();
}

/// CBOR witness for one task key, wrapped under the label — the proof path
/// from the certified root down to sha256(record bytes).
pub fn witness(key: &[u8]) -> Vec<u8> {
    TREE.with_borrow(|tree| {
        let tree = labeled(LABEL, tree.witness(key));
        let mut serializer = serde_cbor::Serializer::new(Vec::new());
        serializer
            .self_describe()
            .and_then(|()| serde::Serialize::serialize(&tree, &mut serializer))
            .map(|()| serializer.into_inner())
            .unwrap_or_default()
    })
}

pub fn recertify() {
    let root = TREE.with_borrow(|tree| labeled_hash(LABEL, &tree.root_hash()));
    ic_cdk::api::certified_data_set(root);
}

/// Upgrade path: the tree is heap state, rebuilt from the stable records.
pub fn rebuild(entries: impl Iterator<Item = (Vec<u8>, Vec<u8>)>) {
    TREE.with_borrow_mut(|tree| {
        for (key, bytes) in entries {
            let digest: Hash = Sha256::digest(&bytes).into();
            tree.insert(key, digest);
        }
    });
    recertify();
}
