//! Canister state: the single `Certified` book/births tree plus a diagnostic
//! anomaly counter. The fold, exactly-once marking, and re-certification all
//! happen here so the update stays a thin gate + outcall + apply.
//!
//! State is in-memory (rebuilt by re-ingest, or by a fresh generation
//! recomputing from chain — architecture §8). No panics on the ingest path.

use crate::certified::{Birth, Certified};
use crate::config::chain_config;
use crate::recognize::{recognize, Tx};
use crown_reduce::ChainId;
use ic_certified_map::HashTree;
use std::cell::RefCell;

thread_local! {
    static STATE: RefCell<Certified> = RefCell::new(Certified::new());
}

/// What one applied transaction folded in.
#[derive(Clone, Copy, Debug, Default)]
pub struct Applied {
    pub settlements: u64,
    pub births: u64,
    pub anomalies: u64,
}

/// Whether a signature was already folded in (exactly-once, gate step 1).
pub fn is_applied(signature: &[u8]) -> bool {
    STATE.with_borrow(|s| s.is_applied(signature))
}

/// Reserve a signature before the outcall await so concurrent same-signature
/// ingests dedup. `false` if empty, already applied, or already reserved.
pub fn reserve(signature: &[u8]) -> bool {
    STATE.with_borrow_mut(|s| s.reserve(signature))
}

/// Drop an in-flight reservation whose ingest aborted, keeping the signature
/// retriable.
pub fn release(signature: &[u8]) {
    STATE.with_borrow_mut(|s| s.release(signature));
}

pub fn applied_count() -> u64 {
    STATE.with_borrow(|s| s.applied_count())
}

pub fn anomaly_count() -> u64 {
    STATE.with_borrow(|s| s.anomaly_count())
}

/// CBOR of a `HashTree` witness (standard IC format; reconstructs to the
/// combined root). Serializing to a `Vec` cannot fail, so an error is dropped.
fn cbor(w: &HashTree) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = ciborium::into_writer(w, &mut buf);
    buf
}

/// Reputation at a key plus a witness proving it against the certified root.
pub fn reputation_witness(chain: ChainId, donor: [u8; 32], recipient: [u8; 32]) -> (u128, Vec<u8>) {
    STATE.with_borrow(|s| {
        let value = s.reputation(chain, donor, recipient);
        (value, cbor(&s.book_witness(chain, donor, recipient)))
    })
}

/// A birth (if present) plus a witness proving it against the certified root.
pub fn birth_witness(escrow: [u8; 32]) -> (Option<Birth>, Vec<u8>) {
    STATE.with_borrow(|s| (s.birth(&escrow).copied(), cbor(&s.birth_witness(escrow))))
}

/// The current combined root (the value under `set_certified_data`).
pub fn combined_root() -> Vec<u8> {
    STATE.with_borrow(|s| s.combined_root().to_vec())
}

/// Publish the current combined root as certified data. Called at `init` so the
/// certificate is meaningful before the first ingest.
pub fn recertify() {
    STATE.with_borrow(|s| ic_cdk::api::certified_data_set(s.combined_root()));
}

/// Recognize, attribute, fold, record, mark applied, and re-certify — the whole
/// state mutation for one paid transaction. Births are recorded before
/// settlements so a same-tx settlement can attribute to a same-tx escrow; the
/// cross-tx ordering invariant (birth's slot precedes its settlement's) is
/// documented on `Certified::attribute`.
pub fn apply(signature: Vec<u8>, tx: &Tx) -> Applied {
    let cfg = chain_config();
    let recognized = recognize(tx, &cfg);

    STATE.with_borrow_mut(|s| {
        s.add_anomalies(recognized.anomalies);
        let mut births = 0u64;
        for (escrow, b) in recognized.births {
            s.record_birth(escrow, b);
            births = births.saturating_add(1);
        }
        let mut settlements = 0u64;
        for ev in recognized.settlements {
            let attributed = s.attribute(ev);
            if s.apply_settlement(attributed).is_ok() {
                settlements = settlements.saturating_add(1);
            }
        }
        // Empty signatures are never marked; then publish the new combined root.
        s.mark_applied(signature);
        ic_cdk::api::certified_data_set(s.combined_root());
        Applied {
            settlements,
            births,
            anomalies: recognized.anomalies,
        }
    })
}
