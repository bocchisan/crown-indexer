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

/// Whether a signature has already been folded in — the whole of exactly-once,
/// and the gate's first (free) step. There is no second terminal state: a read
/// that failed leaves no trace, so the signature stays foldable.
pub fn is_applied(signature: &[u8]) -> bool {
    STATE.with_borrow(|s| s.is_applied(signature))
}

/// Retire a signature that was read fine but folded nothing — a finalized
/// *reverted* transaction. It moved nothing and never will, so it is marked
/// applied (exactly-once retires it for free) rather than left to be re-fetched
/// forever at full price by a pusher who cannot tell it apart from a transient
/// failure. `false` if a concurrent ingest of the same signature got there first.
pub fn retire(signature: Vec<u8>) -> bool {
    STATE.with_borrow_mut(|s| s.mark_applied(signature))
}

/// One page of births for the successor generation's seed (architecture §8).
pub fn births_page(start_after: Option<[u8; 32]>, limit: usize) -> Vec<([u8; 32], Birth)> {
    STATE.with_borrow(|s| s.births_page(start_after, limit))
}

/// The capacity gauge: heap bytes in use, populated book keys, recorded births.
///
/// Heap is the binding limit — all state lives there (no stable memory), the book
/// is monotone by law (§2), and a blackholed canister can neither be upgraded nor
/// have its memory limit raised. When it runs out, every ingest traps and the book
/// stops for good; this is the only advance warning, so the cutover is scheduled
/// off these numbers.
pub fn state_stats() -> (u64, u64, u64) {
    STATE.with_borrow(|s| (heap_bytes(), s.book_keys(), s.births_count()))
}

/// Wasm heap currently allocated to this canister, in bytes. Off-wasm (host
/// tests) there is no such notion, so it reads zero.
fn heap_bytes() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (core::arch::wasm32::memory_size(0) as u64).saturating_mul(65_536)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        0
    }
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
    STATE.with_borrow(|s| (s.birth(&escrow), cbor(&s.birth_witness(escrow))))
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
///
/// `None` if the signature is already applied — and that check is the whole of
/// exactly-once: it happens here, inside the same synchronous mutation that sets
/// `applied`, so no two ingests of one signature can both fold however they
/// raced. Folding twice would double the reputation a settlement proves for the
/// price of one ingest.
pub fn apply(signature: Vec<u8>, tx: &Tx) -> Option<Applied> {
    if STATE.with_borrow(|s| s.is_applied(&signature)) {
        return None;
    }
    let cfg = chain_config();
    let recognized = recognize(tx, &cfg);

    STATE.with_borrow_mut(|s| {
        let mut anomalies = recognized.anomalies;
        s.add_anomalies(recognized.anomalies);
        let mut births = 0u64;
        for (escrow, b) in recognized.births {
            s.record_birth(escrow, b);
            births = births.saturating_add(1);
        }
        let mut settlements = 0u64;
        for ev in recognized.settlements {
            let attributed = s.attribute(ev);
            match s.apply_settlement(attributed) {
                Ok(()) => settlements = settlements.saturating_add(1),
                // The law refused the fold (`u128` overflow at this key). Out of
                // physical reach, but a recognized-yet-unfolded settlement must
                // never be silent, and that is exactly what the anomaly counter
                // already means — so it is counted there rather than dropped.
                Err(_) => {
                    s.add_anomalies(1);
                    anomalies = anomalies.saturating_add(1);
                }
            }
        }
        // Empty signatures are never marked; then publish the new combined root.
        s.mark_applied(signature);
        ic_cdk::api::certified_data_set(s.combined_root());
        Some(Applied {
            settlements,
            births,
            anomalies,
        })
    })
}
