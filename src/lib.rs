//! crown-indexer — the single paid index (canister). Reads pinned `Settled`
//! and births from the public chain, folds via crown-reduce, serves certified
//! reads. No money, no keys, no signing (architecture §6).
//!
//! The single non-`query` is the paid `ingest`: gate (no work before payment) →
//! accept cycles → `getTransaction` outcall → recognize → fold → re-certify.
//! `unwrap`/`expect`/`panic` are barred on the ingest path.

use candid::{CandidType, Deserialize, Nat};
use crown_reduce::ChainId;
use gate::Gate;

pub mod certified;
pub mod config;
pub mod gate;
pub mod parse;
pub mod recognize;
pub mod rpc;
pub mod state;

/// Longest signature accepted by `ingest`. A Solana transaction signature is a
/// 64-byte ed25519 signature, which is at most 88 base58 characters; anything
/// longer can never resolve to a finalized transaction. The relay caps ingress
/// at 8 KiB, but this canister is immutable (blackholed), so it also bounds the
/// argument itself — a malformed over-long signature is rejected for free,
/// before it is ever reserved or sent to the RPC.
const MAX_SIGNATURE_LEN: usize = 88;

/// Outcome of a paid `ingest`.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum IngestResult {
    /// Folded in: counts of settlements, births, and cross-check anomalies.
    Applied {
        settlements: u64,
        births: u64,
        anomalies: u64,
    },
    /// Signature already folded in, or an identical ingest is in flight — no
    /// charge, no outcall.
    Duplicate,
    /// Attached cycles below `INGEST_PRICE` — rejected before any work.
    Underpaid,
    /// Canister balance below `CYCLE_FLOOR` — refused to touch the reserve.
    LowBalance,
    /// No finalized transaction under consensus, or it failed / was unreadable.
    NotFound,
}

/// A recorded escrow birth, for `get_birth`. `gross` is not surfaced: the index
/// stores only `donor`/`slot` (a game's address derivation already commits `gross`).
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct BirthView {
    pub donor: Vec<u8>,
    pub slot: u64,
}

impl From<certified::Birth> for BirthView {
    fn from(b: certified::Birth) -> Self {
        Self {
            donor: b.donor.to_vec(),
            slot: b.slot,
        }
    }
}

/// Publish the initial (empty) combined root so certified reads work before the
/// first ingest. No config/state to accept — the pinned roots are baked.
#[ic_cdk::init]
fn init() {
    state::recertify();
}

/// Drop unpaid ingress before it induces any work. `ingest` is the only update
/// and it is paid — but ingress messages can never attach cycles, so a direct
/// user `ingest` is always `Underpaid` yet would still decode the (up to ~2 MB)
/// argument and run the gate for free. The relay reaches `ingest` via an
/// inter-canister call, which bypasses `inspect_message`, so the paid path is
/// unaffected. Any other ingress (none today) is accepted.
#[ic_cdk::inspect_message]
fn inspect_message() {
    if ic_cdk::api::msg_method_name() == "ingest" {
        return; // no accept_message → the unpaid ingress is dropped
    }
    ic_cdk::api::accept_message();
}

/// The single non-`query`: paid ingest of one Solana signature. Order (spec
/// §Поверхность): `is_applied` → attached ≥ `INGEST_PRICE` → balance ≥
/// `CYCLE_FLOOR` → **accept cycles** → outcall. No outcall or write before
/// payment is accepted (non-negativity invariant #1).
#[ic_cdk::update]
async fn ingest(signature: String) -> IngestResult {
    // An over-long signature is malformed — it can never resolve to a finalized
    // transaction. Reject it for free, before the gate: no reservation, no
    // outcall, no argument kept (defense in depth on an immutable canister).
    if signature.len() > MAX_SIGNATURE_LEN {
        return IngestResult::NotFound;
    }
    let sig_bytes = signature.as_bytes().to_vec();

    match gate::gate(
        state::is_applied(&sig_bytes),
        ic_cdk::api::msg_cycles_available(),
        ic_cdk::api::canister_cycle_balance(),
        config::INGEST_PRICE,
        config::CYCLE_FLOOR,
    ) {
        Gate::Duplicate => return IngestResult::Duplicate,
        Gate::Underpaid => return IngestResult::Underpaid,
        Gate::LowBalance => return IngestResult::LowBalance,
        Gate::Proceed => {}
    }

    // Reserve the signature *before* the outcall await. The exactly-once mark
    // (`apply`) only lands after the await, so without this reservation N
    // concurrent ingests of the same signature would each pass the gate and fold
    // the settlement N times, inflating reputation. A failed reservation means a
    // duplicate or an in-flight sibling — free, no charge. (Empty signatures are
    // never productive and are rejected here too.)
    if !state::reserve(&sig_bytes) {
        return IngestResult::Duplicate;
    }

    // Payment accepted before any outcall.
    ic_cdk::api::msg_cycles_accept(config::INGEST_PRICE);

    let Some(reply) = rpc::fetch(signature).await else {
        state::release(&sig_bytes); // keep the signature retriable
        return IngestResult::NotFound;
    };
    let Some(tx) = parse::parse(&reply) else {
        state::release(&sig_bytes); // failed / unreadable transaction — retriable
        return IngestResult::NotFound;
    };
    let a = state::apply(sig_bytes, &tx);
    IngestResult::Applied {
        settlements: a.settlements,
        births: a.births,
        anomalies: a.anomalies,
    }
}

/// Reputation at `(chain, donor, recipient)` (0 if absent) plus a witness that
/// reconstructs to the combined root. Verify it with `get_certificate` against
/// the NNS root key. Free query. Empty witness on a malformed (non-32B) key.
#[ic_cdk::query]
fn get_reputation(chain: Vec<u8>, donor: Vec<u8>, recipient: Vec<u8>) -> (Nat, Vec<u8>) {
    match (to32(chain), to32(donor), to32(recipient)) {
        (Some(c), Some(d), Some(r)) => {
            let (v, w) = state::reputation_witness(ChainId(c), d, r);
            (Nat::from(v), w)
        }
        _ => (Nat::from(0u8), Vec::new()),
    }
}

/// A birth (if recorded) plus a witness reconstructing to the combined root.
#[ic_cdk::query]
fn get_birth(escrow: Vec<u8>) -> (Option<BirthView>, Vec<u8>) {
    match to32(escrow) {
        Some(e) => {
            let (b, w) = state::birth_witness(e);
            (b.map(BirthView::from), w)
        }
        None => (None, Vec::new()),
    }
}

/// The IC certificate (signed by the NNS root key) over the canister's certified
/// data, plus the combined root it commits to. A witness verifies against this.
#[ic_cdk::query]
fn get_certificate() -> (Option<Vec<u8>>, Vec<u8>) {
    (ic_cdk::api::data_certificate(), state::combined_root())
}

/// Version of the fold (from crown-reduce). Free query.
#[ic_cdk::query]
fn get_reduce_version() -> u32 {
    crown_reduce::REDUCE_VERSION
}

/// Count of applied signatures. Free query (empty signatures are never marked).
#[ic_cdk::query]
fn get_applied_count() -> u64 {
    state::applied_count()
}

/// Count of cross-check anomalies (event vs executed transfer). Free query.
#[ic_cdk::query]
fn get_anomaly_count() -> u64 {
    state::anomaly_count()
}

/// A 32-byte address from a blob argument, or `None` on wrong length.
fn to32(v: Vec<u8>) -> Option<[u8; 32]> {
    v.try_into().ok()
}

ic_cdk::export_candid!();
