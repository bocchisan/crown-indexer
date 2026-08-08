//! crown-indexer — the single paid index (canister). Reads pinned `Settled`
//! and births from the public chain, folds via crown-reduce, serves certified
//! reads. No money, no keys, no signing (architecture §6).
//!
//! The single non-`query` is the paid `ingest`: gate (no work before payment) →
//! accept cycles → `getTransaction` outcall → recognize → fold → re-certify.
//! `unwrap`/`expect`/`panic` are barred on the ingest path.
#![forbid(unsafe_code)]
// The ban is a crate lint, not a habit. This canister is blackholed: a panic on
// the ingest path is a trap that cannot be patched out, and an unmarked overflow
// is a wrong book that cannot be corrected. `crown-reduce` already denies these;
// the index is the half that actually touches untrusted chain bytes, so it must
// too. Tests are exempt — `unwrap` in a test *is* the assertion.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing
    )
)]

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
    /// Folded in: counts of settlements, births, and cross-check anomalies. All
    /// zero when the transaction was read fine but held nothing this index
    /// recognizes — including a *reverted* one, which is retired here rather than
    /// retried, since a finalized failure is permanent.
    Applied {
        settlements: u64,
        births: u64,
        anomalies: u64,
    },
    /// Signature already folded in — no charge, no outcall. Also the answer when
    /// a concurrent ingest of the same signature reached the fold first: nothing
    /// is reserved ahead of the outcall, so the loser of that race pays for its
    /// own duplicate (`00 §3.2`) and the book still sees exactly one fold.
    Duplicate,
    /// Attached cycles below `INGEST_PRICE` — rejected before any work.
    Underpaid,
    /// Canister balance below `CYCLE_FLOOR` — refused to touch the reserve.
    LowBalance,
    /// No finalized transaction under consensus, or the reply could not be read.
    /// The payment is kept — `fund-then-fail` must not be cheaper than the work
    /// it triggers (`01-standards §Тесты 4`) — but the signature itself is left
    /// untouched and stays foldable by anyone, forever. That matters: a
    /// not-yet-finalized transaction is indistinguishable here from an unreadable
    /// one, so a signature retired on failed reads could be retired by an
    /// adversary who submits it *before* finality, for the price of the reads.
    /// A transaction that was read and simply reverted is not this: it is
    /// `Applied` with zero counts.
    NotFound,
    /// The transaction sits at or past `CUTOVER_SLOT` — it belongs to the next
    /// generation's book, not this one's (architecture §8). Not an error and not
    /// retriable here: the payment is kept (the outcall was made), but the
    /// signature stays free for the successor to fold.
    AfterCutover,
    /// The transaction settles an address with no private key whose birth this
    /// index has not recorded — an escrow it has never seen born. Folding it
    /// would credit the escrow **address** rather than the person who funded it,
    /// silently and forever (the law only adds). So nothing is folded and nothing
    /// is marked: the payment is kept, the signature stays free, and the fix is in
    /// the caller's hands — fold that escrow's birth (`create_escrow`
    /// transaction), then submit this signature again.
    ///
    /// Ordinary in exactly one place: a scope whose verdict signature opens more
    /// escrows than the game ever saw (`crown-games/conditional-funding` — a
    /// collection's contributions past the first). Before this answer existed,
    /// that case lost the donor's reputation permanently instead
    /// (`state::attributable`).
    UnknownBirth,
}

/// One enumerated birth, for the successor generation's seed (`get_births_page`).
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct BirthEntry {
    pub escrow: Vec<u8>,
    pub donor: Vec<u8>,
    pub slot: u64,
}

/// One enumerated book entry, for the successor generation (`get_book_page`).
/// The key is surfaced as its three parts rather than the raw 96 bytes: the
/// successor has to rebuild the key to rebuild the tree, and a layout it has to
/// infer is a layout that can be inferred wrong.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct BookEntry {
    pub chain: Vec<u8>,
    pub donor: Vec<u8>,
    pub recipient: Vec<u8>,
    pub reputation: Nat,
}

/// The capacity gauge (`get_state_stats`). All state is heap-resident and the
/// book only grows, so these numbers are what says how much of this generation
/// is left.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct StateStats {
    pub heap_bytes: u64,
    pub book_keys: u64,
    pub births: u64,
}

/// Largest `get_births_page` reply. Sized so a full page stays well inside the
/// query response limit (~80 B per entry on the wire → under 1 MiB).
const MAX_BIRTHS_PAGE: usize = 10_000;

/// Largest `get_book_page` reply. Half of `MAX_BIRTHS_PAGE` because an entry is
/// roughly twice the size (three 32-byte fields plus the value against an escrow
/// and a donor), so a full page lands in the same place inside the limit.
const MAX_BOOK_PAGE: usize = 5_000;

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

/// Re-publish the combined root after an upgrade. State is heap-only, so an
/// upgrade empties the book — but `certified_data` survives it, so without this
/// the canister would keep serving the *pre-upgrade* root while every witness
/// reconstructs to the empty one, and every certified read would fail
/// verification until the first ingest happened to land.
///
/// Mainnet is blackholed and never upgrades; devnet and testnet do, and a hook
/// that must exist before the freeze cannot be added after it.
#[ic_cdk::post_upgrade]
fn post_upgrade() {
    state::recertify();
}

/// Drop *every* ingress message. Nothing here is reachable by ingress by design,
/// so the boundary admits nothing — `accept_message` is never called.
///
/// Two paths are affected, and both must be closed. `ingest` is paid, but ingress
/// can never attach cycles, so a direct user `ingest` is always `Underpaid` while
/// still costing a decode of the (up to ~2 MB) argument. And every `query` here
/// can also be called as a *replicated* update, which the canister then executes
/// and pays for out of its own balance: ~6.5M cycles for the cheapest counter,
/// far more for a full `get_births_page`. Nothing gates that — the ingest gate
/// only sees `ingest` — so an anonymous caller could burn the balance down to
/// `CYCLE_FLOOR`, after which every paid ingest answers `LowBalance` and the book
/// stops for good. On a blackholed canister that is unfixable, so the boundary
/// fails closed: the exported hook itself is what refuses, since a canister with
/// no `inspect_message` accepts all ingress by default.
///
/// The paid path is unaffected: the relay reaches `ingest` by inter-canister
/// call, which is not inspected. Queries reached as queries are also not
/// inspected — free reads stay free.
#[ic_cdk::inspect_message]
fn inspect_message() {
    // No `accept_message()`, on any method: every ingress message is dropped.
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

    // An empty signature can never resolve to a transaction and is never marked
    // applied (invariant #1), so it would retry forever at full price. Free.
    if sig_bytes.is_empty() {
        return IngestResult::NotFound;
    }

    // Nothing is reserved ahead of the outcall, deliberately. Exactly-once is
    // `apply`'s synchronous `is_applied` check, not a reservation: N concurrent
    // ingests of one signature all fetch, and exactly one folds. A reservation
    // would save the losers an outcall each — work their own submitter paid for
    // (`00 §3.2`) — at the price of state committed before an `await`, which a
    // trapped callback rolls back *around*: the signature would then read as
    // "in flight" forever, indistinguishable from "already folded", on a canister
    // that cannot be patched. Cheap to add later; impossible to remove later.

    // Payment accepted before any outcall.
    ic_cdk::api::msg_cycles_accept(config::INGEST_PRICE);

    // A failed read keeps the payment (`01-standards §Тесты 4`) and changes no
    // state: the signature stays foldable by anyone. Retrying is the submitter's
    // own cost to bound (contract of the pusher, `07-build-plan.md`), and the
    // platform's own retries are bounded where its money actually leaves — the
    // relay's per-key cycle budget.
    let Some(reply) = rpc::fetch(signature).await else {
        return IngestResult::NotFound;
    };
    // Generation boundary (architecture §8). Generations are *summed*, not
    // replaced, so a settlement folded by both would double the reputation it
    // proves for the price of one ingest. Refusing past the boundary is what makes
    // the two books disjoint, and it must be enforced here rather than trusted to
    // the pusher: `ingest` is permissionless-once-paid, so "nobody submits old
    // slots to the old canister" is a convention an adversary is free to break.
    // No attempt is spent — the transaction is perfectly readable, it is simply
    // not ours, and the signature must stay untouched for the successor to fold.
    // Decided off the reply's own slot, before parsing: the boundary is about
    // whose mandate the transaction is, which does not depend on reading it.
    if config::CUTOVER_SLOT.is_some_and(|cutover| reply.slot >= cutover) {
        return IngestResult::AfterCutover;
    }
    match parse::parse(&reply) {
        Some(parse::Parsed::Executed(tx)) => match state::apply(sig_bytes, &tx) {
            state::Folded::Applied(a) => IngestResult::Applied {
                settlements: a.settlements,
                births: a.births,
                anomalies: a.anomalies,
            },
            // Already applied — a concurrent ingest of the same signature got
            // there first. Above all: not folded twice.
            state::Folded::Duplicate => IngestResult::Duplicate,
            // An escrow settled before this index saw it born. Nothing folded,
            // nothing marked — fold the birth and resubmit (`state::attributable`).
            state::Folded::UnknownBirth => IngestResult::UnknownBirth,
        },
        // Read fine; the chain says it reverted. Finalized and permanent, so it is
        // retired rather than left retriable: nothing is wrong with the read, and
        // a pusher that could not tell the two apart would re-fetch it forever at
        // full price.
        Some(parse::Parsed::Reverted) => {
            if state::retire(sig_bytes) {
                IngestResult::Applied {
                    settlements: 0,
                    births: 0,
                    anomalies: 0,
                }
            } else {
                IngestResult::Duplicate
            }
        }
        None => IngestResult::NotFound,
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

/// One page of recorded births in escrow order, starting strictly after
/// `start_after`. `None` means the cursor was not a 32-byte address; an empty
/// vector means the walk is done. The two are told apart deliberately — a
/// malformed cursor answered with "empty" would read as "done" and silently
/// truncate the successor's seed, which is exactly the misattribution this query
/// exists to prevent.
///
/// Sole consumer: the generational handoff (architecture §8). Free query, so the
/// seed costs nothing; it is auditable after the fact, since every entry can be
/// re-checked against this canister's certificate via `get_birth`.
#[ic_cdk::query]
fn get_births_page(start_after: Option<Vec<u8>>, limit: u32) -> Option<Vec<BirthEntry>> {
    let cursor = match start_after {
        Some(v) => Some(to32(v)?),
        None => None,
    };
    // Clamped to at least one so a zero `limit` cannot answer "empty" forever and
    // stall the walk short of the end.
    let limit = (limit as usize).clamp(1, MAX_BIRTHS_PAGE);
    Some(
        state::births_page(cursor, limit)
            .into_iter()
            .map(|(escrow, b)| BirthEntry {
                escrow: escrow.to_vec(),
                donor: b.donor.to_vec(),
                slot: b.slot,
            })
            .collect(),
    )
}

/// One page of the book in key order, starting strictly after `start_after`.
/// `None` means the cursor was not a 96-byte key; an empty vector means the walk
/// is done — told apart for `get_births_page`'s reason, a truncated walk that
/// reads as a finished one.
///
/// Consumer: the generational handoff (architecture §8). Free query, so absorbing
/// gen-1 costs nothing, and the copy is verifiable in one shot rather than entry
/// by entry: rebuild the tree from these pages, and the reconstructed root must
/// equal the one gen-1's certificate commits to (`get_certificate`). One check
/// for the whole book — against one paid outcall per transaction, had the
/// successor been made to re-read the chain instead.
///
/// The cursor is `chain ‖ donor ‖ recipient`, i.e. the three fields of the
/// previous page's last entry concatenated in that order.
#[ic_cdk::query]
fn get_book_page(start_after: Option<Vec<u8>>, limit: u32) -> Option<Vec<BookEntry>> {
    if start_after.as_ref().is_some_and(|c| c.len() != 96) {
        return None;
    }
    // Clamped to at least one for `get_births_page`'s reason: a zero `limit`
    // answering "empty" forever stalls the walk short of the end.
    let limit = (limit as usize).clamp(1, MAX_BOOK_PAGE);
    Some(
        state::book_page(start_after.as_deref(), limit)
            .into_iter()
            .map(|(chain, donor, recipient, reputation)| BookEntry {
                chain: chain.0.to_vec(),
                donor: donor.to_vec(),
                recipient: recipient.to_vec(),
                reputation: Nat::from(reputation),
            })
            .collect(),
    )
}

/// The capacity gauge: heap bytes, book keys, births. Free query.
///
/// The one reading that says how much of this generation is left. State is
/// heap-only and the book is monotone by law (§2), so the heap figure only ever
/// rises; when it reaches the canister's memory limit every ingest traps and the
/// book stops permanently. Blackholed means that limit cannot be raised and this
/// query cannot be added later — so the cutover is planned off these numbers, or
/// it is not planned at all.
#[ic_cdk::query]
fn get_state_stats() -> StateStats {
    let (heap_bytes, book_keys, births) = state::state_stats();
    StateStats {
        heap_bytes,
        book_keys,
        births,
    }
}

/// A 32-byte address from a blob argument, or `None` on wrong length.
fn to32(v: Vec<u8>) -> Option<[u8; 32]> {
    v.try_into().ok()
}

ic_cdk::export_candid!();
