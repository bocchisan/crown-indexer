//! Canister state: the single `Certified` book/births tree plus a diagnostic
//! anomaly counter. The fold, exactly-once marking, and re-certification all
//! happen here so the update stays a thin gate + outcall + apply.
//!
//! State is in-memory (rebuilt by re-ingest, or by a fresh generation
//! recomputing from chain — architecture §8). No panics on the ingest path.

use crate::certified::{Birth, Certified};
use crate::config::chain_config;
use crate::recognize::{recognize, Tx};
use crown_reduce::{ChainId, Settled};
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

/// The outcome of folding one paid transaction.
#[derive(Clone, Copy, Debug)]
pub enum Folded {
    Applied(Applied),
    /// Already folded in — exactly-once refused this copy.
    Duplicate,
    /// The transaction settles an address with **no private key** whose birth
    /// this index has not recorded. Nothing is folded and nothing is marked:
    /// fold the birth, then submit this signature again ([`attributable`]).
    UnknownBirth,
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

/// One page of the book for the successor generation (architecture §8).
pub fn book_page(
    start_after: Option<&[u8]>,
    limit: usize,
) -> Vec<(ChainId, [u8; 32], [u8; 32], u128)> {
    STATE.with_borrow(|s| s.book_page(start_after, limit))
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

/// Whether a recognized settlement can be credited to the wallet that paid it.
///
/// **This is what enforces the ordering "birth before settlement" — nothing else
/// does.** `Certified::attribute` maps an escrow to its funding donor by looking
/// the escrow up in the births tree; a settlement folded before that birth lands
/// is credited to the escrow address instead, silently and **permanently** (the
/// law only adds — there is no debit and no re-attribution, architecture §5).
///
/// The test is the payer's own shape, and it needs no per-form knowledge. A
/// `Settled.donor` is either a transaction-level signer — an ed25519 public key,
/// therefore **on** the curve — or a PDA that signed through a CPI, therefore
/// **off** it (`crown_derive::solana_is_off_curve`, the same predicate the
/// address derivation itself applies). So:
///
/// - on-curve → a wallet paid; the event's donor is the donor. Folds.
/// - off-curve **with** a recorded birth (this index's, or one born in this very
///   transaction) → an escrow paid; attribution knows whose. Folds.
/// - off-curve **without** one → an address that can never hold a key and that
///   this index cannot attribute. Refused: the transaction is left unfolded, the
///   signature unmarked, and whoever wants the reputation folds the birth first
///   and resubmits.
///
/// Why refusing beats folding-to-the-escrow. The failure it replaces was the
/// worst kind the book has — silent, permanent, and reachable by anyone for the
/// price of one ingest: a scope's verdict signature opens **every** escrow that
/// derived its resolver, including ones the game never saw (a collection's second
/// contribution — `crown-games/conditional-funding`), so an adversary could
/// settle such an escrow and fold that settlement first, burning a real donor's
/// reputation for ≈$0.02. It is now a transient: refusal writes nothing, so the
/// same signature is still foldable by anyone, forever. Censorship is not the
/// mirror risk — clearing the refusal is permissionless too (fold the birth), so
/// no party can hold another's settlement hostage.
///
/// What it costs: a settlement from a keyless payer that is *not* one of our
/// escrows (a third-party program donating through the splitter with a PDA
/// authority) stops folding. That is deliberate — reputation under a key nobody
/// holds is not reputation, and the book's key is a wallet (`00 §2`).
fn attributable(s: &Certified, births_in_tx: &[([u8; 32], Birth)], ev: &Settled) -> bool {
    if !crown_derive::solana_is_off_curve(&ev.donor) {
        return true; // a wallet paid: the event's donor is the donor
    }
    s.birth(&ev.donor).is_some() || births_in_tx.iter().any(|(escrow, _)| *escrow == ev.donor)
}

/// Recognize, attribute, fold, record, mark applied, and re-certify — the whole
/// state mutation for one paid transaction. Births are recorded before
/// settlements so a same-tx settlement can attribute to a same-tx escrow; the
/// cross-tx ordering invariant (the birth is folded before its settlement) is
/// enforced by [`attributable`], which refuses the transaction outright rather
/// than let a settlement be credited to an address instead of a person.
///
/// `Duplicate` if the signature is already applied — and that check is the whole
/// of exactly-once: it happens here, inside the same synchronous mutation that
/// sets `applied`, so no two ingests of one signature can both fold however they
/// raced. Folding twice would double the reputation a settlement proves for the
/// price of one ingest.
///
/// Refusal is all-or-nothing, and deliberately so: a transaction carrying several
/// settlements (a batched claim) is folded whole or not at all, because a partial
/// fold would mark the signature applied and retire the settlements it skipped.
pub fn apply(signature: Vec<u8>, tx: &Tx) -> Folded {
    if STATE.with_borrow(|s| s.is_applied(&signature)) {
        return Folded::Duplicate;
    }
    let cfg = chain_config();
    let recognized = recognize(tx, &cfg);

    STATE.with_borrow_mut(|s| {
        // Before any mutation, including the anomaly counter: a refused
        // transaction must leave this canister exactly as it found it.
        if recognized
            .settlements
            .iter()
            .any(|ev| !attributable(s, &recognized.births, ev))
        {
            return Folded::UnknownBirth;
        }
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
        Folded::Applied(Applied {
            settlements,
            births,
            anomalies,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settled(donor: [u8; 32]) -> Settled {
        Settled {
            chain: ChainId([1u8; 32]),
            donor,
            recipient: [2u8; 32],
            gross: 500_000,
        }
    }

    /// A canonical PDA — off the curve by construction, which is exactly the
    /// shape of every escrow address.
    fn pda(salt: [u8; 32]) -> [u8; 32] {
        let (addr, _bump) = crown_derive::solana_pda_address([9u8; 32], &[b"escrow", &salt])
            .expect("a canonical bump exists");
        addr
    }

    /// An address a private key could exist for — the shape of every wallet.
    /// Asserted rather than assumed: roughly half of all byte patterns are off
    /// the curve, so a fixture picked by eye would quietly exercise the *other*
    /// branch and the test would pass for the wrong reason.
    fn wallet() -> [u8; 32] {
        let w = [1u8; 32];
        assert!(
            !crown_derive::solana_is_off_curve(&w),
            "this fixture must be a possible public key"
        );
        w
    }

    #[test]
    fn a_wallet_payer_needs_no_birth() {
        let s = Certified::new();
        assert!(attributable(&s, &[], &settled(wallet())));
    }

    /// The case the check exists for: an escrow settles and its birth is not in.
    /// Folding here would credit the escrow address forever, so it is refused —
    /// and the refusal clears the moment the birth lands.
    #[test]
    fn a_keyless_payer_without_a_birth_is_refused_until_the_birth_lands() {
        let mut s = Certified::new();
        let escrow = pda([42u8; 32]);
        assert!(!attributable(&s, &[], &settled(escrow)));

        s.record_birth(
            escrow,
            Birth {
                donor: [7u8; 32],
                slot: 1,
            },
        );
        assert!(attributable(&s, &[], &settled(escrow)));
    }

    /// A birth born in the same transaction counts: `apply` records births before
    /// settlements, so a create-and-claim batch must not refuse itself.
    #[test]
    fn a_birth_in_the_same_transaction_counts() {
        let s = Certified::new();
        let escrow = pda([1u8; 32]);
        let births = [(
            escrow,
            Birth {
                donor: [7u8; 32],
                slot: 5,
            },
        )];
        assert!(!attributable(&s, &[], &settled(escrow)));
        assert!(attributable(&s, &births, &settled(escrow)));
    }

    /// A recorded birth for *another* escrow proves nothing about this one.
    #[test]
    fn another_escrows_birth_does_not_admit_this_one() {
        let mut s = Certified::new();
        s.record_birth(
            pda([1u8; 32]),
            Birth {
                donor: [7u8; 32],
                slot: 1,
            },
        );
        assert!(!attributable(&s, &[], &settled(pda([2u8; 32]))));
    }
}
