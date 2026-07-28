//! Certified state: two keyed-Merkle trees (book, births) with a combined root
//! for `set_certified_data`. `crown-reduce` is the law of the book; the tree
//! mirrors the changed leaf so a key's value is provable by a witness.
//!
//! Book leaf: `(chain ‖ donor ‖ recipient) → u128le(gross)`.
//! Birth leaf: `escrow → donor ‖ u64le(slot)`. `gross` is not stored — attribution
//! reads only `donor`, and a game's escrow-address derivation already commits it.
//! `combined_root = fork_hash(labeled_hash("book", book_root),
//! labeled_hash("births", births_root))` — a key witness reconstructs straight
//! to it, so verification against the NNS root key is standard.

use crown_reduce::{reduce, Book, ChainId, Overflow, Settled};
use ic_certified_map::{
    fork, fork_hash, labeled, labeled_hash, AsHashTree, Hash, HashTree, RbTree,
};
use std::collections::{BTreeMap, BTreeSet};

/// Sub-tree labels of the combined certified root (domain separation).
const LABEL_BOOK: &[u8] = b"book";
const LABEL_BIRTHS: &[u8] = b"births";

/// A recorded escrow birth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Birth {
    pub donor: [u8; 32],
    pub slot: u64,
}

/// Book key bytes: `chain ‖ donor ‖ recipient`.
fn book_key(chain: ChainId, donor: [u8; 32], recipient: [u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(96);
    k.extend_from_slice(&chain.0);
    k.extend_from_slice(&donor);
    k.extend_from_slice(&recipient);
    k
}

/// The derived, certified state of the index.
pub struct Certified {
    book: Book,
    births: BTreeMap<[u8; 32], Birth>,
    book_tree: RbTree<Vec<u8>, Vec<u8>>,
    births_tree: RbTree<Vec<u8>, Vec<u8>>,
    /// Exactly-once: signatures already folded in. Every non-empty signature that
    /// reaches the fold is marked (whether or not it yielded a settlement); empty
    /// ones never are (non-negativity invariant #1).
    applied: BTreeSet<Vec<u8>>,
    /// Signatures with an ingest in flight (reserved before the outcall await, so
    /// concurrent same-signature ingests dedup even though `applied` is only set
    /// after the await). Cleared on success (`mark_applied`) or abort (`release`).
    in_flight: BTreeSet<Vec<u8>>,
    /// Diagnostic count of cross-check anomalies (a splitter event with no matching
    /// real transfer). Not certified — a health signal, folded in with the book so
    /// a re-ingest rebuilds it alongside everything else.
    anomalies: u64,
}

impl Default for Certified {
    fn default() -> Self {
        Self::new()
    }
}

impl Certified {
    pub fn new() -> Self {
        Self {
            book: Book::new(),
            births: BTreeMap::new(),
            book_tree: RbTree::new(),
            births_tree: RbTree::new(),
            applied: BTreeSet::new(),
            in_flight: BTreeSet::new(),
            anomalies: 0,
        }
    }

    /// Fold a settlement under the crown-reduce law and mirror the changed leaf.
    pub fn apply_settlement(&mut self, s: Settled) -> Result<(), Overflow> {
        reduce(&mut self.book, s)?;
        let value = self.book.get(&(s.chain, s.donor, s.recipient));
        self.book_tree.insert(
            book_key(s.chain, s.donor, s.recipient),
            value.to_le_bytes().to_vec(),
        );
        Ok(())
    }

    /// Record an escrow birth (idempotent by escrow address).
    pub fn record_birth(&mut self, escrow: [u8; 32], b: Birth) {
        let mut v = Vec::with_capacity(40);
        v.extend_from_slice(&b.donor);
        v.extend_from_slice(&b.slot.to_le_bytes());
        self.births_tree.insert(escrow.to_vec(), v);
        self.births.insert(escrow, b);
    }

    pub fn birth(&self, escrow: &[u8; 32]) -> Option<&Birth> {
        self.births.get(escrow)
    }

    /// Attribute a settlement's real donor (architecture §4): a `Settled` whose
    /// donor is a known escrow (has a birth) is credited to the escrow's funding
    /// donor; otherwise the event donor stands (a direct donation).
    ///
    /// Ordering invariant: an escrow's birth must be folded before its settlement,
    /// else the settlement is (mis)credited to the escrow address, not the donor.
    /// This holds by construction in slot order — a birth's `create_escrow` is
    /// always in an earlier slot than its `claim`/`release` — which is exactly the
    /// order the canonical from-chain recompute (architecture §8) folds in, so the
    /// recompute is always correct. A live canister that ingests a settlement
    /// before its birth misattributes *transiently*; the next generation's
    /// slot-ordered recompute is the source of truth and heals it. We deliberately
    /// keep the fold order-simple (no reverse index / deferral / re-attribution)
    /// and lean on that backstop rather than add a mechanism.
    pub fn attribute(&self, event: Settled) -> Settled {
        match self.births.get(&event.donor) {
            Some(b) => Settled {
                donor: b.donor,
                ..event
            },
            None => event,
        }
    }

    /// Whether a signature has already been folded in.
    pub fn is_applied(&self, signature: &[u8]) -> bool {
        self.applied.contains(signature)
    }

    /// Reserve a signature for an in-flight ingest, *synchronously* before the
    /// outcall await. `false` (reject) if it is empty, already applied, or already
    /// reserved — this is the atomic exactly-once guard against concurrent
    /// same-signature ingests each folding the settlement. Released by
    /// `mark_applied` (success) or `release` (abort).
    pub fn reserve(&mut self, signature: &[u8]) -> bool {
        if signature.is_empty() {
            return false;
        }
        if self.applied.contains(signature) || self.in_flight.contains(signature) {
            return false;
        }
        self.in_flight.insert(signature.to_vec());
        true
    }

    /// Drop an in-flight reservation whose ingest aborted (e.g. outcall NotFound),
    /// so the signature stays retriable.
    pub fn release(&mut self, signature: &[u8]) {
        self.in_flight.remove(signature);
    }

    /// Mark a non-empty signature applied (clearing any in-flight reservation).
    /// Empty signatures are never marked (exactly-once invariant #1). Returns
    /// `true` if newly inserted.
    pub fn mark_applied(&mut self, signature: Vec<u8>) -> bool {
        if signature.is_empty() {
            return false;
        }
        self.in_flight.remove(&signature);
        self.applied.insert(signature)
    }

    pub fn applied_count(&self) -> u64 {
        self.applied.len() as u64
    }

    /// Record cross-check anomalies from one transaction (saturating).
    pub fn add_anomalies(&mut self, n: u64) {
        self.anomalies = self.anomalies.saturating_add(n);
    }

    pub fn anomaly_count(&self) -> u64 {
        self.anomalies
    }

    /// Reputation at a key (0 if absent).
    pub fn reputation(&self, chain: ChainId, donor: [u8; 32], recipient: [u8; 32]) -> u128 {
        self.book.get(&(chain, donor, recipient))
    }

    /// The labeled hash of the book sub-tree — the leaf that `combined_root` and
    /// every book/birth witness must agree on. Centralized so a label/hashing
    /// change can't diverge a witness from the certified root (a witness prunes
    /// its sibling with the *same* value the root forks in).
    fn book_leaf(&self) -> Hash {
        labeled_hash(LABEL_BOOK, &self.book_tree.root_hash())
    }

    /// The labeled hash of the births sub-tree (see `book_leaf`).
    fn births_leaf(&self) -> Hash {
        labeled_hash(LABEL_BIRTHS, &self.births_tree.root_hash())
    }

    /// `combined_root` — the value handed to `set_certified_data`. A labeled
    /// fork of the two sub-trees, so a key witness reconstructs straight to it
    /// (standard IC verification against the NNS root key, no manual hashing).
    pub fn combined_root(&self) -> Hash {
        fork_hash(&self.book_leaf(), &self.births_leaf())
    }

    #[cfg(test)]
    pub fn book_root(&self) -> Hash {
        self.book_tree.root_hash()
    }

    #[cfg(test)]
    pub fn births_root(&self) -> Hash {
        self.births_tree.root_hash()
    }

    /// Witness for a book key: the book sub-witness under its label, forked with
    /// the pruned births sub-tree — reconstructs to `combined_root`.
    pub fn book_witness(
        &self,
        chain: ChainId,
        donor: [u8; 32],
        recipient: [u8; 32],
    ) -> HashTree<'_> {
        fork(
            labeled(
                LABEL_BOOK,
                self.book_tree.witness(&book_key(chain, donor, recipient)),
            ),
            HashTree::Pruned(self.births_leaf()),
        )
    }

    /// Witness for a birth: the pruned book sub-tree forked with the births
    /// sub-witness under its label — reconstructs to `combined_root`.
    pub fn birth_witness(&self, escrow: [u8; 32]) -> HashTree<'_> {
        fork(
            HashTree::Pruned(self.book_leaf()),
            labeled(LABEL_BIRTHS, self.births_tree.witness(&escrow)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settled(chain: u8, d: u8, r: u8, gross: u128) -> Settled {
        let mut c = [0u8; 32];
        c[0] = chain;
        Settled {
            chain: ChainId(c),
            donor: [d; 32],
            recipient: [r; 32],
            gross,
        }
    }

    #[test]
    fn fold_is_the_law_and_root_moves() {
        let mut s = Certified::new();
        let empty = s.combined_root();

        s.apply_settlement(settled(1, 1, 2, 100)).unwrap();
        s.apply_settlement(settled(1, 1, 2, 50)).unwrap(); // same key accumulates
        s.apply_settlement(settled(1, 3, 4, 7)).unwrap();

        // crown-reduce law held.
        let mut c = [0u8; 32];
        c[0] = 1;
        assert_eq!(s.reputation(ChainId([0; 32]), [0; 32], [0; 32]), 0); // absent key
        assert_eq!(s.reputation(ChainId(c), [7; 32], [8; 32]), 0); // absent key
        assert_eq!(s.reputation(ChainId(c), [1; 32], [2; 32]), 150);
        assert_eq!(s.reputation(ChainId(c), [3; 32], [4; 32]), 7);

        // Root is non-empty and changed from empty.
        assert_ne!(s.combined_root(), empty);
    }

    #[test]
    fn witness_reconstructs_to_root() {
        let mut s = Certified::new();
        s.apply_settlement(settled(1, 1, 2, 150)).unwrap();
        s.apply_settlement(settled(1, 3, 4, 7)).unwrap();

        let mut c = [0u8; 32];
        c[0] = 1;
        let w = s.book_witness(ChainId(c), [1; 32], [2; 32]);
        // The full (forked) witness reconstructs to exactly the combined root —
        // this is what the NNS certificate certifies.
        assert_eq!(w.reconstruct(), s.combined_root());
    }

    #[test]
    fn birth_is_recorded_and_roots_are_independent() {
        let mut s = Certified::new();
        let book_before = s.book_root();
        s.record_birth(
            [9; 32],
            Birth {
                donor: [1; 32],
                slot: 42,
            },
        );
        // Recording a birth does not touch the book root.
        assert_eq!(s.book_root(), book_before);
        assert_ne!(s.births_root(), Certified::new().births_root());
        let w = s.birth_witness([9; 32]);
        // The birth witness also reconstructs to the combined root.
        assert_eq!(w.reconstruct(), s.combined_root());
    }

    #[test]
    fn attribution_credits_the_escrow_donor() {
        let mut s = Certified::new();
        let escrow = [5u8; 32];
        let real_donor = [1u8; 32];
        s.record_birth(
            escrow,
            Birth {
                donor: real_donor,
                slot: 1,
            },
        );
        let mut c = [0u8; 32];
        c[0] = 1;
        // A settlement whose donor is the escrow → credited to the funding donor.
        let event = Settled {
            chain: ChainId(c),
            donor: escrow,
            recipient: [2; 32],
            gross: 485,
        };
        assert_eq!(s.attribute(event).donor, real_donor);
        // A direct donation (no birth) → donor stands.
        let direct = Settled {
            chain: ChainId(c),
            donor: [9; 32],
            recipient: [2; 32],
            gross: 10,
        };
        assert_eq!(s.attribute(direct).donor, [9; 32]);
    }

    #[test]
    fn exactly_once_and_empty_signature() {
        let mut s = Certified::new();
        assert!(!s.is_applied(b"sigA"));
        assert!(s.mark_applied(b"sigA".to_vec())); // newly applied
        assert!(s.is_applied(b"sigA"));
        assert!(!s.mark_applied(b"sigA".to_vec())); // already applied → not new

        // Empty signatures are never marked (invariant #1).
        assert!(!s.mark_applied(Vec::new()));
        assert!(!s.is_applied(b""));
        assert_eq!(s.applied_count(), 1);
    }

    #[test]
    fn reservation_dedups_concurrent_ingests() {
        let mut s = Certified::new();
        // First reservation of a fresh signature succeeds.
        assert!(s.reserve(b"sigA"));
        // A concurrent sibling (before the first marks applied) is rejected.
        assert!(!s.reserve(b"sigA"));
        // Empty signatures are never reserved.
        assert!(!s.reserve(b""));
        // Completing the ingest marks it applied and clears the reservation.
        assert!(s.mark_applied(b"sigA".to_vec()));
        assert!(s.is_applied(b"sigA"));
        // An already-applied signature cannot be reserved again.
        assert!(!s.reserve(b"sigA"));
    }

    #[test]
    fn release_keeps_an_aborted_signature_retriable() {
        let mut s = Certified::new();
        assert!(s.reserve(b"sigB"));
        // Abort (e.g. outcall NotFound) releases the reservation.
        s.release(b"sigB");
        // Not applied, and reservable again.
        assert!(!s.is_applied(b"sigB"));
        assert!(s.reserve(b"sigB"));
    }
}
