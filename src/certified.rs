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
//!
//! The tree *is* the book: there is no second `crown_reduce::Book` beside it.
//! Every key would otherwise be stored twice — 144 B of BTreeMap on top of the
//! 216 B the tree needs anyway, 40% of the only structure that grows forever on
//! a canister whose heap ceiling cannot be raised (`docs/spec.md §Ёмкость`). The
//! law stays in one place regardless: `crown_reduce::fold_one` is the
//! `checked_add`, and this module only decides where the accumulated value is
//! kept.

use crown_reduce::{fold_one, ChainId, Overflow, Settled};
use ic_certified_map::{
    fork, fork_hash, labeled, labeled_hash, AsHashTree, Hash, HashTree, RbTree,
};
use std::collections::BTreeSet;

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

/// The accumulated `u128` under a book leaf, or `0` if the key is absent (an
/// absent key reads as zero — the law never subtracts, so there is nothing else
/// it could mean). A leaf of the wrong width cannot occur: `apply_settlement` is
/// the only writer and always writes 16 bytes.
fn leaf_value(leaf: Option<&Vec<u8>>) -> u128 {
    leaf.and_then(|v| <[u8; 16]>::try_from(v.as_slice()).ok())
        .map(u128::from_le_bytes)
        .unwrap_or(0)
}

/// A birth leaf: `donor(32) ‖ u64le(slot)`. `None` on any other width, which
/// `record_birth` — the only writer — cannot produce.
fn birth_leaf(leaf: &[u8]) -> Option<Birth> {
    let donor: [u8; 32] = leaf.get(..32)?.try_into().ok()?;
    let slot: [u8; 8] = leaf.get(32..40)?.try_into().ok()?;
    Some(Birth {
        donor,
        slot: u64::from_le_bytes(slot),
    })
}

/// The derived, certified state of the index.
pub struct Certified {
    /// The book: `(chain ‖ donor ‖ recipient) → u128le`. Sole storage — the
    /// certified tree and the map of accumulated values are the same structure.
    book_tree: RbTree<Vec<u8>, Vec<u8>>,
    /// Populated book keys. `RbTree` has no `len`, and the capacity gauge needs
    /// the count every ingest — counting the tree would be O(n) on the one
    /// number that exists to warn before the heap fills.
    book_keys: u64,
    /// Births: `escrow → donor ‖ u64le(slot)`. Sole storage, for the same reason
    /// the book has only one: the tree already holds the whole leaf, so a
    /// `BTreeMap` beside it stored every birth twice — on the second structure
    /// that grows forever and is never pruned (`08-deferred.md`), i.e. straight
    /// out of the generation's capacity (`docs/spec.md §Ёмкость`).
    births_tree: RbTree<Vec<u8>, Vec<u8>>,
    /// Recorded births — the other half of the capacity gauge (see `book_keys`).
    births_count: u64,
    /// Exactly-once: signatures already folded in. Every non-empty signature that
    /// reaches the fold is marked (whether or not it yielded a settlement); empty
    /// ones never are (non-negativity invariant #1).
    ///
    /// **This set is the whole of exactly-once.** `state::apply` tests it inside
    /// the same synchronous mutation that sets it, so two ingests of one
    /// signature cannot both fold, however they raced. Nothing reserves a
    /// signature ahead of the outcall: a reservation would only save the loser of
    /// such a race one outcall — paid by whoever submitted the duplicate (`00
    /// §3.2`) — while committing state before an `await` that a trapped callback
    /// then rolls back around, wedging the signature for the life of a canister
    /// nobody can fix.
    applied: BTreeSet<Vec<u8>>,
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
            book_tree: RbTree::new(),
            book_keys: 0,
            births_tree: RbTree::new(),
            births_count: 0,
            applied: BTreeSet::new(),
            anomalies: 0,
        }
    }

    /// Fold a settlement into the leaf under the crown-reduce law. Read the
    /// accumulated value, `fold_one`, write it back — the tree is the book, so
    /// there is no second structure to keep in step with this one.
    pub fn apply_settlement(&mut self, s: Settled) -> Result<(), Overflow> {
        let key = book_key(s.chain, s.donor, s.recipient);
        let leaf = self.book_tree.get(&key);
        // A key with no leaf is a new key. Counted here rather than derived,
        // because the tree cannot be asked its size (see `book_keys`).
        let is_new = leaf.is_none();
        // Overflow is refused *before* the write and before the count moves: a
        // partially applied fold is a book no recompute reproduces.
        let next = fold_one(leaf_value(leaf), s.gross)?;
        if is_new {
            self.book_keys = self.book_keys.saturating_add(1);
        }
        self.book_tree.insert(key, next.to_le_bytes().to_vec());
        Ok(())
    }

    /// Record an escrow birth (idempotent by escrow address).
    ///
    /// Re-recording an escrow overwrites the leaf and does **not** move the count:
    /// a birth is one escrow, and the same `create_escrow` re-read yields the same
    /// address. (On-chain it cannot even differ — the address is a PDA of the salt,
    /// so a second `create_escrow` for it fails.)
    pub fn record_birth(&mut self, escrow: [u8; 32], b: Birth) {
        let key = escrow.to_vec();
        if self.births_tree.get(&key).is_none() {
            self.births_count = self.births_count.saturating_add(1);
        }
        let mut v = Vec::with_capacity(40);
        v.extend_from_slice(&b.donor);
        v.extend_from_slice(&b.slot.to_le_bytes());
        self.births_tree.insert(key, v);
    }

    /// The recorded birth of `escrow`, read straight off the certified leaf — the
    /// same bytes the accompanying witness proves.
    pub fn birth(&self, escrow: &[u8; 32]) -> Option<Birth> {
        self.births_tree
            .get(escrow.as_slice())
            .and_then(|v| birth_leaf(v))
    }

    /// One page of recorded births in escrow-key order, starting strictly after
    /// `start_after` (or at the beginning). At most `limit` entries.
    ///
    /// Sole consumer: the generational handoff (architecture §8). A settlement is
    /// attributed to its escrow's funding donor by looking the escrow up in the
    /// births tree, so a generation that starts empty misattributes every escrow
    /// born before it — to the escrow address, permanently. `get_birth` cannot
    /// supply the seed: it answers only for an escrow you already know, and the
    /// successor by construction does not know them. Hence enumeration, and hence
    /// it must exist *before* the freeze — a blackholed generation grows no new
    /// query.
    ///
    /// Paged rather than whole so one reply always fits the response limit no
    /// matter how large the tree has grown; the caller walks pages by feeding the
    /// last escrow back. `RbTree::iter` is in-order, so a page boundary can neither
    /// skip nor repeat an entry.
    ///
    /// The cursor is a scan, not a seek: `RbTree` exposes no "iterate from key", so
    /// reaching page `k` walks past the `k · limit` entries before it. Deliberate,
    /// and the cost is bounded where it lands — this is a free `query` (one node,
    /// no consensus), its sole caller is the one-off handoff, and the boundary now
    /// refuses ingress entirely, so it cannot be turned into a paid-work amplifier
    /// (`lib.rs::inspect_message`). The alternative was keeping a second copy of
    /// every birth in a `BTreeMap` purely to get `range` — 140 B per birth, forever,
    /// on the structure that is never pruned and bounds the generation.
    pub fn births_page(
        &self,
        start_after: Option<[u8; 32]>,
        limit: usize,
    ) -> Vec<([u8; 32], Birth)> {
        self.births_tree
            .iter()
            // Exclusive lower bound: the cursor entry was returned by the previous
            // page, so resuming *at* it would repeat one birth per page boundary.
            .skip_while(|(k, _)| match &start_after {
                Some(cursor) => k.as_slice() <= cursor.as_slice(),
                None => false,
            })
            .filter_map(|(k, v)| {
                let escrow: [u8; 32] = k.as_slice().try_into().ok()?;
                Some((escrow, birth_leaf(v)?))
            })
            .take(limit)
            .collect()
    }

    /// Number of recorded births — one half of the capacity gauge (see `book_keys`).
    pub fn births_count(&self) -> u64 {
        self.births_count
    }

    /// One page of book entries in key order, starting strictly after
    /// `start_after` (or at the beginning). At most `limit` entries.
    ///
    /// Consumer: the generational handoff (architecture §8), the same one
    /// `births_page` serves, and it must exist before the freeze for the same
    /// reason — a blackholed generation grows no new query. `reputation` cannot
    /// supply it: it answers only for a `(chain, donor, recipient)` you already
    /// know, and the successor by construction knows none of them. Hence
    /// enumeration.
    ///
    /// What it buys over summing generations. Without it the successor starts
    /// empty and a reader adds gen-1 + gen-2, which is correct (the law is
    /// additive, §2) but makes every past generation a permanent liability: gen-1
    /// must stay funded and readable forever, since an unreadable gen-1 turns the
    /// sum into nothing, and after `n` cutovers a reader queries `n+1` canisters.
    /// With enumeration the successor can absorb gen-1 wholesale and verify the
    /// copy in one shot — rebuild the tree, compare the reconstructed root against
    /// gen-1's certificate — after which gen-1 is disposable. One BLS check for
    /// the whole book, against one paid outcall per transaction if the successor
    /// had to re-read the chain instead (`08-deferred.md §Переезд поколения`).
    ///
    /// Absorbing is *not* the same trust as recomputing, and the difference is the
    /// choice: a copy inherits gen-1's recognition verbatim, so it is right only
    /// when gen-1's book is right (capacity ran out, a factory was added). A book
    /// wrong by a bug is fixed only by folding the chain from scratch.
    ///
    /// Paging, cursor semantics and the O(n) walk are exactly `births_page`'s, for
    /// exactly its reasons — see there; the cursor is the 96-byte book key.
    pub fn book_page(
        &self,
        start_after: Option<&[u8]>,
        limit: usize,
    ) -> Vec<(ChainId, [u8; 32], [u8; 32], u128)> {
        self.book_tree
            .iter()
            .skip_while(|(k, _)| match start_after {
                Some(cursor) => k.as_slice() <= cursor,
                None => false,
            })
            .filter_map(|(k, v)| {
                let chain: [u8; 32] = k.get(..32)?.try_into().ok()?;
                let donor: [u8; 32] = k.get(32..64)?.try_into().ok()?;
                let recipient: [u8; 32] = k.get(64..96)?.try_into().ok()?;
                Some((ChainId(chain), donor, recipient, leaf_value(Some(v))))
            })
            .take(limit)
            .collect()
    }

    /// Number of populated book keys. With `births_count` and the heap size this
    /// is the capacity gauge: the book is monotone by law (§2) and never shrinks,
    /// so on a blackholed canister these numbers are the only warning that the
    /// generation is nearing its end and the cutover must be scheduled. A gauge
    /// added after the freeze is a gauge that does not exist.
    pub fn book_keys(&self) -> u64 {
        self.book_keys
    }

    /// Attribute a settlement's real donor (architecture §4): a `Settled` whose
    /// donor is a known escrow (has a birth) is credited to the escrow's funding
    /// donor; otherwise the event donor stands (a direct donation).
    ///
    /// Ordering requirement: an escrow's birth must be folded **before** its
    /// settlement, else the settlement is credited to the escrow address instead of
    /// the donor — and that is **permanent**, not transient. The law only adds
    /// (`crown-reduce`): there is no debit, no re-attribution, and a later birth
    /// does not reach back. Within this generation the wrong key stands forever.
    ///
    /// Only one of the two generation mechanisms (architecture §8) undoes it, and
    /// it is not the cheap one: a from-chain **recompute** folds in slot order and
    /// is correct by construction, but a **handoff** *sums* generations, so it
    /// carries the wrong key forward untouched. Misattribution therefore costs a
    /// full recompute of chain history — never assume it heals itself.
    ///
    /// **The ordering is enforced, not assumed** — `state::attributable` refuses
    /// the whole transaction when a settlement's payer is off-curve (so: a PDA,
    /// so: an escrow) and has no recorded birth. Nothing is folded, nothing is
    /// marked, and the same signature folds correctly once the birth is in. So
    /// this function is never reached with an escrow it does not know.
    ///
    /// It is written that way because the argument that used to stand here — "the
    /// settle path holds the order: a `Settled` from an escrow can only come from
    /// `claim(settle)`, which needs the scope's resolver signature, which exists
    /// only after a game materialized the scope on a birth proof" — is true only
    /// for a scope holding exactly one escrow. Read narrowly, it says a signature
    /// exists after *a* birth proof; the signature is per **scope**, and it opens
    /// every escrow that derived that resolver. Three cases fell outside it, and
    /// they are the reason the gate exists rather than a paragraph:
    /// - **A scope holding more than one escrow (`B=N`)**, which is in the first
    ///   release. `conditional-funding` materializes on the birth proof of the
    ///   *first* contribution; contributions 2..N join by deriving the resolver and
    ///   never touch the canister. Adversarially reachable, too: `claim` is
    ///   permissionless once the verdict signature is public, so anyone could
    ///   settle a stranger's contribution and fold that settlement first — burning
    ///   a real donor's reputation for the price of one ingest.
    /// - An escrow whose `resolver` is its creator's own key needs no game and no
    ///   birth proof; the creator can settle it themselves.
    /// - A form whose settle path is not signature-gated at all (`stream`'s
    ///   `release` is permissionless and schedule-gated). That is no longer a
    ///   reason to keep such a form out of the perimeter — the gate covers it —
    ///   but `stream` stays out for the reason that has not changed: it has no
    ///   consumer (`08-deferred.md`).
    ///
    /// The fold itself stays order-simple on purpose: no reverse index, no
    /// deferral, no re-attribution. The gate is what buys that simplicity — it
    /// turns the one ordering mistake this design cannot survive into a refusal
    /// anyone can clear.
    pub fn attribute(&self, event: Settled) -> Settled {
        match self.birth(&event.donor) {
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

    /// Mark a non-empty signature applied. Empty signatures are never marked
    /// (exactly-once invariant #1). Returns `true` if newly inserted.
    ///
    /// Applied is the *only* terminal state a signature has. There is no attempt
    /// budget and no poisoning: an unreadable read leaves the signature exactly as
    /// it found it, so a later ingest — once the transaction is finalized, or once
    /// the providers agree — still folds it. Bounding retries would bound the
    /// platform's own wasted spend, but the payer is not always the platform:
    /// `ingest` is permissionless-once-paid, so anyone may spend the budget of a
    /// signature they do not own, and a spent budget is refusal *forever* on a
    /// canister that cannot be patched. The loss it used to bound is bounded
    /// instead where the payer actually is — the relay's per-key cycle budget
    /// (`crown-relay/src/admit.rs`, non-negativity invariant #6), which is not
    /// frozen and can be retuned.
    pub fn mark_applied(&mut self, signature: Vec<u8>) -> bool {
        if signature.is_empty() {
            return false;
        }
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

    /// Reputation at a key (0 if absent) — read straight off the certified leaf,
    /// which is the same value the accompanying witness proves.
    pub fn reputation(&self, chain: ChainId, donor: [u8; 32], recipient: [u8; 32]) -> u128 {
        leaf_value(self.book_tree.get(&book_key(chain, donor, recipient)))
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
    fn births_page_walks_every_birth_exactly_once() {
        let mut s = Certified::new();
        for i in 0..10u8 {
            s.record_birth(
                [i; 32],
                Birth {
                    donor: [i.wrapping_add(100); 32],
                    slot: u64::from(i),
                },
            );
        }

        // Walk in pages of 3, feeding the last escrow back as the cursor — the
        // handoff's access pattern.
        let mut seen: Vec<[u8; 32]> = Vec::new();
        let mut cursor = None;
        loop {
            let page = s.births_page(cursor, 3);
            if page.is_empty() {
                break;
            }
            assert!(page.len() <= 3, "a page never exceeds its limit");
            cursor = page.last().map(|(k, _)| *k);
            seen.extend(page.into_iter().map(|(k, _)| k));
        }

        // Every birth, once, in key order: a page boundary neither skips nor
        // repeats — a skipped birth is a permanent misattribution in the successor.
        assert_eq!(seen.len(), 10);
        let mut expected: Vec<[u8; 32]> = (0..10u8).map(|i| [i; 32]).collect();
        expected.sort();
        assert_eq!(seen, expected);
        assert_eq!(s.births_count(), 10);
    }

    #[test]
    fn book_page_walks_every_key_exactly_once_and_carries_the_total() {
        let mut s = Certified::new();
        for i in 0..10u8 {
            s.apply_settlement(settled(1, i, i.wrapping_add(1), 100))
                .unwrap();
            // Same key twice: the page must carry the accumulated total, not the
            // last settlement — the successor folds what it is given, once.
            s.apply_settlement(settled(1, i, i.wrapping_add(1), 5))
                .unwrap();
        }

        let mut seen: Vec<(Vec<u8>, u128)> = Vec::new();
        let mut cursor: Option<Vec<u8>> = None;
        loop {
            let page = s.book_page(cursor.as_deref(), 3);
            if page.is_empty() {
                break;
            }
            assert!(page.len() <= 3, "a page never exceeds its limit");
            cursor = page.last().map(|(c, d, r, _)| book_key(*c, *d, *r));
            seen.extend(page.into_iter().map(|(c, d, r, v)| (book_key(c, d, r), v)));
        }

        // Every key, once, in key order. A skipped key is reputation the successor
        // never learns about; a repeated one is reputation invented out of a page
        // boundary — and the law has no way to take either back.
        assert_eq!(seen.len(), 10);
        assert_eq!(s.book_keys(), 10);
        assert!(seen.iter().all(|(_, v)| *v == 105));
        let mut keys: Vec<Vec<u8>> = seen.iter().map(|(k, _)| k.clone()).collect();
        let sorted = {
            let mut k = keys.clone();
            k.sort();
            k
        };
        assert_eq!(keys, sorted, "pages come in key order");
        keys.dedup();
        assert_eq!(keys.len(), 10);
    }

    /// The property the enumeration exists for, end to end: a successor that folds
    /// the pages it was handed lands on **the same root** gen-1's certificate
    /// commits to. That equality is the whole verification — one comparison for
    /// the entire state, instead of a witness per entry or a paid re-read of the
    /// chain per transaction (`08-deferred.md §Переезд поколения`).
    ///
    /// It works because a book leaf is the accumulated total and the law is a
    /// plain sum (§2): folding each total once reproduces the leaf exactly. The
    /// successor needs no knowledge of how gen-1 arrived there.
    ///
    /// **What the successor does NOT reproduce is gen-1's root, and that is a
    /// property of the tree rather than a defect in the pages.** `RbTree`'s hash
    /// is over the *structure* of the red-black tree, and the structure depends on
    /// the order keys were inserted in. Gen-1 inserts in ingest order — whatever
    /// order transactions arrived — while the pages enumerate in **key** order, so
    /// a replay builds a differently-shaped tree over identical content and
    /// commits a different root. Measured on the stand at `P8`: same 12 keys, same
    /// values, three insertion orders, three roots.
    ///
    /// The earlier version of this test asserted root equality and passed — but
    /// only because its keys (`[i; 32]`, ascending) happened to be inserted in key
    /// order, so the two shapes coincided. It could not have gone red at the event
    /// it existed for, which is the one thing a test must be able to do.
    ///
    /// So the property the handover actually rests on is the one asserted here:
    /// **a canonical replay normalizes.** Whatever order the predecessor grew in,
    /// replaying its pages produces the *same* successor — which is what makes the
    /// handover verifiable by a third party, who replays the same pages and gets
    /// the same root as the deployed gen-2. Acceptance at cutover is that equality
    /// plus the key-value sets, not equality with gen-1's own root
    /// (`crown-spec/docs/09-mainnet-runbook.md`).
    #[test]
    fn a_canonical_replay_of_the_pages_normalizes_whatever_order_gen1_grew_in() {
        // Two predecessors with identical content, grown in different orders —
        // exactly what "ingest order is arbitrary" means in production.
        let order_a: [u8; 7] = [0, 1, 2, 3, 4, 5, 6];
        let order_b: [u8; 7] = [4, 0, 6, 2, 5, 1, 3];
        let grow = |order: &[u8]| {
            let mut g = Certified::new();
            for &i in order {
                g.apply_settlement(settled(1, i, i.wrapping_add(1), 100 + u128::from(i)))
                    .unwrap();
                g.apply_settlement(settled(2, i, i.wrapping_add(1), 9))
                    .unwrap();
                g.record_birth(
                    [i; 32],
                    Birth {
                        donor: [i.wrapping_add(100); 32],
                        slot: u64::from(i),
                    },
                );
            }
            g
        };
        let gen1a = grow(&order_a);
        let gen1b = grow(&order_b);

        // The same content really is the same content…
        assert_eq!(gen1a.book_keys(), gen1b.book_keys());
        assert_eq!(gen1a.births_count(), gen1b.births_count());
        assert_eq!(gen1a.book_page(None, 1_000), gen1b.book_page(None, 1_000));
        assert_eq!(
            gen1a.births_page(None, 1_000),
            gen1b.births_page(None, 1_000)
        );

        // …and the replay of that content is one successor, not two.
        let replay = |src: &Certified| {
            let mut g = Certified::new();
            for (chain, donor, recipient, gross) in src.book_page(None, 1_000) {
                g.apply_settlement(Settled {
                    chain,
                    donor,
                    recipient,
                    gross,
                })
                .unwrap();
            }
            for (escrow, birth) in src.births_page(None, 1_000) {
                g.record_birth(escrow, birth);
            }
            g
        };
        let gen2a = replay(&gen1a);
        let gen2b = replay(&gen1b);

        assert_eq!(
            gen2a.combined_root(),
            gen2b.combined_root(),
            "a canonical replay must not depend on how the predecessor grew — without \
             this the successor is unverifiable by anyone who did not watch the ingests"
        );
        assert_eq!(gen2a.book_keys(), gen1a.book_keys());
        assert_eq!(gen2a.births_count(), gen1a.births_count());
        assert_eq!(gen2a.book_page(None, 1_000), gen1a.book_page(None, 1_000));
        assert_eq!(
            gen2a.births_page(None, 1_000),
            gen1a.births_page(None, 1_000)
        );
    }

    /// The count is kept, not derived (`RbTree` has no `len`), so re-recording an
    /// escrow must not inflate it — the gauge it feeds is what schedules the
    /// cutover, and an over-count would schedule it early on a canister that
    /// cannot be asked again.
    #[test]
    fn re_recording_a_birth_overwrites_without_double_counting() {
        let mut s = Certified::new();
        let escrow = [3u8; 32];
        s.record_birth(
            escrow,
            Birth {
                donor: [1; 32],
                slot: 10,
            },
        );
        assert_eq!(s.births_count(), 1);
        // Same escrow again (a re-ingest of the same `create_escrow`).
        s.record_birth(
            escrow,
            Birth {
                donor: [1; 32],
                slot: 10,
            },
        );
        assert_eq!(s.births_count(), 1, "one escrow is one birth");
        assert_eq!(s.births_page(None, 10).len(), 1);
        // A different escrow does move it.
        s.record_birth(
            [4u8; 32],
            Birth {
                donor: [2; 32],
                slot: 11,
            },
        );
        assert_eq!(s.births_count(), 2);
    }

    /// The birth is read back off the certified leaf — the same bytes the witness
    /// proves. This is what makes the removed `BTreeMap` redundant rather than
    /// merely duplicated: there was never a second source of truth to lose.
    #[test]
    fn a_birth_reads_back_from_the_certified_leaf() {
        let mut s = Certified::new();
        let b = Birth {
            donor: [8; 32],
            slot: 4_242,
        };
        s.record_birth([6u8; 32], b);
        assert_eq!(s.birth(&[6u8; 32]), Some(b));
        assert_eq!(s.birth(&[7u8; 32]), None);
    }

    #[test]
    fn births_page_carries_the_donor_the_successor_needs() {
        let mut s = Certified::new();
        s.record_birth(
            [4; 32],
            Birth {
                donor: [7; 32],
                slot: 99,
            },
        );
        let page = s.births_page(None, 10);
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].0, [4u8; 32]);
        // Donor and slot survive the page — the seed is exactly what `attribute`
        // reads, so a seeded successor attributes an escrow born before it.
        assert_eq!(page[0].1.donor, [7u8; 32]);
        assert_eq!(page[0].1.slot, 99);
    }

    /// Past the cutover the transaction is readable, simply not ours: the ingest
    /// touches no state at all, so the signature stays free and the successor
    /// generation is free to fold it.
    #[test]
    fn a_signature_past_the_cutover_is_left_untouched() {
        let s = Certified::new();
        assert!(!s.is_applied(b"sigC"));
    }

    #[test]
    fn book_keys_counts_distinct_keys_not_settlements() {
        let mut s = Certified::new();
        assert_eq!(s.book_keys(), 0);
        s.apply_settlement(settled(1, 1, 2, 100)).unwrap();
        s.apply_settlement(settled(1, 1, 2, 50)).unwrap(); // same key accumulates
        assert_eq!(s.book_keys(), 1, "the gauge measures stored keys");
        s.apply_settlement(settled(1, 3, 4, 7)).unwrap();
        assert_eq!(s.book_keys(), 2);
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

    /// Exactly-once rests on `applied` and on nothing else: whichever ingest of a
    /// signature reaches the fold first marks it, and every later one — however it
    /// raced — is refused. This is the property the removed reservation was
    /// *believed* to provide and never did (`state::apply`).
    #[test]
    fn the_applied_set_is_the_whole_of_exactly_once() {
        let mut s = Certified::new();
        assert!(s.mark_applied(b"sigA".to_vec())); // the winner folds
        assert!(!s.mark_applied(b"sigA".to_vec())); // every sibling is refused
        assert!(!s.mark_applied(b"sigA".to_vec()));
        assert!(s.is_applied(b"sigA"));
        assert_eq!(s.applied_count(), 1, "one fold, however many callers raced");
    }

    /// An unreadable ingest leaves the signature exactly as it found it, however
    /// many times it fails. This is the property that makes the book
    /// uncensorable: a signature nobody could read yet — because it is not
    /// finalized, or because the providers had not caught up — is still foldable
    /// by the next caller. Bounding it would let anyone retire a signature they
    /// do not own, permanently, on a canister nobody can patch.
    #[test]
    fn a_signature_that_could_not_be_read_stays_foldable_forever() {
        let mut s = Certified::new();
        // No amount of failed reads is recorded anywhere: `applied` is the only
        // terminal state, and only a real fold sets it.
        assert!(!s.is_applied(b"sigB"));
        assert_eq!(s.applied_count(), 0);
        // The read finally lands — the signature folds normally.
        assert!(s.mark_applied(b"sigB".to_vec()));
        assert!(s.is_applied(b"sigB"));
        assert_eq!(s.applied_count(), 1);
    }
}
