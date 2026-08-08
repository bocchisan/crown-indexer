//! Recognition: a finalized Solana transaction → recognized `Settled`
//! settlements and escrow births (spec §Распознавание, architecture §4/§5).
//!
//! Two recognition roots and nothing else counts:
//! - **Settlement** — a `Settled` event-CPI from the *pinned* splitter, whose
//!   `gross`/mint/authority is cross-checked against an executed `TransferChecked`
//!   in the same transaction. A foreign program's event, or an event with no
//!   matching real transfer, is not reputation (it is an anomaly / ignored).
//! - **Birth** — a `create_escrow` of a *pinned* factory, whose escrow account is
//!   re-derived as `find_program_address([b"escrow", salt], factory)`; a spoofed
//!   escrow that isn't a genuine factory PDA is dropped.
//!
//! Donor is left as the on-chain authority here; `Certified::attribute` maps a
//! known escrow to its funding donor (§4). This module is pure — no I/O, no
//! panics, no `unwrap` (it runs on the paid ingest path). The RPC/JSON → `Tx`
//! mapping lives in the ingest layer; the `MIN_GROSS` reputation floor is applied
//! here via `ChainConfig` — a sub-floor settlement is dust, not reputation.

use crate::certified::Birth;
use crown_reduce::{Address, ChainId, Settled};
use sha2::{Digest, Sha256};

/// Anchor's `emit_cpi!` self-CPI tag (`EVENT_IX_TAG` little-endian): the first 8
/// bytes of an event-CPI instruction, before the event discriminator.
const EVENT_IX_TAG_LE: [u8; 8] = [0xe4, 0x45, 0xa5, 0x2e, 0x51, 0xcb, 0x9a, 0x1d];

/// SPL Token `TransferChecked` instruction tag (data byte 0).
const TRANSFER_CHECKED_TAG: u8 = 12;

/// SPL Token program id (`Tokenkeg…`). The cross-check reads real token movement
/// through the canonical token program; a Solana constant, not a config value.
const TOKEN_PROGRAM_ID: Address = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];

/// A flattened instruction from a parsed transaction — top-level or inner (CPI),
/// with resolved account pubkeys and decoded instruction data.
#[derive(Clone, Debug)]
pub struct Instr {
    pub program: Address,
    pub accounts: Vec<Address>,
    pub data: Vec<u8>,
}

/// The recognition-relevant view of one finalized transaction.
#[derive(Clone, Debug)]
pub struct Tx {
    /// Instructions in execution order (top-level and inner, flattened).
    pub instrs: Vec<Instr>,
    /// Slot of the transaction (from the transaction meta), stamped into births.
    pub slot: u64,
}

/// Per-chain recognition roots (from `config/`): the pinned splitter, the USDC
/// mint, the pinned factories whose `create_escrow` yields a birth, and the
/// reputation dust floor.
#[derive(Clone, Debug)]
pub struct ChainConfig {
    pub chain: ChainId,
    pub splitter: Address,
    pub usdc: Address,
    pub factories: Vec<Address>,
    /// Reputation dust floor (cost.md §6, config `MIN_GROSS`): a settlement below
    /// this `gross` is not reputation — it is dropped as dust before folding.
    pub min_gross: u128,
}

/// What one transaction contributes: settlements to fold, births to record, and
/// a count of cross-check anomalies (event without a matching real transfer).
#[derive(Clone, Debug, Default)]
pub struct Recognized {
    pub settlements: Vec<Settled>,
    pub births: Vec<(Address, Birth)>,
    pub anomalies: u64,
}

/// Anchor discriminator: first 8 bytes of `sha256("<namespace>:<name>")`
/// (`global:` for instructions, `event:` for events).
fn anchor_disc(namespace: &str, name: &str) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(namespace.as_bytes());
    h.update(b":");
    h.update(name.as_bytes());
    let full: [u8; 32] = h.finalize().into();
    let mut d = [0u8; 8];
    d.copy_from_slice(full.get(..8).unwrap_or(&[0u8; 8]));
    d
}

/// Read a 32-byte field at `off`, or `None` if out of range.
fn arr32(d: &[u8], off: usize) -> Option<Address> {
    let end = off.checked_add(32)?;
    d.get(off..end)?.try_into().ok()
}

/// Read a little-endian `u64` at `off`, or `None` if out of range.
fn u64le(d: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    Some(u64::from_le_bytes(d.get(off..end)?.try_into().ok()?))
}

/// A cross-check candidate: one executed `TransferChecked`.
struct Transfer {
    mint: Address,
    amount: u64,
    authority: Address,
}

/// Consume the first not-yet-used transfer that cross-checks a settlement's
/// claim — same `mint` (= usdc), `amount` (= gross), and `authority` (= donor).
/// A consumed slot is emptied so no transfer backs two events; returns whether a
/// match was found. Reputation can never exceed really-moved money.
///
/// The transfer's *destination* is deliberately not matched, because it cannot
/// be: the instruction carries the destination **token account**, while the event
/// carries that account's **owner** (`recipient_ata.owner`), and the splitter
/// accepts any token account of the mint — not only the canonical ATA — so the one
/// is not derivable from the other. Closing the gap would take a `getAccountInfo`
/// per settlement, and this repo reads no account state at all. What makes that
/// safe is upstream of this check:
/// a `Settled` is only considered at all when the emitting program is the pinned
/// splitter, and the splitter emits it exclusively after its own
/// `transfer_checked` — so the event already implies a real transfer, and this
/// cross-check is the second lock on a door with one key, not the only one.
fn take_matching(transfers: &mut [Option<Transfer>], usdc: Address, s: &Settled) -> bool {
    for slot in transfers.iter_mut() {
        let Some(t) = slot else { continue };
        if t.mint == usdc && u128::from(t.amount) == s.gross && t.authority == s.donor {
            *slot = None;
            return true;
        }
    }
    false
}

/// All `TransferChecked` instructions to the SPL token program, decoded for the
/// cross-check (accounts `[source, mint, destination, authority]`).
fn collect_transfers(tx: &Tx) -> Vec<Transfer> {
    tx.instrs
        .iter()
        .filter_map(|i| {
            if i.program != TOKEN_PROGRAM_ID || i.data.first() != Some(&TRANSFER_CHECKED_TAG) {
                return None;
            }
            let amount = u64le(&i.data, 1)?;
            let mint = *i.accounts.get(1)?;
            let authority = *i.accounts.get(3)?;
            Some(Transfer {
                mint,
                amount,
                authority,
            })
        })
        .collect()
}

/// Decode a `Settled` event-CPI (tag ‖ disc ‖ borsh `donor,recipient,gross`).
fn decode_settled(d: &[u8], disc: &[u8; 8], chain: ChainId) -> Option<Settled> {
    if d.get(0..8) != Some(EVENT_IX_TAG_LE.as_slice()) || d.get(8..16) != Some(disc.as_slice()) {
        return None;
    }
    let donor = arr32(d, 16)?;
    let recipient = arr32(d, 48)?;
    let gross = u64le(d, 80)?;
    Some(Settled {
        chain,
        donor,
        recipient,
        gross: u128::from(gross),
    })
}

/// Decode a `create_escrow` birth: `donor` = account 0, `escrow` = account 1,
/// `salt` = the first instruction arg; the escrow is re-derived and must equal
/// `find_program_address([b"escrow", salt], factory)`.
///
/// Only the shape-independent fields are read: `donor`/`escrow` (fixed account
/// slots) and `salt` (always the first arg, at `8..40`). `gross` is deliberately
/// **not** read — its offset differs per escrow form (e.g. `two-outcome` puts it
/// at `72`, `stream` has no such field there), so a fixed offset would record
/// garbage for a non-`two-outcome` factory; and the birth needs no `gross` anyway
/// (attribution reads only `donor`, and a game's address derivation commits `gross`
/// via the salt). The PDA re-derivation from `salt` is the genuine-factory gate.
fn decode_birth(instr: &Instr, disc: &[u8; 8], slot: u64) -> Option<(Address, Birth)> {
    let d = &instr.data;
    if d.get(0..8) != Some(disc.as_slice()) {
        return None;
    }
    let donor = *instr.accounts.first()?;
    let escrow = *instr.accounts.get(1)?;
    let salt = arr32(d, 8)?; // salt @ 8..40 — the first arg of every form's create_escrow
    let (pda, _bump) = crown_derive::solana_pda_address(instr.program, &[b"escrow", &salt])?;
    if pda != escrow {
        return None; // spoofed: not a genuine factory PDA
    }
    Some((escrow, Birth { donor, slot }))
}

/// Recognize all settlements and births in one finalized transaction.
///
/// Each pinned-splitter `Settled` is paired with a distinct unconsumed
/// `TransferChecked` matching its `(mint = usdc, amount = gross, authority =
/// donor)`; unpaired events count as anomalies, never as reputation.
pub fn recognize(tx: &Tx, cfg: &ChainConfig) -> Recognized {
    let settled_disc = anchor_disc("event", "Settled");
    let create_disc = anchor_disc("global", "create_escrow");
    let mut transfers: Vec<Option<Transfer>> =
        collect_transfers(tx).into_iter().map(Some).collect();
    let mut out = Recognized::default();

    for instr in &tx.instrs {
        // Settlement: a Settled event-CPI from the pinned splitter.
        if instr.program == cfg.splitter {
            if let Some(s) = decode_settled(&instr.data, &settled_disc, cfg.chain) {
                if s.gross < cfg.min_gross {
                    continue; // dust: below the reputation floor (cost.md §6)
                }
                if take_matching(&mut transfers, cfg.usdc, &s) {
                    out.settlements.push(s);
                } else {
                    out.anomalies = out.anomalies.saturating_add(1);
                }
                continue;
            }
        }
        // Birth: a create_escrow of a pinned factory.
        if cfg.factories.contains(&instr.program) {
            if let Some(birth) = decode_birth(instr, &create_disc, tx.slot) {
                out.births.push(birth);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPLITTER: Address = [1u8; 32];
    const USDC: Address = [2u8; 32];
    const FACTORY: Address = [3u8; 32];
    const OTHER_PROGRAM: Address = [9u8; 32];

    fn cfg() -> ChainConfig {
        ChainConfig {
            chain: ChainId([7u8; 32]),
            splitter: SPLITTER,
            usdc: USDC,
            factories: vec![FACTORY],
            min_gross: 0, // most tests use tiny gross; the floor has its own test
        }
    }

    /// Build a Settled event-CPI instruction (data = tag ‖ disc ‖ borsh).
    fn settled_event(program: Address, donor: Address, recipient: Address, gross: u64) -> Instr {
        let mut data = Vec::new();
        data.extend_from_slice(&EVENT_IX_TAG_LE);
        data.extend_from_slice(&anchor_disc("event", "Settled"));
        data.extend_from_slice(&donor);
        data.extend_from_slice(&recipient);
        data.extend_from_slice(&gross.to_le_bytes());
        Instr {
            program,
            accounts: vec![],
            data,
        }
    }

    /// Build a TransferChecked instruction (accounts [source, mint, dest, auth]).
    fn transfer_checked(mint: Address, amount: u64, authority: Address) -> Instr {
        let mut data = vec![TRANSFER_CHECKED_TAG];
        data.extend_from_slice(&amount.to_le_bytes());
        data.push(6); // decimals
        Instr {
            program: TOKEN_PROGRAM_ID,
            accounts: vec![[0u8; 32], mint, [0u8; 32], authority],
            data,
        }
    }

    /// Build a create_escrow instruction for `factory` funding `escrow`.
    fn create_escrow(
        factory: Address,
        donor: Address,
        escrow: Address,
        salt: [u8; 32],
        gross: u64,
    ) -> Instr {
        let mut data = Vec::new();
        data.extend_from_slice(&anchor_disc("global", "create_escrow"));
        data.extend_from_slice(&salt); // 8..40
        data.extend_from_slice(&[0u8; 32]); // recipient 40..72
        data.extend_from_slice(&gross.to_le_bytes()); // 72..80
        Instr {
            program: factory,
            accounts: vec![donor, escrow],
            data,
        }
    }

    #[test]
    fn settlement_is_recognized_and_cross_checked() {
        let donor = [10u8; 32];
        let recipient = [11u8; 32];
        let tx = Tx {
            slot: 100,
            instrs: vec![
                transfer_checked(USDC, 500, donor),
                settled_event(SPLITTER, donor, recipient, 500),
            ],
        };
        let r = recognize(&tx, &cfg());
        assert_eq!(r.settlements.len(), 1);
        assert_eq!(r.anomalies, 0);
        let s = r.settlements[0];
        assert_eq!(s.donor, donor);
        assert_eq!(s.recipient, recipient);
        assert_eq!(s.gross, 500);
        assert_eq!(s.chain, ChainId([7u8; 32]));
    }

    #[test]
    fn foreign_settled_event_is_not_reputation() {
        // Same event bytes, but emitted by a program that is not the splitter.
        let tx = Tx {
            slot: 1,
            instrs: vec![
                transfer_checked(USDC, 500, [10u8; 32]),
                settled_event(OTHER_PROGRAM, [10u8; 32], [11u8; 32], 500),
            ],
        };
        let r = recognize(&tx, &cfg());
        assert!(r.settlements.is_empty());
        assert_eq!(r.anomalies, 0); // not the splitter → not even considered
    }

    #[test]
    fn cross_check_mismatch_is_an_anomaly() {
        let donor = [10u8; 32];
        // Event says 500, but the only transfer moved 499 — reputation must not
        // exceed really-moved money.
        let tx = Tx {
            slot: 1,
            instrs: vec![
                transfer_checked(USDC, 499, donor),
                settled_event(SPLITTER, donor, [11u8; 32], 500),
            ],
        };
        let r = recognize(&tx, &cfg());
        assert!(r.settlements.is_empty());
        assert_eq!(r.anomalies, 1);

        // Wrong mint is equally an anomaly.
        let tx = Tx {
            slot: 1,
            instrs: vec![
                transfer_checked([99u8; 32], 500, donor),
                settled_event(SPLITTER, donor, [11u8; 32], 500),
            ],
        };
        assert_eq!(recognize(&tx, &cfg()).anomalies, 1);
    }

    #[test]
    fn two_settlements_need_two_distinct_transfers() {
        let donor = [10u8; 32];
        // One transfer, two identical events → one is real, one is unpaired.
        let tx = Tx {
            slot: 1,
            instrs: vec![
                transfer_checked(USDC, 500, donor),
                settled_event(SPLITTER, donor, [11u8; 32], 500),
                settled_event(SPLITTER, donor, [11u8; 32], 500),
            ],
        };
        let r = recognize(&tx, &cfg());
        assert_eq!(r.settlements.len(), 1);
        assert_eq!(r.anomalies, 1);

        // With two transfers, both settlements are cross-checked.
        let tx = Tx {
            slot: 1,
            instrs: vec![
                transfer_checked(USDC, 500, donor),
                transfer_checked(USDC, 500, donor),
                settled_event(SPLITTER, donor, [11u8; 32], 500),
                settled_event(SPLITTER, donor, [11u8; 32], 500),
            ],
        };
        let r = recognize(&tx, &cfg());
        assert_eq!(r.settlements.len(), 2);
        assert_eq!(r.anomalies, 0);
    }

    #[test]
    fn a_sub_floor_settlement_is_dust_not_reputation() {
        let donor = [10u8; 32];
        let floored = ChainConfig {
            min_gross: 200_000,
            ..cfg()
        };
        // A real transfer backs it, but the amount is below the floor → dropped as
        // dust: not reputation, and not an anomaly (it is a genuine sub-floor move).
        let tx = Tx {
            slot: 1,
            instrs: vec![
                transfer_checked(USDC, 199_999, donor),
                settled_event(SPLITTER, donor, [11u8; 32], 199_999),
            ],
        };
        let r = recognize(&tx, &floored);
        assert!(r.settlements.is_empty());
        assert_eq!(r.anomalies, 0);

        // Exactly at the floor counts (inclusive).
        let tx = Tx {
            slot: 1,
            instrs: vec![
                transfer_checked(USDC, 200_000, donor),
                settled_event(SPLITTER, donor, [11u8; 32], 200_000),
            ],
        };
        assert_eq!(recognize(&tx, &floored).settlements.len(), 1);
    }

    #[test]
    fn birth_is_recognized_only_for_a_genuine_factory_pda() {
        let donor = [10u8; 32];
        let salt = [42u8; 32];
        // The genuine escrow PDA the factory would derive for this salt.
        let (escrow, _bump) =
            crown_derive::solana_pda_address(FACTORY, &[b"escrow", &salt]).unwrap();
        let tx = Tx {
            slot: 777,
            instrs: vec![create_escrow(FACTORY, donor, escrow, salt, 1_000)],
        };
        let r = recognize(&tx, &cfg());
        assert_eq!(r.births.len(), 1);
        let (esc, birth) = r.births[0];
        assert_eq!(esc, escrow);
        assert_eq!(birth.donor, donor);
        assert_eq!(birth.slot, 777);

        // A spoofed escrow account (not the derived PDA) is dropped.
        let spoof = Tx {
            slot: 1,
            instrs: vec![create_escrow(FACTORY, donor, [123u8; 32], salt, 1_000)],
        };
        assert!(recognize(&spoof, &cfg()).births.is_empty());

        // create_escrow from an unpinned program is not a birth.
        let foreign = Tx {
            slot: 1,
            instrs: vec![create_escrow(OTHER_PROGRAM, donor, escrow, salt, 1_000)],
        };
        assert!(recognize(&foreign, &cfg()).births.is_empty());
    }

    /// One paid read, many recognized events — the property the whole cost model
    /// rests on and nothing checked.
    ///
    /// `INGEST_PRICE` buys one `getTransaction`, not one escrow: the fetch is per
    /// **transaction**, so a client that puts `B` births (or `K` settlements) in a
    /// single Solana transaction divides the per-settlement cost of that term by
    /// `B` (by `K`). That is exactly what the `g/K` term of `cost.md §2` means, and
    /// it is a property of *this* function — it walks every instruction and keeps
    /// every event it recognizes, with no notion of "the" birth or "the"
    /// settlement.
    ///
    /// Pinned as a test because the batching lives entirely in the client: nothing
    /// here would fail loudly if recognition quietly started keeping only the first
    /// event, and the model would go on claiming an amortization that no longer
    /// happened.
    #[test]
    fn one_transaction_carries_a_batch_of_births_and_settlements() {
        let donors: [Address; 3] = [[10u8; 32], [11u8; 32], [12u8; 32]];
        let recipient = [20u8; 32];
        let mut instrs = Vec::new();
        let mut escrows = Vec::new();

        // Three `create_escrow` of the pinned factory, one transaction.
        for (i, donor) in donors.iter().enumerate() {
            let salt = [i as u8 + 1; 32];
            let (escrow, _) =
                crown_derive::solana_pda_address(FACTORY, &[b"escrow", &salt]).unwrap();
            escrows.push(escrow);
            instrs.push(create_escrow(FACTORY, *donor, escrow, salt, 1_000));
        }
        // …and three settlements, each with its own executed transfer, as a batched
        // claim transaction produces them.
        for donor in &donors {
            instrs.push(transfer_checked(USDC, 500, *donor));
            instrs.push(settled_event(SPLITTER, *donor, recipient, 500));
        }

        let r = recognize(&Tx { slot: 900, instrs }, &cfg());

        assert_eq!(r.births.len(), 3, "every birth in the batch is recognized");
        assert_eq!(
            r.settlements.len(),
            3,
            "every settlement in the batch is recognized"
        );
        assert_eq!(r.anomalies, 0, "each event found its own distinct transfer");
        for (i, (escrow, birth)) in r.births.iter().enumerate() {
            assert_eq!(*escrow, escrows[i]);
            assert_eq!(birth.donor, donors[i]);
            assert_eq!(
                birth.slot, 900,
                "the slot is the transaction's, not the event's"
            );
        }
    }
}
