//! Baked network config (`build.rs` from `config/<profile>.toml`). Nothing
//! network lives in code; this module only turns the baked constants into the
//! runtime `ChainConfig` and the freezable cost-gate constants the gate reads.

use crate::recognize::ChainConfig;
use crown_reduce::ChainId;

include!(concat!(env!("OUT_DIR"), "/config.rs"));

/// What the IC itself charges the SOL RPC canister for one `getTransaction`, from
/// the published HTTPS-outcall formula applied per queried provider:
///
/// ```text
/// per_provider = (3_000_000 + 60_000·n)·n        // base
///              + 400·n·request_bytes             // request
///              + 800·n·max_response_bytes        // response (charged on the cap)
/// total        = per_provider · providers
/// ```
///
/// `n` is the SOL RPC canister's subnet size. The response term is charged on the
/// **cap**, not the actual body, which is why `response_max_bytes` is a cost knob
/// on every ingest and not a free safety margin.
///
/// This is a **floor, not the price.** The index does not make the outcall — it
/// calls a canister that makes it, and that canister charges its own tariff on
/// top. Kept because it is the one part of the price that is a published law
/// rather than someone's tariff: if the measured price below ever fell under it,
/// the measurement would be the thing that is wrong.
const IC_OUTCALL_FLOOR: u128 = ((3_000_000 + 60_000 * RPC_NODES) * RPC_NODES
    + 400 * RPC_NODES * RPC_REQUEST_BYTES
    + 800 * RPC_NODES * RESPONSE_MAX_BYTES as u128)
    * RPC_PROVIDERS;

/// The SOL RPC canister's own tariff for one `getTransaction`, per provider:
/// a fixed part plus the response cap. Measured against the live canister's free
/// `getTransactionCyclesCost` query on **2026-07-31**, across caps 4–64 KiB and
/// 3–6 providers; both axes are linear and these two constants reproduce every
/// sample exactly.
///
/// ```text
/// per_provider = 516_479_040 + 27_200 · max_response_bytes
/// ```
///
/// **Why this replaced the IC formula as the gate's input.** The gate used to
/// price the ingest off `IC_OUTCALL_FLOOR`, which for the shipped config is
/// 5_381_248_000 — while the canister actually asks 7_038_843_200, a third more.
/// So the "≥2× margin" the ordering below claims to enforce was really 1.7×, and
/// the direction of that error is the fatal one: under-attaching arrives here as
/// `Consistent(Err(TooFewCycles))`, i.e. an ordinary unreadable reply, on a
/// canister that cannot be patched. A tariff can move, so this is re-measured at
/// the cost-gate; what must not happen is pricing our work off someone else's
/// cost instead of their price.
const SOL_RPC_PER_PROVIDER: u128 = 516_479_040 + 27_200 * RESPONSE_MAX_BYTES as u128;

/// The price of one paid ingest's outcall, as the callee charges it.
const OUTCALL_WORST_CASE: u128 = SOL_RPC_PER_PROVIDER * RPC_PROVIDERS;

// The tariff cannot sit below the law it is derived from: the canister pays the
// IC for the same outcall out of what it charges us. A config where it does means
// one of the two models was mistyped.
const _: () = assert!(
    OUTCALL_WORST_CASE >= IC_OUTCALL_FLOOR,
    "the measured SOL RPC tariff is below what the IC charges for the same outcall \
     — one of the two models is wrong"
);

/// Cycles held back from `INGEST_PRICE` for the index's own execution of one
/// ingest — decode, recognize, fold, two `RbTree` inserts, re-certify. Reserved
/// so that even if the SOL RPC canister accepted every attached cycle instead of
/// refunding the unused part, one ingest still could not cost more than it
/// charged (non-negativity invariant #1 without an assumption about the callee).
/// An order of magnitude over any measured ingest execution.
const EXECUTION_RESERVE: u128 = 1_000_000_000;

// Non-negativity invariant #1, as a *compile-time* law rather than a test: an
// ingest may never cost the index more than it charged, and must attach enough
// for the call to land at all. Checked on the constants that actually reached the
// code, which is why it lives here and not in `build.rs` — a config can be parsed
// correctly and still be wrong, and the compiler is the last reader before the
// freeze. The index is blackholed: a violation is unfixable afterwards, so it
// must not be expressible.
const _: () = assert!(
    ATTACH_CYCLES >= OUTCALL_WORST_CASE,
    "under-attaching burns INGEST_PRICE on a call that never lands"
);
const _: () = assert!(
    ATTACH_CYCLES + EXECUTION_RESERVE <= INGEST_PRICE,
    "one outcall plus this canister's own execution must not cost more than the \
     ingest that paid for them"
);
// The floor and the ceiling are not symmetric, and the margin sits where the
// asymmetry is. Under-attaching is fatal and *silent*: the SOL RPC canister
// answers `Consistent(Err(TooFewCycles))`, which arrives here as an ordinary
// unreadable reply, so every ingest accepts INGEST_PRICE and fails — on a
// blackholed canister, forever, with no distinguishing signal, and the book
// never advances. Over-attaching costs nothing: the IC refunds whatever
// the callee did not accept, and `EXECUTION_RESERVE` above bounds the damage even
// if it accepted everything. So the model is treated as a lower bound with room
// to spare, not as a target to sit near. The authoritative number is the SOL RPC
// canister's own free `getTransactionCyclesCost` query; the cost-gate (P8) pins
// `attach_cycles` off *that*, and this model only has to catch an incoherent
// config at build time.
const _: () = assert!(
    OUTCALL_WORST_CASE * 2 <= ATTACH_CYCLES,
    "attach_cycles must stay ≥2× the modelled worst case — under-attaching fails \
     silently and unfixably, over-attaching is refunded"
);
// The threshold is asked of exactly `RPC_PROVIDERS` providers — `rpc.rs` states
// `total` rather than letting the canister default it. Strictly fewer than the
// providers queried, because `min == total` is unanimity, not a threshold: one
// flaky provider would fail every read, and every ingest would be paid for
// nothing until it recovered. And ≤255 because `total` is a `nat8` on the wire.
const _: () = assert!(
    CONSENSUS as u128 <= RPC_PROVIDERS && RPC_PROVIDERS <= 255,
    "the consensus threshold must be reachable within the providers queried, and \
     the provider count must fit the `total : opt nat8` the SOL RPC canister takes"
);
const _: () = assert!(
    (CONSENSUS as u128) < RPC_PROVIDERS,
    "querying exactly `consensus` providers is unanimity: a single flaky provider \
     would fail every read, and every ingest would be charged for nothing"
);
const _: () = assert!(
    CONSENSUS >= 3,
    "the index recognizes a settlement on three-provider agreement \
     (`docs/spec.md §RPC`)"
);
const _: () = assert!(MIN_GROSS > 0, "min_gross = 0 admits dust as reputation");
const _: () = assert!(
    CYCLE_FLOOR > 0,
    "cycle_floor = 0 lets the index spend its reserve"
);

// The recognition roots (`FACTORIES` non-empty, `splitter ≠ usdc`, no factory
// colliding with either or listed twice) are checked on the frozen profile by
// `build.rs`, where the addresses are decoded. They are about the *shape of the
// config*, not about a frozen number, and they exist in exactly one place — so
// they stay there.

/// The pinned recognition roots for this profile's single cluster.
pub fn chain_config() -> ChainConfig {
    ChainConfig {
        chain: ChainId(CHAIN_ID),
        splitter: SPLITTER,
        usdc: USDC,
        factories: FACTORIES.to_vec(),
        min_gross: MIN_GROSS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[cfg(crown_profile = "testnet")]
    #[test]
    fn testnet_cost_gate_constants_are_baked() {
        // Straight from config/testnet.toml — the freezable cost-gate values.
        assert_eq!(PROFILE, "testnet");
        assert_eq!(INGEST_PRICE, 17_000_000_000);
        assert_eq!(MIN_GROSS, 200_000);
        assert_eq!(chain_config().min_gross, 200_000); // floor wired into recognition
        assert_eq!(CYCLE_FLOOR, 1_000_000_000_000);
        assert_eq!(CONSENSUS, 3);
        assert_eq!(RPC_PROVIDERS, 5); // asked for as `total`, not just priced
        assert_eq!(ATTACH_CYCLES, 15_000_000_000);
        assert_eq!(RESPONSE_MAX_BYTES, 32_768);
        // Devnet runs a single generation, so the boundary is off. On mainnet it
        // is a cost-gate value (P8) and must be reachable before the heap fills —
        // see `docs/spec.md §Ёмкость`. The `cutover` profile turns it on so the
        // `AfterCutover` path is not dead code in every buildable configuration.
        assert_eq!(CUTOVER_SLOT, None);
    }

    /// The test-only profile that arms the generation boundary. Everything else
    /// matches `testnet`, so a `cutover` build differs from the shipped one in
    /// exactly the constant under test.
    #[cfg(crown_profile = "cutover")]
    #[test]
    fn the_cutover_profile_arms_the_boundary_and_changes_nothing_else() {
        assert_eq!(PROFILE, "cutover");
        assert_eq!(CUTOVER_SLOT, Some(1000));
        assert_eq!(INGEST_PRICE, 17_000_000_000);
        assert_eq!(MIN_GROSS, 200_000);
        assert_eq!(ATTACH_CYCLES, 15_000_000_000);
        assert_eq!(CHAIN_ID, super::tests::devnet_chain_id());
    }

    /// `ChainId = sha256("crown-chain:v1:" ‖ "devnet")`, shared by the profiles
    /// that target devnet.
    fn devnet_chain_id() -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"crown-chain:v1:");
        h.update(b"devnet");
        h.finalize().into()
    }

    /// Non-negativity invariant #1 is enforced twice at compile time (`build.rs`
    /// on the config it bakes, `const _: ()` on the constants that reached the
    /// code), so nothing is left for a runtime test to catch. What is worth
    /// pinning here is the *model itself*: if the formula is ever edited, this
    /// says what number it used to produce.
    /// Both models, pinned to the numbers they produced when they were measured —
    /// so an edit to either formula says what it changed.
    ///
    /// The gap between them is the point: the IC's published outcall price is the
    /// floor (what the SOL RPC canister pays), the tariff is what it charges. The
    /// ordering `2·tariff ≤ ATTACH_CYCLES ≤ INGEST_PRICE − reserve` is a
    /// compile-time law above; only the values need pinning here.
    #[test]
    fn both_outcall_models_are_the_documented_formulas() {
        // 34-node subnet, 5 providers, 1 KiB request, 32 KiB response cap.
        assert_eq!(IC_OUTCALL_FLOOR, 5_381_248_000);
        // Measured 2026-07-31 against `getTransactionCyclesCost` on the live
        // canister, for exactly the request `rpc.rs` builds. The gap between the
        // two — 30.8% on this config — is the canister's own margin, and it is
        // stated in prose rather than asserted: "the tariff sits at least 30% over
        // the law" is not a law, it is this month's reading, and a build that
        // breaks because the callee got *cheaper* would be a check working against
        // its own purpose. What must hold is `tariff >= floor`, and that is a
        // `const _: ()` above.
        assert_eq!(OUTCALL_WORST_CASE, 7_038_843_200);
    }

    // The cycle margin (`≥2×` the model, `+ EXECUTION_RESERVE ≤ INGEST_PRICE`),
    // the consensus shape (`3 ≤ CONSENSUS < RPC_PROVIDERS ≤ 255`), the non-zero
    // floors and the mainnet recognition roots are `const _: ()` laws above,
    // checked by the compiler on the constants that reached the code. Restating
    // them as runtime tests would assert on constants — strictly weaker, and it
    // cannot fail later than the build already does.

    #[test]
    fn chain_id_is_the_documented_derivation() {
        // ChainId = sha256("crown-chain:v1:" ‖ id), id = "devnet".
        let expected = devnet_chain_id();
        assert_eq!(CHAIN_ID, expected);
        assert_eq!(chain_config().chain, ChainId(expected));
    }

    #[test]
    fn recognition_roots_are_pinned_to_real_addresses() {
        // Every perimeter root is a real base58 address now (recognition is armed):
        // non-zero, and distinct so a splitter event is never confused with a mint
        // or a factory birth.
        assert_ne!(SPLITTER, [0u8; 32]);
        assert_ne!(USDC, [0u8; 32]);
        assert_ne!(SPLITTER, USDC);
        // Both testnet factories are pinned; a zero (placeholder) factory would be
        // dropped by `build.rs`, so an empty list would mean an unfilled config.
        let c = chain_config();
        assert_eq!(c.splitter, SPLITTER);
        assert_eq!(c.usdc, USDC);
        assert_eq!(c.factories.len(), 2);
        assert!(c.factories.iter().all(|f| *f != [0u8; 32]));
        assert_ne!(c.factories[0], c.factories[1]);
    }
}
