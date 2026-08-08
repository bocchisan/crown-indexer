//! PocketIC end-to-end on a real IC replica.
//!
//! Ingress messages cannot attach cycles, so an ingress `ingest` is always
//! *unpaid* — which is exactly the non-negativity invariant #8 case: it must be
//! rejected before any outcall. The paid path (a cycle-attaching caller + a mock
//! SOL RPC canister) is a separate harness.
//!
//! Run with the bundled server:
//!   POCKET_IC_BIN=~/.cache/dfinity/versions/<v>/pocket-ic cargo test --test e2e

use candid::{Decode, Encode, Nat, Principal, Reserved};
use crown_indexer::config;
use crown_indexer::parse::{
    EncodedTransaction, EncodedTxWithMeta, Encoding, GetTransactionResult,
    MultiGetTransactionResult, TransactionReply, TxMeta, TxStatus,
};
use crown_indexer::{IngestResult, StateStats};
use pocket_ic::{PocketIc, PocketIcBuilder};
use solana_program::instruction::{AccountMeta, Instruction as SolIx};
use solana_program::message::Message as SolMessage;
use solana_program::pubkey::Pubkey;

const T_CYCLES: u128 = 4_000_000_000_000;

/// SPL Token program id and Anchor's `emit_cpi!` tag — the recognition anchors.
const TOKEN_PROGRAM: [u8; 32] = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];
const EVENT_IX_TAG: [u8; 8] = [0xe4, 0x45, 0xa5, 0x2e, 0x51, 0xcb, 0x9a, 0x1d];

/// A donor address a private key could exist for. Every wallet address is an
/// ed25519 public key, therefore **on** the curve — and the fold now refuses a
/// settlement whose payer is **off** it and has no recorded birth, because such an
/// address can only be an escrow this index has not seen born
/// (`state::attributable`). Roughly half of all byte patterns are off the curve,
/// so a donor picked by eye would silently exercise the wrong branch: asserted
/// below rather than assumed.
const WALLET_DONOR: [u8; 32] = [1u8; 32];

/// The fixture above really is wallet-shaped. Cheap, and it fails loudly the day
/// someone edits the constant to a prettier number.
#[test]
fn the_donor_fixture_is_a_possible_public_key() {
    assert!(
        !crown_derive::solana_is_off_curve(&WALLET_DONOR),
        "a direct donation comes from a wallet — this fixture must be on-curve"
    );
}

fn indexer_wasm() -> Vec<u8> {
    build_indexer_wasm("testnet", "target")
}

/// The indexer wasm for a config profile, built into its own target directory so
/// two profiles never invalidate each other's artifacts.
fn build_indexer_wasm(profile: &str, target_dir: &str) -> Vec<u8> {
    let path = format!("{target_dir}/wasm32-unknown-unknown/release/crown_indexer.wasm");
    // Always invoke cargo — never "skip if the file exists". The profile's
    // addresses are baked into the wasm by `build.rs`, so a cached artifact is a
    // *different program* from the one the test host is asserting about. Skipping
    // the build meant an edited `config/*.toml` was silently never picked up, and
    // the suite tested last week's bytecode; the failure that exposed this looked
    // like a broken assertion, but a smaller edit would have passed just as
    // silently. Cargo is incremental, so an unchanged tree costs a fraction of a
    // second here.
    let status = std::process::Command::new("cargo")
        .args([
            "build",
            "--lib",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
            "--target-dir",
            target_dir,
        ])
        .env("CROWN_PROFILE", profile)
        .status()
        .expect("cargo build");
    assert!(
        status.success(),
        "failed to build the {profile} indexer wasm"
    );
    std::fs::read(&path).expect("read indexer wasm")
}

fn setup() -> (PocketIc, Principal) {
    // An NNS subnet gives a root key, so the data certificate chains to it as it
    // would on mainnet; the canister lives on an application subnet.
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build();
    let app = pic.topology().get_app_subnets()[0];
    let id = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(id, T_CYCLES);
    pic.install_canister(id, indexer_wasm(), Encode!().unwrap(), None);
    (pic, id)
}

fn query(pic: &PocketIc, id: Principal, method: &str, args: Vec<u8>) -> Vec<u8> {
    pic.query_call(id, Principal::anonymous(), method, args)
        .expect("query rejected")
}

#[test]
fn unpaid_ingest_is_rejected_before_any_outcall() {
    let (pic, id) = setup();
    // An ingress `ingest` attaches no cycles and can never be productive, so
    // `inspect_message` drops it *before* the (up to ~2 MB) arg is even decoded —
    // no gate, no outcall, no work. The message is rejected at the boundary, not
    // answered (the paid path reaches `ingest` inter-canister, bypassing inspect).
    let res = pic.update_call(
        id,
        Principal::anonymous(),
        "ingest",
        Encode!(&"anySignature".to_string()).unwrap(),
    );
    assert!(
        res.is_err(),
        "inspect_message must drop the unpaid ingress before any decode/gate/outcall, got {res:?}"
    );

    // Nothing was folded or marked applied.
    let applied = Decode!(
        &query(&pic, id, "get_applied_count", Encode!().unwrap()),
        u64
    )
    .unwrap();
    let anomalies = Decode!(
        &query(&pic, id, "get_anomaly_count", Encode!().unwrap()),
        u64
    )
    .unwrap();
    assert_eq!(applied, 0);
    assert_eq!(anomalies, 0);
}

/// The boundary is fail-*closed*: it admits no ingress at all, not merely
/// `ingest`.
///
/// Every `query` here can also be addressed as a *replicated* update, which the
/// canister then executes and pays for out of its own balance — and no gate sees
/// those, since the ingest gate only runs inside `ingest`. Left open, an
/// anonymous caller could burn the balance down to `CYCLE_FLOOR`, after which
/// every paid ingest answers `LowBalance` and the book stops for good. On a
/// blackholed canister that is unfixable, so it must not be reachable at all.
#[test]
fn every_ingress_is_dropped_at_the_boundary_and_costs_nothing() {
    let (pic, id) = setup();
    let before = pic.cycle_balance(id);

    // The cheapest and the most expensive query, each addressed as a replicated
    // update. Both must be refused at the boundary, before execution.
    for (method, args) in [
        ("get_applied_count", Encode!().unwrap()),
        ("get_state_stats", Encode!().unwrap()),
        (
            "get_births_page",
            Encode!(&None::<Vec<u8>>, &10_000u32).unwrap(),
        ),
    ] {
        let res = pic.update_call(id, Principal::anonymous(), method, args);
        assert!(
            res.is_err(),
            "`{method}` as a replicated update must be dropped at the boundary, got {res:?}"
        );
    }

    assert_eq!(
        pic.cycle_balance(id),
        before,
        "a message refused at the boundary must not cost the canister a cycle"
    );

    // Free reads are untouched: queries reached *as queries* are not inspected.
    let stats = query(&pic, id, "get_applied_count", Encode!().unwrap());
    assert_eq!(Decode!(&stats, u64).unwrap(), 0);
}

#[test]
fn free_queries_answer_from_a_fresh_canister() {
    let (pic, id) = setup();
    let version = Decode!(
        &query(&pic, id, "get_reduce_version", Encode!().unwrap()),
        u32
    )
    .unwrap();
    assert_eq!(version, crown_reduce::REDUCE_VERSION);

    // Reputation of an absent key is 0, but a witness is still returned.
    let zeros = vec![0u8; 32];
    let (value, witness) = Decode!(
        &query(
            &pic,
            id,
            "get_reputation",
            Encode!(&zeros, &zeros, &zeros).unwrap()
        ),
        Nat,
        Vec<u8>
    )
    .unwrap();
    assert_eq!(value, Nat::from(0u8));
    assert!(!witness.is_empty(), "an absence proof is still a witness");
}

#[test]
fn certificate_is_live_and_commits_to_the_combined_root() {
    use ic_certification::{Certificate, LookupResult};

    let (pic, id) = setup();
    // The NNS root key exists on this instance — the certificate chains to it as
    // it would on mainnet (BLS/delegation verification is the standard client
    // library's job; here we verify the certificate's *content*).
    assert!(pic.root_key().is_some());

    let (cert, root) = Decode!(
        &query(&pic, id, "get_certificate", Encode!().unwrap()),
        Option<Vec<u8>>,
        Vec<u8>
    )
    .unwrap();
    // `init` published the empty combined root, so a certificate exists already.
    let cert = cert.expect("data certificate must be present in a query");
    assert_eq!(root.len(), 32, "combined root is a 32-byte hash");

    // The certified data in the certificate must equal the reported root: the
    // canister cannot report a root it did not actually certify.
    // ic-certification deserializes zero-copy, so a borrowing decoder is needed.
    let cert: Certificate = serde_cbor::from_slice(&cert).expect("certificate is valid CBOR");
    let path: [&[u8]; 3] = [b"canister", id.as_slice(), b"certified_data"];
    match cert.tree.lookup_path(path) {
        LookupResult::Found(data) => {
            assert_eq!(data, &root[..], "certificate commits to the reported root")
        }
        other => panic!("certified_data absent from certificate: {other:?}"),
    }
}

// ----- paid-ingest harness (mock relay + mock SOL RPC at the pinned principal) -----

fn mock_wasm() -> Vec<u8> {
    let path = "e2e-mock/target/wasm32-unknown-unknown/release/mock_sol_rpc.wasm";
    if !std::path::Path::new(path).exists() {
        let status = std::process::Command::new("cargo")
            .args(["build", "--release", "--target", "wasm32-unknown-unknown"])
            .current_dir("e2e-mock")
            .status()
            .expect("cargo build mock");
        assert!(status.success(), "failed to build the mock wasm");
    }
    std::fs::read(path).expect("read mock wasm")
}

/// Indexer on an application subnet; the mock installed at the *pinned* SOL RPC
/// principal (`tghme-…`) on the fiduciary subnet, so the indexer reaches it by
/// the same address it uses on mainnet.
fn setup_with_mock() -> (PocketIc, Principal, Principal) {
    setup_with_mock_wasm(indexer_wasm())
}

fn setup_with_mock_wasm(wasm: Vec<u8>) -> (PocketIc, Principal, Principal) {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_fiduciary_subnet()
        .with_application_subnet()
        .build();
    let app = pic.topology().get_app_subnets()[0];
    let indexer = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(indexer, T_CYCLES);
    pic.install_canister(indexer, wasm, Encode!().unwrap(), None);

    let sol_rpc = Principal::from_text("tghme-zyaaa-aaaar-qarca-cai").unwrap();
    let mock = pic
        .create_canister_with_id(None, None, sol_rpc)
        .expect("the SOL RPC principal must be installable on the fiduciary subnet");
    pic.add_cycles(mock, 100 * T_CYCLES);
    pic.install_canister(mock, mock_wasm(), Encode!().unwrap(), None);
    (pic, indexer, mock)
}

fn settled_discriminator() -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"event:Settled");
    let full: [u8; 32] = h.finalize().into();
    full[..8].try_into().unwrap()
}

fn create_escrow_discriminator() -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"global:create_escrow");
    let full: [u8; 32] = h.finalize().into();
    full[..8].try_into().unwrap()
}

/// SPL `TransferChecked`, accounts `[source, mint, dest, authority]`.
fn transfer_ix(amount: u64, authority: Pubkey) -> SolIx {
    let mut data = vec![12u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(6); // decimals
    SolIx {
        program_id: Pubkey::new_from_array(TOKEN_PROGRAM),
        accounts: vec![
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(config::USDC), false),
            AccountMeta::new(Pubkey::new_unique(), false),
            AccountMeta::new_readonly(authority, true),
        ],
        data,
    }
}

/// A `Settled` event-CPI from the pinned splitter: tag ‖ disc ‖ borsh fields.
fn settled_ix(donor: [u8; 32], recipient: [u8; 32], gross: u64) -> SolIx {
    let mut data = Vec::new();
    data.extend_from_slice(&EVENT_IX_TAG);
    data.extend_from_slice(&settled_discriminator());
    data.extend_from_slice(&donor);
    data.extend_from_slice(&recipient);
    data.extend_from_slice(&gross.to_le_bytes());
    SolIx {
        program_id: Pubkey::new_from_array(config::SPLITTER),
        accounts: vec![],
        data,
    }
}

/// A `create_escrow` of the first pinned factory, with the escrow account set to
/// the PDA that factory really derives for `salt`.
fn create_escrow_ix(donor: Pubkey, salt: [u8; 32]) -> (SolIx, [u8; 32]) {
    let factory = config::FACTORIES[0];
    let (escrow, _bump) =
        crown_derive::solana_pda_address(factory, &[b"escrow", &salt]).expect("derive escrow PDA");
    let mut data = Vec::new();
    data.extend_from_slice(&create_escrow_discriminator());
    data.extend_from_slice(&salt); // 8..40 — the first arg of every form
    data.extend_from_slice(&[0u8; 32]); // recipient
    data.extend_from_slice(&1_000_000u64.to_le_bytes()); // gross (not read)
    let ix = SolIx {
        program_id: Pubkey::new_from_array(factory),
        accounts: vec![
            AccountMeta::new(donor, true),
            AccountMeta::new(Pubkey::new_from_array(escrow), false),
        ],
        data,
    };
    (ix, escrow)
}

/// A canned `getTransaction` reply carrying `ixs` at `slot`. `executed = false`
/// makes it a reverted transaction — read perfectly well, moved nothing.
fn canned(ixs: &[SolIx], payer: Pubkey, slot: u64, executed: bool) -> Vec<u8> {
    let msg = SolMessage::new(ixs, Some(&payer));
    let sigs = usize::from(msg.header.num_required_signatures);
    let mut raw = vec![sigs as u8];
    raw.extend(vec![0u8; sigs * 64]);
    raw.extend(msg.serialize());

    let reply = TransactionReply {
        slot,
        transaction: EncodedTxWithMeta {
            meta: Some(TxMeta {
                status: if executed {
                    TxStatus::Ok
                } else {
                    TxStatus::Err(Reserved)
                },
                inner_instructions: None,
                loaded_addresses: None,
            }),
            transaction: EncodedTransaction::Binary(
                bs58::encode(raw).into_string(),
                Encoding::Base58,
            ),
        },
    };
    Encode!(&MultiGetTransactionResult::Consistent(
        GetTransactionResult::Ok(Some(reply))
    ))
    .unwrap()
}

/// A direct-donation `Settled` from the pinned splitter plus its matching
/// `TransferChecked` (mint = the baked USDC).
fn canned_response(donor: [u8; 32], recipient: [u8; 32], gross: u64, slot: u64) -> Vec<u8> {
    let donor_pk = Pubkey::new_from_array(donor);
    canned(
        &[
            transfer_ix(gross, donor_pk),
            settled_ix(donor, recipient, gross),
        ],
        donor_pk,
        slot,
        true,
    )
}

/// Arm the mock with the next reply.
fn set_response(pic: &PocketIc, mock: Principal, bytes: Vec<u8>) {
    pic.update_call(
        mock,
        Principal::anonymous(),
        "set_response",
        Encode!(&bytes).unwrap(),
    )
    .expect("set_response");
}

fn calls(pic: &PocketIc, mock: Principal) -> u64 {
    Decode!(&query(pic, mock, "calls", Encode!().unwrap()), u64).unwrap()
}

fn counter(pic: &PocketIc, indexer: Principal, method: &str) -> u64 {
    Decode!(&query(pic, indexer, method, Encode!().unwrap()), u64).unwrap()
}

fn relay_ingest(pic: &PocketIc, mock: Principal, indexer: Principal, sig: &str) -> IngestResult {
    relay_ingest_with(pic, mock, indexer, sig, (config::INGEST_PRICE as u64) * 3)
}

fn relay_ingest_with(
    pic: &PocketIc,
    mock: Principal,
    indexer: Principal,
    sig: &str,
    cycles: u64,
) -> IngestResult {
    let outer = pic
        .update_call(
            mock,
            Principal::anonymous(),
            "relay_ingest",
            Encode!(&indexer, &sig.to_string(), &cycles).unwrap(),
        )
        .expect("relay_ingest rejected");
    let raw = Decode!(&outer, Vec<u8>).unwrap();
    Decode!(&raw, IngestResult).unwrap()
}

fn reputation(pic: &PocketIc, indexer: Principal, donor: [u8; 32], recipient: [u8; 32]) -> Nat {
    let (value, _witness) = Decode!(
        &query(
            pic,
            indexer,
            "get_reputation",
            Encode!(
                &config::CHAIN_ID.to_vec(),
                &donor.to_vec(),
                &recipient.to_vec()
            )
            .unwrap()
        ),
        Nat,
        Vec<u8>
    )
    .unwrap();
    value
}

#[test]
fn paid_ingest_folds_a_settlement_into_reputation() {
    let (pic, indexer, mock) = setup_with_mock();
    let donor = WALLET_DONOR;
    let recipient = [8u8; 32];
    let gross = 500_000u64;
    set_response(&pic, mock, canned_response(donor, recipient, gross, 123));

    // Paid ingest through the relay → one settlement folded.
    //
    // Measure what the ingest actually *costs us* while we are here. The mock
    // refuses the attached cycles, so the balance delta across the call is
    // `INGEST_PRICE − execution`, and `execution` is the number
    // `EXECUTION_RESERVE` claims to be "an order of magnitude over any measured
    // ingest execution" — a claim that until now nothing measured. This is the
    // expensive shape too: decode, recognize, fold, two `RbTree` inserts and a
    // re-certification, not an early refusal.
    let before = pic.cycle_balance(indexer);
    let res = relay_ingest(&pic, mock, indexer, "sig-1");
    let execution =
        config::INGEST_PRICE.saturating_sub(pic.cycle_balance(indexer).saturating_sub(before));
    println!(
        "[cost] ingest execution: {execution} cycles (reserve {})",
        config::EXECUTION_RESERVE
    );
    assert!(
        execution < config::EXECUTION_RESERVE,
        "one ingest executed for {execution} cycles, over the {} held back for it —          the compile-time law in `config.rs` no longer bounds what an ingest can cost",
        config::EXECUTION_RESERVE
    );
    assert!(
        matches!(
            res,
            IngestResult::Applied {
                settlements: 1,
                births: 0,
                anomalies: 0
            }
        ),
        "expected one settlement, got {res:?}"
    );
    assert_eq!(
        reputation(&pic, indexer, donor, recipient),
        Nat::from(gross)
    );

    // Exactly one outcall, and it carried the response cap (invariant #1).
    assert_eq!(calls(&pic, mock), 1);
    let cap = Decode!(
        &query(&pic, mock, "last_cap", Encode!().unwrap()),
        Option<u64>
    )
    .unwrap();
    assert_eq!(cap, Some(config::RESPONSE_MAX_BYTES));

    // Same signature again: duplicate, no work, no double-count.
    let dup = relay_ingest(&pic, mock, indexer, "sig-1");
    assert!(matches!(dup, IngestResult::Duplicate), "got {dup:?}");
    assert_eq!(
        reputation(&pic, indexer, donor, recipient),
        Nat::from(gross)
    );
    assert_eq!(
        calls(&pic, mock),
        1,
        "a duplicate must not make another outcall"
    );

    // The gauge that schedules the cutover, live through the canister: one book
    // key, no births.
    let stats = Decode!(
        &query(&pic, indexer, "get_state_stats", Encode!().unwrap()),
        StateStats
    )
    .unwrap();
    assert_eq!(stats.book_keys, 1);
    assert_eq!(stats.births, 0);
    assert!(stats.heap_bytes > 0, "heap is readable inside the wasm");
}

/// An inter-canister ingest is the *paid* path — `inspect_message` never sees it.
/// Underpayment therefore has to be caught by the gate, and caught before the
/// outcall: this is non-negativity invariant #1 on the path that can actually
/// attach cycles, which the ingress test cannot reach.
#[test]
fn an_underpaid_inter_canister_ingest_makes_no_outcall() {
    let (pic, indexer, mock) = setup_with_mock();
    set_response(
        &pic,
        mock,
        canned_response(WALLET_DONOR, [8u8; 32], 500_000, 123),
    );

    let res = relay_ingest_with(
        &pic,
        mock,
        indexer,
        "sig-underpaid",
        (config::INGEST_PRICE as u64) - 1,
    );
    assert!(matches!(res, IngestResult::Underpaid), "got {res:?}");
    assert_eq!(
        calls(&pic, mock),
        0,
        "no outcall before payment is accepted"
    );
    assert_eq!(counter(&pic, indexer, "get_applied_count"), 0);

    // And one cycle more is enough — the boundary is exactly `INGEST_PRICE`.
    let ok = relay_ingest_with(
        &pic,
        mock,
        indexer,
        "sig-underpaid",
        config::INGEST_PRICE as u64,
    );
    assert!(matches!(ok, IngestResult::Applied { .. }), "got {ok:?}");
    assert_eq!(calls(&pic, mock), 1);
}

/// A finalized *reverted* transaction is read perfectly well; it simply moved
/// nothing. It must be retired on the spot — applied, free from then on — rather
/// than left retriable like an unreadable one: a pusher that could not tell the
/// two apart would re-fetch a permanent non-event forever, at full price.
#[test]
fn a_reverted_transaction_is_retired_not_retried() {
    let (pic, indexer, mock) = setup_with_mock();
    let donor = Pubkey::new_from_array(WALLET_DONOR);
    set_response(
        &pic,
        mock,
        canned(
            &[
                transfer_ix(500_000, donor),
                settled_ix(WALLET_DONOR, [8u8; 32], 500_000),
            ],
            donor,
            123,
            false, // reverted
        ),
    );

    let res = relay_ingest(&pic, mock, indexer, "sig-reverted");
    assert!(
        matches!(
            res,
            IngestResult::Applied {
                settlements: 0,
                births: 0,
                anomalies: 0
            }
        ),
        "a reverted transaction folds nothing, but is done with: got {res:?}"
    );
    assert_eq!(counter(&pic, indexer, "get_applied_count"), 1);
    // Its `Settled` was never folded — the transaction reverted, so no money moved.
    assert_eq!(
        reputation(&pic, indexer, WALLET_DONOR, [8u8; 32]),
        Nat::from(0u8)
    );

    // Free from here on, and no second outcall: exactly-once retired it.
    let again = relay_ingest(&pic, mock, indexer, "sig-reverted");
    assert!(matches!(again, IngestResult::Duplicate), "got {again:?}");
    assert_eq!(calls(&pic, mock), 1);
}

/// The other half of that distinction, and the one no test used to run: a read
/// that did **not** land keeps the payment and leaves the signature exactly as it
/// found it.
///
/// `01-standards §Тесты 12` asks for this one by name — "сколько угодно провалов
/// подряд не делают сигнатуру невписываемой" — and it is the property the whole
/// no-attempt-budget decision rests on. `commitment = finalized` makes a
/// not-yet-final transaction indistinguishable here from an unreadable one, so a
/// signature that failed N reads has to still fold on the N+1st; if it did not,
/// anyone could retire someone else's payment for the price of the reads, forever,
/// on a canister nobody can patch. Nothing checked it: the unit test named for the
/// property only calls `mark_applied`, and `NotFound` was never produced end to
/// end at all.
///
/// The payment is the other direction of the same edge (`§Тесты 4`): the outcall
/// happened, so `INGEST_PRICE` is kept even though nothing was folded — fund-then-
/// fail must not be cheaper than the work it triggers.
#[test]
fn a_read_that_failed_keeps_the_payment_and_leaves_the_signature_foldable() {
    let (pic, indexer, mock) = setup_with_mock();
    let donor = WALLET_DONOR;
    let recipient = [8u8; 32];
    let gross = 500_000u64;

    // Both shapes of "unreadable", in the order a real signature meets them: no
    // finalized transaction under consensus yet, and a provider-side error.
    let not_found = Encode!(&MultiGetTransactionResult::Consistent(
        GetTransactionResult::Ok(None)
    ))
    .unwrap();
    let errored = Encode!(&MultiGetTransactionResult::Consistent(
        GetTransactionResult::Err(Reserved)
    ))
    .unwrap();

    for (attempt, reply) in [&not_found, &errored, &not_found, &errored, &not_found]
        .into_iter()
        .enumerate()
    {
        set_response(&pic, mock, reply.clone());
        let before = pic.cycle_balance(indexer);
        let res = relay_ingest(&pic, mock, indexer, "sig-unreadable");
        assert!(matches!(res, IngestResult::NotFound), "got {res:?}");

        // Paid, and the payment bought a real attempt: the outcall was made.
        assert!(
            pic.cycle_balance(indexer) > before,
            "a failed read keeps INGEST_PRICE — it is not refunded"
        );
        assert_eq!(calls(&pic, mock), attempt as u64 + 1);

        // And it changed nothing: `applied` is the only terminal state a signature
        // has, so no amount of failure can retire one.
        assert_eq!(counter(&pic, indexer, "get_applied_count"), 0);
        assert_eq!(counter(&pic, indexer, "get_anomaly_count"), 0);
    }

    // The transaction finally reads. The signature was never consumed by the five
    // failures — that is exactly what "stays foldable forever" has to mean.
    set_response(&pic, mock, canned_response(donor, recipient, gross, 123));
    let res = relay_ingest(&pic, mock, indexer, "sig-unreadable");
    assert!(
        matches!(res, IngestResult::Applied { settlements: 1, .. }),
        "five failed reads must not retire a signature: got {res:?}"
    );
    assert_eq!(
        reputation(&pic, indexer, donor, recipient),
        Nat::from(gross)
    );
    assert_eq!(counter(&pic, indexer, "get_applied_count"), 1);
}

/// The attribution chain end to end (architecture §4), across two ingests: a
/// birth records `escrow → donor`, and a later settlement whose on-chain donor is
/// that escrow is credited to the funding donor instead of to the escrow address.
/// This is the property the birth seed exists to preserve across generations.
#[test]
fn an_escrow_settlement_is_credited_to_its_funding_donor() {
    let (pic, indexer, mock) = setup_with_mock();
    let donor = Pubkey::new_from_array(WALLET_DONOR);
    let recipient = [8u8; 32];
    let gross = 500_000u64;

    // 1. The birth: `create_escrow` from a pinned factory, escrow = the real PDA.
    let (ix, escrow) = create_escrow_ix(donor, [42u8; 32]);
    set_response(&pic, mock, canned(&[ix], donor, 100, true));
    let res = relay_ingest(&pic, mock, indexer, "sig-birth");
    assert!(
        matches!(
            res,
            IngestResult::Applied {
                settlements: 0,
                births: 1,
                anomalies: 0
            }
        ),
        "got {res:?}"
    );

    // The birth is queryable, and enumerable as the successor's seed.
    let (birth, witness) = Decode!(
        &query(
            &pic,
            indexer,
            "get_birth",
            Encode!(&escrow.to_vec()).unwrap()
        ),
        Option<crown_indexer::BirthView>,
        Vec<u8>
    )
    .unwrap();
    let birth = birth.expect("the birth was recorded");
    assert_eq!(birth.donor, donor.to_bytes().to_vec());
    assert_eq!(birth.slot, 100);
    assert!(!witness.is_empty());

    let page = Decode!(
        &query(
            &pic,
            indexer,
            "get_births_page",
            Encode!(&None::<Vec<u8>>, &10u32).unwrap()
        ),
        Option<Vec<crown_indexer::BirthEntry>>
    )
    .unwrap()
    .expect("a well-formed cursor answers with a page");
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].escrow, escrow.to_vec());
    assert_eq!(page[0].donor, donor.to_bytes().to_vec());

    // 2. The settlement, a later slot, paid out *by the escrow*: the on-chain
    //    donor of the event is the escrow PDA, and so is the transfer authority.
    let escrow_pk = Pubkey::new_from_array(escrow);
    set_response(
        &pic,
        mock,
        canned(
            &[
                transfer_ix(gross, escrow_pk),
                settled_ix(escrow, recipient, gross),
            ],
            escrow_pk,
            200,
            true,
        ),
    );
    let res = relay_ingest(&pic, mock, indexer, "sig-settle");
    assert!(
        matches!(res, IngestResult::Applied { settlements: 1, .. }),
        "got {res:?}"
    );

    // Credited to the human who funded the escrow …
    assert_eq!(
        reputation(&pic, indexer, donor.to_bytes(), recipient),
        Nat::from(gross)
    );
    // … and not to the escrow address, which is the silent, permanent failure
    // mode an unseeded generation would fall into.
    assert_eq!(reputation(&pic, indexer, escrow, recipient), Nat::from(0u8));
}

/// The other end of that chain, and the one that used to have no answer at all:
/// the settlement arrives **first**, before the index has seen the escrow born.
///
/// It is not a corner case. A scope's verdict signature opens every escrow that
/// derived its resolver — including escrows the game never saw, which is exactly
/// how a collection takes its contributions past the first
/// (`crown-games/conditional-funding`). Folding such a settlement would credit the
/// escrow **address** for good: the law only adds, so a birth arriving later does
/// not reach back, and the donor's reputation for a real payment is gone. Worse,
/// anyone could cause it deliberately for the price of one ingest.
///
/// So the fold refuses, and refusing has to be *free of consequence*: nothing
/// folded, nothing counted, the signature not marked. The very same signature then
/// folds correctly once the birth is in — no second chance needed, because the
/// first one was never spent.
#[test]
fn a_settlement_that_outran_its_birth_is_refused_and_folds_after_it() {
    let (pic, indexer, mock) = setup_with_mock();
    let donor = Pubkey::new_from_array(WALLET_DONOR);
    let recipient = [8u8; 32];
    let gross = 500_000u64;

    let (birth_ix, escrow) = create_escrow_ix(donor, [42u8; 32]);
    let escrow_pk = Pubkey::new_from_array(escrow);
    let settle = canned(
        &[
            transfer_ix(gross, escrow_pk),
            settled_ix(escrow, recipient, gross),
        ],
        escrow_pk,
        200,
        true,
    );

    // 1. The settlement, ingested before the birth.
    set_response(&pic, mock, settle.clone());
    let res = relay_ingest(&pic, mock, indexer, "sig-settle");
    assert!(matches!(res, IngestResult::UnknownBirth), "got {res:?}");

    // Nothing moved — not the book, not the counters, not `applied`.
    assert_eq!(reputation(&pic, indexer, escrow, recipient), Nat::from(0u8));
    assert_eq!(
        reputation(&pic, indexer, donor.to_bytes(), recipient),
        Nat::from(0u8)
    );
    assert_eq!(counter(&pic, indexer, "get_applied_count"), 0);
    assert_eq!(counter(&pic, indexer, "get_anomaly_count"), 0);

    // Repeating it changes nothing either: a refusal is not a spent attempt.
    set_response(&pic, mock, settle.clone());
    let again = relay_ingest(&pic, mock, indexer, "sig-settle");
    assert!(matches!(again, IngestResult::UnknownBirth), "got {again:?}");
    assert_eq!(counter(&pic, indexer, "get_applied_count"), 0);

    // 2. The birth lands (an earlier slot, as it was on chain all along).
    set_response(&pic, mock, canned(&[birth_ix], donor, 100, true));
    let res = relay_ingest(&pic, mock, indexer, "sig-birth");
    assert!(
        matches!(res, IngestResult::Applied { births: 1, .. }),
        "got {res:?}"
    );

    // 3. …and the very same settlement signature now folds, to the human.
    set_response(&pic, mock, settle);
    let res = relay_ingest(&pic, mock, indexer, "sig-settle");
    assert!(
        matches!(res, IngestResult::Applied { settlements: 1, .. }),
        "the refused signature was never spent: got {res:?}"
    );
    assert_eq!(
        reputation(&pic, indexer, donor.to_bytes(), recipient),
        Nat::from(gross)
    );
    assert_eq!(reputation(&pic, indexer, escrow, recipient), Nat::from(0u8));
}

/// A wallet needs no birth, and that is what keeps the refusal narrow: a direct
/// donation is paid by a transaction-level signer, whose address is on the curve
/// by construction. If the check had been "no birth → refuse", every direct
/// donation in the system would have stopped folding.
#[test]
fn a_direct_donation_from_a_wallet_still_folds_with_no_birth_anywhere() {
    let (pic, indexer, mock) = setup_with_mock();
    let recipient = [8u8; 32];
    let gross = 500_000u64;
    set_response(
        &pic,
        mock,
        canned_response(WALLET_DONOR, recipient, gross, 123),
    );
    let res = relay_ingest(&pic, mock, indexer, "sig-direct");
    assert!(
        matches!(res, IngestResult::Applied { settlements: 1, .. }),
        "got {res:?}"
    );
    assert_eq!(
        reputation(&pic, indexer, WALLET_DONOR, recipient),
        Nat::from(gross)
    );
}

/// The generation boundary (architecture §8, handoff mechanism #1), on a build
/// that actually has one. `cutover_slot = 0` in both shipped profiles, so without
/// this profile the `AfterCutover` branch is dead code in every buildable
/// configuration and would run for the first time in production, on a canister
/// nobody can fix.
#[test]
fn after_cutover_is_refused_without_spending_the_signature() {
    let wasm = build_indexer_wasm("cutover", "target/profile-cutover");
    let (pic, indexer, mock) = setup_with_mock_wasm(wasm);
    let donor = WALLET_DONOR;
    let recipient = [8u8; 32];
    let gross = 500_000u64;

    // Slot 5000 is past the profile's boundary of 1000: the next generation's
    // mandate, not this one's.
    set_response(&pic, mock, canned_response(donor, recipient, gross, 5000));
    let res = relay_ingest(&pic, mock, indexer, "sig-late");
    assert!(matches!(res, IngestResult::AfterCutover), "got {res:?}");
    assert_eq!(
        calls(&pic, mock),
        1,
        "the slot is only knowable from the reply"
    );
    assert_eq!(
        reputation(&pic, indexer, donor, recipient),
        Nat::from(0u8),
        "nothing past the boundary reaches this generation's book"
    );

    // Not applied: the signature must stay free for the successor to fold, or the
    // settlement falls into the gap between generations.
    assert_eq!(counter(&pic, indexer, "get_applied_count"), 0);

    // Repeating it changes nothing — refusal past the boundary touches no state.
    for _ in 0..5 {
        assert!(matches!(
            relay_ingest(&pic, mock, indexer, "sig-late"),
            IngestResult::AfterCutover
        ));
    }
    assert_eq!(counter(&pic, indexer, "get_applied_count"), 0);

    // And the same signature is still free to fold: a transaction *before* the
    // boundary folds normally, which is what "the signature stays free" means.
    set_response(&pic, mock, canned_response(donor, recipient, gross, 999));
    let res = relay_ingest(&pic, mock, indexer, "sig-late");
    assert!(
        matches!(res, IngestResult::Applied { settlements: 1, .. }),
        "the signature was never consumed by the refusals: got {res:?}"
    );
    assert_eq!(
        reputation(&pic, indexer, donor, recipient),
        Nat::from(gross)
    );

    // The last slot before the boundary is ours; the boundary itself is not.
    set_response(&pic, mock, canned_response(donor, recipient, gross, 1000));
    assert!(matches!(
        relay_ingest(&pic, mock, indexer, "sig-at-boundary"),
        IngestResult::AfterCutover
    ));
}

/// **Generation capacity, measured through the canister rather than asserted in a
/// document.** `cost.md §7` publishes bytes-per-unit (book key / birth / applied
/// signature) and a ceiling in ingests derived from them — and until now nothing
/// executed that derivation. The numbers matter more than most: the index is
/// blackholed, its heap is the only storage it will ever have, and `CUTOVER_SLOT`
/// is pinned off exactly this arithmetic. A model that is wrong here is wrong in
/// the one direction that cannot be fixed after the freeze.
///
/// So: fold real settlements through the real ingest path and watch `heap_bytes`
/// move. Each one is a fresh `(donor, recipient)` pair, i.e. the worst case the
/// model assumes — a new book key every time, never a top-up of an existing one.
///
/// What this asserts is the **ceiling**, not the exact figure: a per-settlement
/// cost above the model would mean the generation runs out sooner than
/// `CUTOVER_SLOT` assumes, which is the failure with no recovery. Coming in under
/// it is free headroom and needs no test to permit.
#[test]
fn a_settlement_costs_no_more_heap_than_the_capacity_model_assumes() {
    /// `cost.md §7`: 216 B book key + 0.8 · 130 B birth + 1.8 · 121 B applied
    /// ≈ 538 B per settlement, upper-bounded. This run folds settlements without
    /// births, so it exercises the book-key + applied terms; the allowance stays
    /// the full model figure because that is the number the cutover is planned on.
    const MODELLED_BYTES_PER_SETTLEMENT: u64 = 538;
    /// `heap_bytes` reads wasm **pages** (64 KiB), so the run has to allocate
    /// several of them or the answer is "zero bytes each" — which is what a first
    /// attempt at 200 settlements reported, and it is not a measurement, it is a
    /// granularity artefact. At the modelled 538 B this is ~1 MB, i.e. ~16 pages.
    const N: u64 = 4_000;

    let (pic, indexer, mock) = setup_with_mock();
    let stats = |pic: &PocketIc| -> StateStats {
        Decode!(
            &query(pic, indexer, "get_state_stats", Encode!().unwrap()),
            StateStats
        )
        .unwrap()
    };

    let before = stats(&pic);
    for i in 0..N {
        // A fresh pair each time: the model's worst case is "every settlement is
        // a new book key", and a repeated pair would measure the cheap path.
        let mut donor = [2u8; 32];
        donor[0..8].copy_from_slice(&i.to_le_bytes());
        // Wallet donors only — an off-curve one would need a folded birth first
        // (`attributable`), and this test is about bytes, not attribution.
        if crown_derive::solana_is_off_curve(&donor) {
            continue;
        }
        let mut recipient = [3u8; 32];
        recipient[0..8].copy_from_slice(&i.to_le_bytes());
        set_response(
            &pic,
            mock,
            canned_response(donor, recipient, 500_000, 100 + i),
        );
        let sig = format!("cap-sig-{i}");
        assert!(
            matches!(
                relay_ingest(&pic, mock, indexer, &sig),
                IngestResult::Applied { settlements: 1, .. }
            ),
            "settlement {i} must fold"
        );
    }
    let after = stats(&pic);

    let folded = after.book_keys - before.book_keys;
    let grew = after.heap_bytes - before.heap_bytes;
    let per = grew / folded.max(1);
    println!("[capacity] {folded} settlements → +{grew} B heap = {per} B each (model {MODELLED_BYTES_PER_SETTLEMENT})");
    // 3 GiB of heap at the measured rate — the number `CUTOVER_SLOT` is planned on.
    println!(
        "[capacity] 3 GiB / {per} B ≈ {:.2}M settlements per generation",
        (3.0 * 1024.0 * 1024.0 * 1024.0 / per as f64) / 1e6
    );
    assert!(
        per <= MODELLED_BYTES_PER_SETTLEMENT,
        "a settlement costs {per} B of heap, over the {MODELLED_BYTES_PER_SETTLEMENT} B the capacity \
         model assumes — the generation fills sooner than `CUTOVER_SLOT` plans for, and the index \
         is blackholed"
    );
}

/// **The generation handover, across the canister boundary rather than inside one
/// process.** `certified.rs` already pins the property in a unit test — a
/// successor rebuilt from the pages reconstructs the same root. What that test
/// cannot see is the half the cutover actually uses: the pages have to come out
/// **through a query**, in candid, paginated by a cursor, and they have to come
/// out *whole*. A `limit` that silently truncates a walk, or a cursor that skips a
/// key, produces a successor whose root simply differs — with no error anywhere,
/// on a predecessor that is blackholed and cannot be asked again.
///
/// This asserts the two properties that were measurable: **both enumerations
/// cross the boundary complete** (against the gauge that schedules the cutover),
/// and **each entry crosses faithfully** (against the point query for the same
/// key). Both hold, with a deliberately small page size so the cursor is
/// exercised rather than the "it all fit in one page" case.
///
/// **It deliberately does not compare the rebuilt root with gen-1's**, and the
/// reason is a finding rather than an omission: it cannot match. `RbTree` hashes
/// the *structure* of the red-black tree, the structure depends on insertion
/// order, gen-1 inserts in ingest order and the pages enumerate in key order. Same
/// content, different shape, different root — measured here at `P8` (12 identical
/// keys, three insertion orders, three roots). The property the handover really
/// rests on is that a **canonical replay normalizes**, which is pinned where it
/// belongs, next to the tree
/// (`certified.rs::a_canonical_replay_of_the_pages_normalizes_whatever_order_gen1_grew_in`).
/// Acceptance at cutover is that plus these two page properties — not equality
/// with gen-1's own root.
#[test]
fn both_enumerations_cross_the_canister_boundary_whole_and_faithful() {
    /// Small on purpose — several pages per enumeration, so the cursor is
    /// exercised rather than the "everything fits in one page" case.
    const PAGE: u32 = 7;
    const N: u64 = 40;

    let (pic, indexer, mock) = setup_with_mock();

    // A mixed history, folded through the real paid path: settlements from wallet
    // donors (a fresh pair each, so every one is its own book key) plus births —
    // the shape the cutover actually meets.
    let mut folded = 0u64;
    for i in 0..N {
        let mut donor = [4u8; 32];
        donor[0..8].copy_from_slice(&i.to_le_bytes());
        if crown_derive::solana_is_off_curve(&donor) {
            continue;
        }
        let mut recipient = [5u8; 32];
        recipient[0..8].copy_from_slice(&i.to_le_bytes());
        set_response(
            &pic,
            mock,
            canned_response(donor, recipient, 300_000 + i, 500 + i),
        );
        if matches!(
            relay_ingest(&pic, mock, indexer, &format!("ho-sig-{i}")),
            IngestResult::Applied { settlements: 1, .. }
        ) {
            folded += 1;
        }
    }
    assert!(folded > 0, "the handover needs a history to hand over");

    for i in 0..12u8 {
        let (ix, _escrow) = create_escrow_ix(Pubkey::new_from_array(WALLET_DONOR), [i; 32]);
        set_response(
            &pic,
            mock,
            canned(
                &[ix],
                Pubkey::new_from_array(WALLET_DONOR),
                600 + u64::from(i),
                true,
            ),
        );
        assert!(
            matches!(
                relay_ingest(&pic, mock, indexer, &format!("ho-birth-{i}")),
                IngestResult::Applied {
                    births: 1,
                    settlements: 0,
                    ..
                }
            ),
            "birth {i} must fold, and fold nothing else"
        );
    }

    // ---- drain both enumerations over the boundary ----
    let mut book: Vec<crown_indexer::BookEntry> = Vec::new();
    let mut cursor: Option<Vec<u8>> = None;
    loop {
        let page = Decode!(
            &query(
                &pic,
                indexer,
                "get_book_page",
                Encode!(&cursor, &PAGE).unwrap()
            ),
            Option<Vec<crown_indexer::BookEntry>>
        )
        .unwrap()
        .expect("a valid cursor must not be refused");
        if page.is_empty() {
            break;
        }
        let last = page.last().expect("non-empty");
        let mut key = Vec::with_capacity(96);
        key.extend_from_slice(&last.chain);
        key.extend_from_slice(&last.donor);
        key.extend_from_slice(&last.recipient);
        cursor = Some(key);
        book.extend(page);
    }

    let mut births: Vec<crown_indexer::BirthEntry> = Vec::new();
    let mut cursor: Option<Vec<u8>> = None;
    loop {
        let page = Decode!(
            &query(
                &pic,
                indexer,
                "get_births_page",
                Encode!(&cursor, &PAGE).unwrap()
            ),
            Option<Vec<crown_indexer::BirthEntry>>
        )
        .unwrap()
        .expect("a valid cursor must not be refused");
        if page.is_empty() {
            break;
        }
        cursor = Some(page.last().expect("non-empty").escrow.clone());
        births.extend(page);
    }

    // 1. Complete — against the gauge the cutover is scheduled off. The failure
    //    this catches is a walk that stops early and reads as finished.
    let stats = Decode!(
        &query(&pic, indexer, "get_state_stats", Encode!().unwrap()),
        StateStats
    )
    .unwrap();
    assert_eq!(
        book.len() as u64,
        stats.book_keys,
        "the paged walk handed over {} of {} book keys",
        book.len(),
        stats.book_keys
    );
    assert_eq!(
        births.len() as u64,
        stats.births,
        "the paged walk handed over {} of {} births",
        births.len(),
        stats.births
    );
    assert!(
        book.len() > PAGE as usize && births.len() > PAGE as usize,
        "both enumerations must span several pages, or the cursor is untested"
    );

    // 2. Faithful — every entry equals what the point query says for the same key.
    //    A mangled field would rebuild a successor that is wrong rather than short.
    for e in &births {
        let (direct, _w) = Decode!(
            &query(&pic, indexer, "get_birth", Encode!(&e.escrow).unwrap()),
            Option<crown_indexer::BirthView>,
            Vec<u8>
        )
        .unwrap();
        let d = direct.expect("an enumerated escrow must also be queryable");
        assert_eq!(
            (d.donor, d.slot),
            (e.donor.clone(), e.slot),
            "birth entry differs from the point query"
        );
    }
    for e in &book {
        let (rep, _w) = Decode!(
            &query(
                &pic,
                indexer,
                "get_reputation",
                Encode!(&e.chain, &e.donor, &e.recipient).unwrap()
            ),
            Nat,
            Vec<u8>
        )
        .unwrap();
        assert_eq!(rep, e.reputation, "book entry differs from the point query");
    }

    println!(
        "[handover] {} book keys + {} births crossed whole in pages of {PAGE}, each matching its point query",
        book.len(),
        births.len()
    );
}
