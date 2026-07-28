//! PocketIC end-to-end on a real IC replica.
//!
//! Ingress messages cannot attach cycles, so an ingress `ingest` is always
//! *unpaid* — which is exactly the non-negativity invariant #8 case: it must be
//! rejected before any outcall. The paid path (a cycle-attaching caller + a mock
//! SOL RPC canister) is a separate harness.
//!
//! Run with the bundled server:
//!   POCKET_IC_BIN=~/.cache/dfinity/versions/<v>/pocket-ic cargo test --test e2e

use candid::{Decode, Encode, Nat, Principal};
use crown_indexer::config;
use crown_indexer::parse::{
    EncodedTransaction, EncodedTxWithMeta, Encoding, GetTransactionResult,
    MultiGetTransactionResult, TransactionReply, TxMeta, TxStatus,
};
use crown_indexer::IngestResult;
use pocket_ic::{PocketIc, PocketIcBuilder};

const T_CYCLES: u128 = 4_000_000_000_000;

/// SPL Token program id and Anchor's `emit_cpi!` tag — the recognition anchors.
const TOKEN_PROGRAM: [u8; 32] = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172, 28, 180, 133, 237,
    95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];
const EVENT_IX_TAG: [u8; 8] = [0xe4, 0x45, 0xa5, 0x2e, 0x51, 0xcb, 0x9a, 0x1d];

fn indexer_wasm() -> Vec<u8> {
    let path = "target/wasm32-unknown-unknown/release/crown_indexer.wasm";
    if !std::path::Path::new(path).exists() {
        let status = std::process::Command::new("cargo")
            .args([
                "build",
                "--lib",
                "--release",
                "--target",
                "wasm32-unknown-unknown",
            ])
            .status()
            .expect("cargo build");
        assert!(status.success(), "failed to build the indexer wasm");
    }
    std::fs::read(path).expect("read indexer wasm")
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
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_fiduciary_subnet()
        .with_application_subnet()
        .build();
    let app = pic.topology().get_app_subnets()[0];
    let indexer = pic.create_canister_on_subnet(None, None, app);
    pic.add_cycles(indexer, T_CYCLES);
    pic.install_canister(indexer, indexer_wasm(), Encode!().unwrap(), None);

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

/// A canned `getTransaction` reply carrying a direct-donation `Settled` from the
/// pinned splitter plus its matching `TransferChecked` (mint = the baked USDC).
fn canned_response(donor: [u8; 32], recipient: [u8; 32], gross: u64, slot: u64) -> Vec<u8> {
    use solana_program::instruction::{AccountMeta, Instruction as SolIx};
    use solana_program::message::Message as SolMessage;
    use solana_program::pubkey::Pubkey;

    let donor_pk = Pubkey::new_from_array(donor);
    let mint_pk = Pubkey::new_from_array(config::USDC); // baked (placeholder [0;32])
    let token_pk = Pubkey::new_from_array(TOKEN_PROGRAM);
    let splitter_pk = Pubkey::new_from_array(config::SPLITTER);
    let source = Pubkey::new_unique();
    let dest = Pubkey::new_unique();

    // TransferChecked: accounts [source, mint, dest, authority].
    let mut transfer_data = vec![12u8];
    transfer_data.extend_from_slice(&gross.to_le_bytes());
    transfer_data.push(6);
    let transfer_ix = SolIx {
        program_id: token_pk,
        accounts: vec![
            AccountMeta::new(source, false),
            AccountMeta::new_readonly(mint_pk, false),
            AccountMeta::new(dest, false),
            AccountMeta::new_readonly(donor_pk, true),
        ],
        data: transfer_data,
    };

    // Settled event-CPI (tag ‖ disc ‖ donor ‖ recipient ‖ gross).
    let mut settled_data = Vec::new();
    settled_data.extend_from_slice(&EVENT_IX_TAG);
    settled_data.extend_from_slice(&settled_discriminator());
    settled_data.extend_from_slice(&donor);
    settled_data.extend_from_slice(&recipient);
    settled_data.extend_from_slice(&gross.to_le_bytes());
    let settled_ix = SolIx {
        program_id: splitter_pk,
        accounts: vec![],
        data: settled_data,
    };

    let msg = SolMessage::new(&[transfer_ix, settled_ix], Some(&donor_pk));
    let sigs = usize::from(msg.header.num_required_signatures);
    let mut raw = vec![sigs as u8];
    raw.extend(vec![0u8; sigs * 64]);
    raw.extend(msg.serialize());

    let reply = TransactionReply {
        slot,
        transaction: EncodedTxWithMeta {
            meta: Some(TxMeta {
                status: TxStatus::Ok,
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

fn relay_ingest(pic: &PocketIc, mock: Principal, indexer: Principal, sig: &str) -> IngestResult {
    let cycles = (config::INGEST_PRICE as u64) * 3; // > INGEST_PRICE + ATTACH_CYCLES
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
    let donor = [7u8; 32];
    let recipient = [8u8; 32];
    let gross = 500_000u64;
    pic.update_call(
        mock,
        Principal::anonymous(),
        "set_response",
        Encode!(&canned_response(donor, recipient, gross, 123)).unwrap(),
    )
    .expect("set_response");

    // Paid ingest through the relay → one settlement folded.
    let res = relay_ingest(&pic, mock, indexer, "sig-1");
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
    let calls = Decode!(&query(&pic, mock, "calls", Encode!().unwrap()), u64).unwrap();
    assert_eq!(calls, 1);
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
    let calls_after = Decode!(&query(&pic, mock, "calls", Encode!().unwrap()), u64).unwrap();
    assert_eq!(calls_after, 1, "a duplicate must not make another outcall");
}
