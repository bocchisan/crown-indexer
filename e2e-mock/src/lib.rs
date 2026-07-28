//! Mock canister for the paid-ingest e2e. It is deliberately type-agnostic: the
//! test candid-encodes a `MultiGetTransactionResult` (using the indexer's own
//! types) and hands the raw bytes to `set_response`; `getTransaction` replies
//! them verbatim via `msg_reply`. It also acts as the cycle-attaching caller
//! (`relay_ingest`) since ingress messages can't carry cycles.

use candid::{CandidType, Deserialize, Principal, Reserved};
use ic_cdk::call::Call;
use std::cell::RefCell;

thread_local! {
    static RESPONSE: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static CALLS: RefCell<u64> = const { RefCell::new(0) };
    static LAST_CAP: RefCell<Option<u64>> = const { RefCell::new(None) };
}

/// Minimal probe of the RPC config: only the response cap matters here (candid
/// record subtyping ignores the other fields).
#[derive(CandidType, Deserialize)]
struct ConfigProbe {
    #[serde(rename = "responseSizeEstimate")]
    response_size_estimate: Option<u64>,
}

/// Store the raw candid bytes `getTransaction` will reply with.
#[ic_cdk::update]
fn set_response(bytes: Vec<u8>) {
    RESPONSE.with(|r| *r.borrow_mut() = bytes);
}

/// How many times `getTransaction` was called (0 proves no outcall happened).
#[ic_cdk::query]
fn calls() -> u64 {
    CALLS.with(|c| *c.borrow())
}

/// The `responseSizeEstimate` the indexer sent on the last call (invariant #1).
#[ic_cdk::query]
fn last_cap() -> Option<u64> {
    LAST_CAP.with(|c| *c.borrow())
}

/// The SOL RPC `getTransaction` the indexer calls. Args are ignored except the
/// response cap; the stored bytes are replied raw so this canister needs none of
/// the indexer's response types.
#[ic_cdk::update(name = "getTransaction", manual_reply = true)]
fn get_transaction(_sources: Reserved, config: Option<ConfigProbe>, _params: Reserved) {
    CALLS.with(|c| *c.borrow_mut() += 1);
    LAST_CAP.with(|c| *c.borrow_mut() = config.and_then(|x| x.response_size_estimate));
    let bytes = RESPONSE.with(|r| r.borrow().clone());
    ic_cdk::api::msg_reply(bytes);
}

/// Call the indexer's `ingest` with `cycles` attached (from this canister's
/// balance), returning the raw reply bytes for the test to decode.
#[ic_cdk::update]
async fn relay_ingest(indexer: Principal, signature: String, cycles: u64) -> Vec<u8> {
    Call::unbounded_wait(indexer, "ingest")
        .with_arg(signature)
        .with_cycles(u128::from(cycles))
        .await
        .expect("ingest call failed")
        .into_bytes()
}
