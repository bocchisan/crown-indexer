//! The single paid outcall: `getTransaction` on the NNS SOL RPC canister
//! (`tghme-zyaaa-aaaar-qarca-cai`), `commitment = finalized`, provider
//! consensus ≥ `CONSENSUS`, response capped at `RESPONSE_MAX_BYTES`
//! (non-negativity invariant #1). Only the request-side candid types live here;
//! the reply types and parsing are in `parse`.

use crate::config::{ATTACH_CYCLES, CLUSTER, CONSENSUS, RESPONSE_MAX_BYTES};
use crate::parse::{self, Encoding, MultiGetTransactionResult, TransactionReply};
use candid::{CandidType, Deserialize, Principal};
use ic_cdk::call::Call;

/// The NNS SOL RPC canister principal (`tghme-zyaaa-aaaar-qarca-cai`), as raw
/// bytes so it needs no fallible text parsing on the ingest path.
const SOL_RPC: [u8; 10] = [0, 0, 0, 0, 2, 48, 4, 68, 1, 1];

#[derive(CandidType, Deserialize)]
enum SolanaCluster {
    Mainnet,
    Devnet,
    Testnet,
}

/// We only ever build `Default(cluster)` — mainnet requires it, and providers
/// are configured on the SOL RPC canister, not passed as URLs from here.
#[derive(CandidType, Deserialize)]
enum RpcSources {
    Default(SolanaCluster),
}

#[derive(CandidType, Deserialize)]
enum ConsensusStrategy {
    Equality,
    Threshold { total: Option<u8>, min: u8 },
}

#[derive(CandidType, Deserialize)]
struct RpcConfig {
    #[serde(rename = "responseSizeEstimate")]
    response_size_estimate: Option<u64>,
    #[serde(rename = "responseConsensus")]
    response_consensus: Option<ConsensusStrategy>,
}

#[derive(CandidType, Deserialize)]
enum CommitmentLevel {
    #[serde(rename = "processed")]
    Processed,
    #[serde(rename = "confirmed")]
    Confirmed,
    #[serde(rename = "finalized")]
    Finalized,
}

#[derive(CandidType, Deserialize)]
struct GetTransactionParams {
    signature: String,
    commitment: Option<CommitmentLevel>,
    #[serde(rename = "maxSupportedTransactionVersion")]
    max_supported_transaction_version: Option<u8>,
    encoding: Option<Encoding>,
}

fn cluster() -> SolanaCluster {
    match CLUSTER {
        0 => SolanaCluster::Mainnet,
        2 => SolanaCluster::Testnet,
        _ => SolanaCluster::Devnet,
    }
}

/// Fetch a finalized transaction under provider consensus, or `None` if the call
/// fails, the providers disagree, or the signature is unknown.
pub async fn fetch(signature: String) -> Option<TransactionReply> {
    let sources = RpcSources::Default(cluster());
    let config = RpcConfig {
        // Cap the response so a bloated tx can never cost more than INGEST_PRICE.
        response_size_estimate: Some(RESPONSE_MAX_BYTES),
        response_consensus: Some(ConsensusStrategy::Threshold {
            total: None,
            min: CONSENSUS,
        }),
    };
    let params = GetTransactionParams {
        signature,
        commitment: Some(CommitmentLevel::Finalized), // finality: always
        max_supported_transaction_version: Some(0),   // accept v0 + get loadedAddresses
        encoding: Some(Encoding::Base58),
    };

    let response = Call::unbounded_wait(Principal::from_slice(&SOL_RPC), "getTransaction")
        .with_args(&(sources, Some(config), params))
        .with_cycles(ATTACH_CYCLES)
        .await
        .ok()?;
    let multi: MultiGetTransactionResult = response.candid().ok()?;
    parse::pick_consistent(multi)
}
