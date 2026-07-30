//! The single paid outcall: `getTransaction` on the NNS SOL RPC canister
//! (`tghme-zyaaa-aaaar-qarca-cai`), `commitment = finalized`, provider
//! consensus ≥ `CONSENSUS`, response capped at `RESPONSE_MAX_BYTES`
//! (non-negativity invariant #1). Only the request-side candid types live here;
//! the reply types and parsing are in `parse`.

use crate::config::{ATTACH_CYCLES, CLUSTER, CONSENSUS, RESPONSE_MAX_BYTES, RPC_PROVIDERS};
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
            // `total` is stated rather than left to the canister's default. With
            // `None` the queried count is whatever the default set holds — three
            // — so `min: 3` becomes 3-of-3: a single flaky provider fails every
            // read, and every ingest is charged for a settlement that never lands.
            // Naming the total
            // buys `CONSENSUS`-of-`RPC_PROVIDERS` (3-of-5 today, two failures
            // tolerated) and makes the cost model honest — it prices exactly the
            // providers this now asks for. `build.rs` gates
            // `CONSENSUS <= RPC_PROVIDERS <= 255`.
            total: Some(RPC_PROVIDERS as u8),
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

#[cfg(test)]
mod tests {
    use super::*;
    use candid::{Decode, Encode};

    // ---- wire compatibility of the *request* with the real SOL-RPC canister ----
    //
    // `parse` proves the reply decodes; nothing proved the request encodes. It is
    // the more dangerous half: candid drops a record field whose name-hash the
    // callee does not know, so a misspelled `responseConsensus` would not error —
    // the canister would simply fall back to its default strategy and the ≥3
    // provider agreement the index recognizes settlements on would quietly stop
    // being enforced. The `W*` types below mirror `sol_rpc_canister.did`
    // field-for-field; encoding *our* argument tuple and decoding it into *theirs*
    // is what a real call does, so a drift on either side breaks this test.
    //
    // `RpcSources` is deliberately one-armed here and two-armed there: a variant
    // with fewer alternatives is a candid subtype, which is exactly why `Custom`
    // is not expressible in this canister (`docs/spec.md §Конфиг`).

    #[derive(CandidType, Deserialize, Debug, PartialEq)]
    enum WCluster {
        Mainnet,
        Devnet,
        Testnet,
    }
    #[derive(CandidType, Deserialize, Debug, PartialEq)]
    enum WRpcSources {
        Custom(candid::Reserved),
        Default(WCluster),
    }
    #[derive(CandidType, Deserialize, Debug, PartialEq)]
    enum WConsensusStrategy {
        Equality,
        Threshold { total: Option<u8>, min: u8 },
    }
    #[derive(CandidType, Deserialize, Debug, PartialEq)]
    struct WRpcConfig {
        #[serde(rename = "responseSizeEstimate")]
        response_size_estimate: Option<u64>,
        #[serde(rename = "responseConsensus")]
        response_consensus: Option<WConsensusStrategy>,
    }
    #[derive(CandidType, Deserialize, Debug, PartialEq)]
    enum WCommitmentLevel {
        #[serde(rename = "processed")]
        Processed,
        #[serde(rename = "confirmed")]
        Confirmed,
        #[serde(rename = "finalized")]
        Finalized,
    }
    #[derive(CandidType, Deserialize, Debug, PartialEq)]
    enum WEncoding {
        #[serde(rename = "base58")]
        Base58,
        #[serde(rename = "base64")]
        Base64,
    }
    #[derive(CandidType, Deserialize, Debug, PartialEq)]
    struct WGetTransactionParams {
        signature: String,
        commitment: Option<WCommitmentLevel>,
        #[serde(rename = "maxSupportedTransactionVersion")]
        max_supported_transaction_version: Option<u8>,
        encoding: Option<WEncoding>,
    }

    /// The argument tuple `fetch` builds, encoded and decoded as the SOL RPC
    /// canister would — every field the index depends on has to survive the trip.
    #[test]
    fn the_request_encodes_to_what_the_sol_rpc_canister_expects() {
        let sources = RpcSources::Default(cluster());
        let config = RpcConfig {
            response_size_estimate: Some(RESPONSE_MAX_BYTES),
            response_consensus: Some(ConsensusStrategy::Threshold {
                total: Some(RPC_PROVIDERS as u8),
                min: CONSENSUS,
            }),
        };
        let params = GetTransactionParams {
            signature: "5j7s…".to_string(),
            commitment: Some(CommitmentLevel::Finalized),
            max_supported_transaction_version: Some(0),
            encoding: Some(Encoding::Base58),
        };

        let bytes = Encode!(&sources, &Some(config), &params).expect("encode");
        let (w_sources, w_config, w_params) = Decode!(
            &bytes,
            WRpcSources,
            Option<WRpcConfig>,
            WGetTransactionParams
        )
        .expect("our request decodes as the canister's argument types");

        // Devnet on this profile, and `Default` — no URLs ever leave this canister.
        assert_eq!(w_sources, WRpcSources::Default(WCluster::Devnet));

        let w_config = w_config.expect("the config record survived as `opt`");
        // Invariant #1: the cap the ingest is priced on actually reaches the wire.
        assert_eq!(w_config.response_size_estimate, Some(RESPONSE_MAX_BYTES));
        // And the consensus strategy — the field that fails *silently* if its name
        // ever drifts, taking the ≥3-provider guarantee with it.
        assert_eq!(
            w_config.response_consensus,
            Some(WConsensusStrategy::Threshold {
                total: Some(5),
                min: 3
            })
        );

        assert_eq!(w_params.signature, "5j7s…");
        assert_eq!(w_params.commitment, Some(WCommitmentLevel::Finalized)); // always
        assert_eq!(w_params.max_supported_transaction_version, Some(0)); // v0 + ALTs
        assert_eq!(w_params.encoding, Some(WEncoding::Base58));
    }

    /// The pinned principal, as raw bytes so the ingest path needs no fallible
    /// text parsing. If the constant is ever retyped, this says what it must mean.
    #[test]
    fn the_pinned_principal_is_the_nns_sol_rpc_canister() {
        assert_eq!(
            Principal::from_slice(&SOL_RPC).to_text(),
            "tghme-zyaaa-aaaar-qarca-cai"
        );
    }
}
