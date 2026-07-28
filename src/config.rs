//! Baked network config (`build.rs` from `config/<profile>.toml`). Nothing
//! network lives in code; this module only turns the baked constants into the
//! runtime `ChainConfig` and the freezable cost-gate constants the gate reads.

use crate::recognize::ChainConfig;
use crown_reduce::ChainId;

include!(concat!(env!("OUT_DIR"), "/config.rs"));

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

    #[test]
    fn testnet_cost_gate_constants_are_baked() {
        // Straight from config/testnet.toml — the freezable cost-gate values.
        assert_eq!(PROFILE, "testnet");
        assert_eq!(INGEST_PRICE, 10_000_000_000);
        assert_eq!(MIN_GROSS, 200_000);
        assert_eq!(chain_config().min_gross, 200_000); // floor wired into recognition
        assert_eq!(CYCLE_FLOOR, 1_000_000_000_000);
        assert_eq!(CONSENSUS, 3);
    }

    #[test]
    fn chain_id_is_the_documented_derivation() {
        // ChainId = sha256("crown-chain:v1:" ‖ id), id = "devnet".
        let mut h = Sha256::new();
        h.update(b"crown-chain:v1:");
        h.update(b"devnet");
        let expected: [u8; 32] = h.finalize().into();
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
