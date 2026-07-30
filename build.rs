//! Bakes the active config profile (`config/<profile>.toml`) into the wasm.
//! Nothing network lives in code: the splitter/USDC/factory addresses, the
//! per-chain identity, and the freezable cost-gate constants all come from
//! `config/`. Addresses are base58-decoded here to `[u8; 32]`, so the runtime
//! carries no base58 decoder. Placeholders (pre-e2e testnet) decode to a zero
//! address / empty factory list — safe: nothing matches until config is filled.
//! On the frozen `mainnet` profile a placeholder is a hard error.
//!
//! **Numbers are not judged here.** Every freezable-constant law — the cycle
//! ordering, the consensus shape, the non-zero floors — is a `const _: () =
//! assert!(…)` in `config.rs`, checked by the compiler on the constants that
//! actually reached the code. Restating them here meant a second copy of the
//! outcall cost model with nothing keeping the two in step, on the one number the
//! freeze depends on; and it could not fail any earlier than the compile that
//! follows it. Add a freezable constant → add its gate in `config.rs`.
//!
//! What stays here is what only exists at bake time: whether the *text* decodes
//! at all (placeholders), and whether the decoded recognition roots are distinct.
//! Those have one copy, and it is this one.

use sha2::{Digest, Sha256};
use std::{env, fs, path::Path};

fn main() {
    // `cutover` is a test-only profile: identical to `testnet` but with the
    // generation boundary switched on, so the `AfterCutover` path — mechanism #1
    // of the handoff (architecture §8) — is exercised by a real build instead of
    // running for the first time in production on a canister nobody can fix.
    println!(
        "cargo:rustc-check-cfg=cfg(crown_profile, values(\"testnet\", \"mainnet\", \"cutover\"))"
    );
    let profile = env::var("CROWN_PROFILE").unwrap_or_else(|_| "testnet".to_string());
    println!("cargo:rustc-cfg=crown_profile=\"{profile}\"");
    println!("cargo:rerun-if-env-changed=CROWN_PROFILE");

    let cfg_path = format!("config/{profile}.toml");
    println!("cargo:rerun-if-changed={cfg_path}");
    let text = fs::read_to_string(&cfg_path).unwrap_or_else(|_| panic!("missing {cfg_path}"));
    let strict = profile == "mainnet"; // frozen profile: placeholders are an error

    let ingest_price = u128_of(&text, "ingest_price");
    let min_gross = u128_of(&text, "min_gross");
    let cycle_floor = u128_of(&text, "cycle_floor");
    let attach_cycles = u128_of(&text, "attach_cycles");
    let response_max_bytes = u128_of(&text, "response_max_bytes") as u64;
    let consensus = u128_of(&text, "consensus") as u8;
    // `0` in config means "no boundary"; it is baked as `None` rather than a
    // sentinel so the ingest path branches on absence instead of comparing against
    // a magic slot number.
    let cutover_slot = match u128_of(&text, "cutover_slot") as u64 {
        0 => "None".to_string(),
        n => format!("Some({n})"),
    };
    // Inputs of the outcall cost model. Baked, not judged: `config.rs` computes
    // the worst case from these same constants and refuses to compile a config
    // that violates the cycle ordering (non-negativity invariant #1).
    let rpc_nodes = u128_of(&text, "rpc_nodes");
    let rpc_providers = u128_of(&text, "rpc_providers");
    let rpc_request_bytes = u128_of(&text, "rpc_request_bytes");

    let id = str_of(&text, "id");
    // Cluster for the SOL RPC `Default` source: 0=Mainnet, 1=Devnet, 2=Testnet.
    let cluster: u8 = match id.as_str() {
        "mainnet" => 0,
        "devnet" => 1,
        "testnet" => 2,
        other => panic!("unknown cluster id `{other}` (expected mainnet/devnet/testnet)"),
    };
    let chain_id = sha256(&[b"crown-chain:v1:", id.as_bytes()]);
    let splitter = addr(&str_of(&text, "splitter"), "splitter", strict);
    let usdc = addr(&str_of(&text, "usdc"), "usdc", strict);
    let factories: Vec<[u8; 32]> = factory_list(&text)
        .iter()
        .filter_map(|s| addr_opt(s, "factory", strict))
        .collect();

    // Recognition roots, on the frozen profile only: a placeholder already panics
    // above, but a config that is *well-formed and wrong* would not. Each of these
    // is silent and permanent if it ships — the index would recognize nothing, or
    // confuse a settlement for a birth, with no way to correct it. Checked here
    // because this is where the addresses exist as decoded bytes; there is no
    // second copy in `config.rs`.
    if strict {
        assert!(
            !factories.is_empty(),
            "mainnet with no factories recognizes no births, so every escrow \
             settlement is credited to the escrow address instead of its donor"
        );
        assert!(
            splitter != usdc,
            "splitter and usdc are the same address — one of them is wrong"
        );
        for (i, f) in factories.iter().enumerate() {
            assert!(
                *f != splitter && *f != usdc,
                "factory #{i} collides with the splitter or the mint"
            );
            assert!(
                factories.iter().skip(i + 1).all(|o| o != f),
                "factory #{i} is listed twice"
            );
        }
    }

    let out = format!(
        "// Baked from {cfg_path} — do not edit. Nothing network lives in code.\n\
         pub const PROFILE: &str = {profile:?};\n\
         pub const INGEST_PRICE: u128 = {ingest_price};\n\
         pub const MIN_GROSS: u128 = {min_gross};\n\
         pub const CYCLE_FLOOR: u128 = {cycle_floor};\n\
         /// Cycles attached to the SOL RPC `getTransaction` outcall (≤ `INGEST_PRICE`).\n\
         pub const ATTACH_CYCLES: u128 = {attach_cycles};\n\
         /// `max_response_bytes` cap on the outcall (non-negativity invariant #1).\n\
         pub const RESPONSE_MAX_BYTES: u64 = {response_max_bytes};\n\
         /// Inputs of the outcall cost model, so the code that spends the cycles\n\
         /// can re-derive the same worst case the config was gated on.\n\
         pub const RPC_NODES: u128 = {rpc_nodes};\n\
         pub const RPC_PROVIDERS: u128 = {rpc_providers};\n\
         pub const RPC_REQUEST_BYTES: u128 = {rpc_request_bytes};\n\
         pub const CONSENSUS: u8 = {consensus};\n\
         /// Generation boundary (architecture §8): the first slot that belongs to\n\
         /// the *next* generation. A transaction at or past it is refused, so two\n\
         /// generations never fold the same settlement and their books can be\n\
         /// summed. `None` = no boundary (a single generation).\n\
         pub const CUTOVER_SLOT: Option<u64> = {cutover_slot};\n\
         /// SOL RPC `Default` cluster: 0=Mainnet, 1=Devnet, 2=Testnet.\n\
         pub const CLUSTER: u8 = {cluster};\n\
         /// ChainId = sha256(\"crown-chain:v1:\" then id) — the opaque book-key cluster identity.\n\
         pub const CHAIN_ID: [u8; 32] = {chain_id:?};\n\
         /// Pinned recognition root #1 (`Settled` splitter). Zero if a placeholder.\n\
         pub const SPLITTER: [u8; 32] = {splitter:?};\n\
         /// Pinned USDC mint (native Circle). Zero if a placeholder.\n\
         pub const USDC: [u8; 32] = {usdc:?};\n\
         /// Pinned factories whose `create_escrow` is a birth. Empty if all placeholders.\n\
         pub const FACTORIES: &[[u8; 32]] = &{factories:?};\n",
    );
    let dst = Path::new(&env::var("OUT_DIR").unwrap()).join("config.rs");
    fs::write(&dst, out).unwrap();
}

/// sha256 over the concatenated parts.
fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The raw value token of `key = <token>` (before any trailing `#` comment),
/// stripped of surrounding whitespace and one layer of quotes.
fn str_of(text: &str, key: &str) -> String {
    text.lines()
        .find_map(|l| {
            let rest = l.trim().strip_prefix(key)?.trim_start().strip_prefix('=')?;
            let rest = rest.split('#').next().unwrap_or(rest).trim();
            Some(rest.trim_matches('"').to_string())
        })
        .unwrap_or_else(|| panic!("missing `{key}` in config"))
}

/// A `u128` value, tolerating `_` digit separators.
fn u128_of(text: &str, key: &str) -> u128 {
    let raw = str_of(text, key);
    raw.replace('_', "")
        .parse()
        .unwrap_or_else(|_| panic!("`{key}` = `{raw}` is not an integer"))
}

/// The bracketed `factories = ["a", "b"]` list as its quoted elements.
fn factory_list(text: &str) -> Vec<String> {
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("factories"))
        .unwrap_or_else(|| panic!("missing `factories` in config"));
    let inner = line
        .split_once('[')
        .and_then(|(_, r)| r.split_once(']'))
        .map(|(inner, _)| inner)
        .unwrap_or("");
    inner
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Base58-decode a required address; a placeholder → zero (or a hard error on
/// the frozen profile).
fn addr(s: &str, what: &str, strict: bool) -> [u8; 32] {
    addr_opt(s, what, strict).unwrap_or([0u8; 32])
}

/// Base58-decode an address, or `None` for a placeholder. Any non-base58 or
/// wrong-length value is treated as a placeholder unless `strict` (mainnet),
/// where it panics — the frozen profile must carry only real addresses.
fn addr_opt(s: &str, what: &str, strict: bool) -> Option<[u8; 32]> {
    match bs58::decode(s).into_vec() {
        Ok(v) if v.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            Some(a)
        }
        _ => {
            if strict {
                panic!("`{what}` = `{s}` is not a valid address (mainnet requires real addresses)");
            }
            println!(
                "cargo:warning=crown-indexer: `{what}` is a placeholder (`{s}`) — baked as unset"
            );
            None
        }
    }
}
