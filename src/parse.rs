//! Parsing: a SOL RPC canister `getTransaction` reply → `recognize::Tx`.
//!
//! The reply carries the transaction two ways: the raw binary (base58 text) of
//! the *message* — from which we decode the account keys and the top-level
//! instructions — and `meta.innerInstructions`, the CPI instructions already in
//! compiled form. Compiled instructions index into the account-key list
//! (static keys ‖ `meta.loadedAddresses` writable ‖ readonly); we resolve those
//! indices to pubkeys so `recognize` sees real programs and accounts.
//!
//! Pure and panic-free (it runs after payment, on the ingest path): every read
//! is bounds-checked, every offset is `checked_*`. A malformed or failed
//! transaction yields `None` — never a partial fold.

use crate::recognize::{Instr, Tx};
use candid::{CandidType, Deserialize, Reserved};

// ----- candid response subset (only the fields recognition needs) -----

/// Aggregated `getTransaction` result across providers (consensus).
#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum MultiGetTransactionResult {
    Consistent(GetTransactionResult),
    Inconsistent(Vec<(Reserved, GetTransactionResult)>),
}

/// One provider's `getTransaction` result (`Ok null` = signature not found).
#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum GetTransactionResult {
    Ok(Option<TransactionReply>),
    Err(Reserved),
}

/// `EncodedConfirmedTransactionWithStatusMeta` — slot plus the encoded tx.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct TransactionReply {
    pub slot: u64,
    pub transaction: EncodedTxWithMeta,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct EncodedTxWithMeta {
    pub meta: Option<TxMeta>,
    pub transaction: EncodedTransaction,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum EncodedTransaction {
    #[serde(rename = "binary")]
    Binary(String, Encoding),
    #[serde(rename = "legacyBinary")]
    LegacyBinary(String),
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum Encoding {
    #[serde(rename = "base58")]
    Base58,
    #[serde(rename = "base64")]
    Base64,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct TxMeta {
    pub status: TxStatus,
    #[serde(rename = "innerInstructions")]
    pub inner_instructions: Option<Vec<InnerInstructions>>,
    #[serde(rename = "loadedAddresses")]
    pub loaded_addresses: Option<LoadedAddresses>,
}

/// Only the success/failure distinction matters — a reverted tx moved nothing.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum TxStatus {
    Ok,
    Err(Reserved),
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct InnerInstructions {
    pub instructions: Vec<Instruction>,
    pub index: u8,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub enum Instruction {
    #[serde(rename = "compiled")]
    Compiled(CompiledInstruction),
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct CompiledInstruction {
    pub data: String, // base58
    pub accounts: Vec<u8>,
    #[serde(rename = "programIdIndex")]
    pub program_id_index: u8,
    #[serde(rename = "stackHeight")]
    pub stack_height: Option<u32>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct LoadedAddresses {
    pub writable: Vec<String>,
    pub readonly: Vec<String>,
}

// ----- consensus + parse -----

/// Take the transaction only under provider consensus (`Consistent` + `Ok` +
/// present). `Inconsistent`, an error, or a not-found signature yields `None`.
pub fn pick_consistent(result: MultiGetTransactionResult) -> Option<TransactionReply> {
    match result {
        MultiGetTransactionResult::Consistent(GetTransactionResult::Ok(reply)) => reply,
        _ => None,
    }
}

/// Map a reply to the recognition view, or `None` if it failed / can't be read.
pub fn parse(reply: &TransactionReply) -> Option<Tx> {
    let meta = reply.transaction.meta.as_ref()?;
    // A failed transaction reverted — no tokens moved, nothing to recognize.
    if !matches!(meta.status, TxStatus::Ok) {
        return None;
    }

    let raw = decode_binary(&reply.transaction.transaction)?;
    let (mut keys, top_level) = parse_message(&raw)?;
    // Full key list = static ‖ loaded writable ‖ loaded readonly (v0 lookups).
    if let Some(la) = &meta.loaded_addresses {
        for s in la.writable.iter().chain(la.readonly.iter()) {
            keys.push(decode_pubkey(s)?);
        }
    }

    let mut instrs = Vec::with_capacity(top_level.len());
    for ci in top_level {
        instrs.push(resolve(ci.program_id_index, &ci.accounts, ci.data, &keys)?);
    }
    // Inner (CPI) instructions carry the Settled event-CPI and the transfers.
    if let Some(groups) = &meta.inner_instructions {
        for g in groups {
            for Instruction::Compiled(ci) in &g.instructions {
                let data = bs58::decode(&ci.data).into_vec().ok()?;
                instrs.push(resolve(ci.program_id_index, &ci.accounts, data, &keys)?);
            }
        }
    }
    Some(Tx {
        instrs,
        slot: reply.slot,
    })
}

/// Resolve a compiled instruction's program/account indices to pubkeys.
fn resolve(
    program_id_index: u8,
    accounts: &[u8],
    data: Vec<u8>,
    keys: &[[u8; 32]],
) -> Option<Instr> {
    let program = *keys.get(usize::from(program_id_index))?;
    let mut resolved = Vec::with_capacity(accounts.len());
    for &i in accounts {
        resolved.push(*keys.get(usize::from(i))?);
    }
    Some(Instr {
        program,
        accounts: resolved,
        data,
    })
}

/// Decode the transaction binary. We request base58, so that is the hot path;
/// base64 is unsupported (we never request it) and yields `None`.
fn decode_binary(t: &EncodedTransaction) -> Option<Vec<u8>> {
    match t {
        EncodedTransaction::Binary(text, Encoding::Base58)
        | EncodedTransaction::LegacyBinary(text) => bs58::decode(text).into_vec().ok(),
        EncodedTransaction::Binary(_, Encoding::Base64) => None,
    }
}

/// Base58 pubkey text → 32 bytes.
fn decode_pubkey(s: &str) -> Option<[u8; 32]> {
    bs58::decode(s).into_vec().ok()?.try_into().ok()
}

/// A top-level compiled instruction decoded straight from the message wire form.
struct RawCompiled {
    program_id_index: u8,
    accounts: Vec<u8>,
    data: Vec<u8>,
}

/// A bounds-checked forward cursor over the transaction bytes.
struct Cur<'a> {
    d: &'a [u8],
    i: usize,
}

impl<'a> Cur<'a> {
    /// Bytes still unread. An upper bound on how much any following field can
    /// hold — used to cap `with_capacity` so a 3-byte `compact_u16` count can
    /// never pre-allocate megabytes it has no bytes to fill.
    fn remaining(&self) -> usize {
        self.d.len().saturating_sub(self.i)
    }

    fn u8(&mut self) -> Option<u8> {
        let b = *self.d.get(self.i)?;
        self.i = self.i.checked_add(1)?;
        Some(b)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.i.checked_add(n)?;
        let s = self.d.get(self.i..end)?;
        self.i = end;
        Some(s)
    }

    fn arr32(&mut self) -> Option<[u8; 32]> {
        self.take(32)?.try_into().ok()
    }

    /// Solana `short_u16`: 1–3 bytes, 7 bits each, LSB first, high bit = more.
    fn compact_u16(&mut self) -> Option<usize> {
        let mut val: u32 = 0;
        let mut shift: u32 = 0;
        loop {
            let b = self.u8()?;
            val = val.checked_add(u32::from(b & 0x7f).checked_shl(shift)?)?;
            if b & 0x80 == 0 {
                break;
            }
            shift = shift.checked_add(7)?;
            if shift >= 21 {
                return None; // a u16 fits in at most 3 bytes
            }
        }
        if val > u32::from(u16::MAX) {
            return None;
        }
        usize::try_from(val).ok()
    }
}

/// Decode a transaction message: static account keys + top-level instructions.
/// Handles legacy and v0 (versioned) messages; v0 address-table lookups are
/// skipped here — the resolved addresses arrive via `meta.loadedAddresses`.
fn parse_message(raw: &[u8]) -> Option<(Vec<[u8; 32]>, Vec<RawCompiled>)> {
    let mut c = Cur { d: raw, i: 0 };

    // Signatures: a compact-array of 64-byte signatures (skipped).
    let num_sigs = c.compact_u16()?;
    c.take(num_sigs.checked_mul(64)?)?;

    // Version prefix: high bit set ⇒ versioned; only v0 is supported.
    let first = *raw.get(c.i)?;
    if first & 0x80 != 0 {
        if first & 0x7f != 0 {
            return None; // unknown message version
        }
        c.u8()?; // consume the version byte
    }

    // Header: numRequiredSignatures, numReadonlySigned, numReadonlyUnsigned.
    c.take(3)?;

    // Static account keys. Cap the pre-allocation by the bytes actually left
    // (32 per key): a declared count larger than the buffer just fails the read
    // below — it must not size an allocation first.
    let num_keys = c.compact_u16()?;
    let mut keys = Vec::with_capacity(num_keys.min(c.remaining() / 32));
    for _ in 0..num_keys {
        keys.push(c.arr32()?);
    }

    // Recent blockhash (skipped).
    c.take(32)?;

    // Compiled instructions. Each costs at least 3 bytes on the wire
    // (program-id index, an account count, a data length), so cap the
    // pre-allocation by `remaining / 3` — same guard as the key list.
    let num_ix = c.compact_u16()?;
    let mut ixs = Vec::with_capacity(num_ix.min(c.remaining() / 3));
    for _ in 0..num_ix {
        let program_id_index = c.u8()?;
        let num_accs = c.compact_u16()?;
        let accounts = c.take(num_accs)?.to_vec();
        let data_len = c.compact_u16()?;
        let data = c.take(data_len)?.to_vec();
        ixs.push(RawCompiled {
            program_id_index,
            accounts,
            data,
        });
    }

    Some((keys, ixs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::instruction::{AccountMeta, Instruction as SolIx};
    use solana_program::message::Message as SolMessage;
    use solana_program::pubkey::Pubkey;

    /// Full transaction wire bytes: `compact(num_sigs) ‖ zero sigs ‖ message`.
    fn tx_bytes(msg: &SolMessage) -> Vec<u8> {
        let sigs = usize::from(msg.header.num_required_signatures);
        let mut out = vec![sigs as u8]; // num_sigs < 128 → one short_u16 byte
        out.extend(vec![0u8; sigs * 64]); // zero signatures (parser skips them)
        out.extend(msg.serialize());
        out
    }

    fn reply(msg: &SolMessage, meta: Option<TxMeta>, slot: u64) -> TransactionReply {
        let bin = bs58::encode(tx_bytes(msg)).into_string();
        TransactionReply {
            slot,
            transaction: EncodedTxWithMeta {
                meta,
                transaction: EncodedTransaction::Binary(bin, Encoding::Base58),
            },
        }
    }

    fn ok_meta(inner: Option<Vec<InnerInstructions>>) -> TxMeta {
        TxMeta {
            status: TxStatus::Ok,
            inner_instructions: inner,
            loaded_addresses: None,
        }
    }

    #[test]
    fn legacy_message_round_trips_top_level_instructions() {
        let payer = Pubkey::new_unique();
        let prog_a = Pubkey::new_unique();
        let prog_b = Pubkey::new_unique();
        let acc1 = Pubkey::new_unique();
        let acc2 = Pubkey::new_unique();

        let ix_a = SolIx::new_with_bytes(
            prog_a,
            &[1, 2, 3],
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(acc1, false),
            ],
        );
        let ix_b = SolIx::new_with_bytes(prog_b, &[9, 9], vec![AccountMeta::new(acc2, false)]);
        let msg = SolMessage::new(&[ix_a, ix_b], Some(&payer));

        let r = reply(&msg, Some(ok_meta(None)), 42);
        let tx = parse(&r).expect("parses");
        assert_eq!(tx.slot, 42);
        assert_eq!(tx.instrs.len(), 2);

        // Instruction A resolves back to its exact program, accounts, and data.
        assert_eq!(tx.instrs[0].program, prog_a.to_bytes());
        assert_eq!(
            tx.instrs[0].accounts,
            vec![payer.to_bytes(), acc1.to_bytes()]
        );
        assert_eq!(tx.instrs[0].data, vec![1, 2, 3]);
        assert_eq!(tx.instrs[1].program, prog_b.to_bytes());
        assert_eq!(tx.instrs[1].accounts, vec![acc2.to_bytes()]);
        assert_eq!(tx.instrs[1].data, vec![9, 9]);
    }

    #[test]
    fn inner_instructions_are_appended_after_top_level() {
        let payer = Pubkey::new_unique();
        let prog = Pubkey::new_unique();
        let msg = SolMessage::new(
            &[SolIx::new_with_bytes(
                prog,
                &[0],
                vec![AccountMeta::new(payer, true)],
            )],
            Some(&payer),
        );
        // The message's account_keys give the indices an inner instruction uses.
        let prog_idx = msg.account_keys.iter().position(|k| *k == prog).unwrap() as u8;
        let payer_idx = msg.account_keys.iter().position(|k| *k == payer).unwrap() as u8;

        let inner = vec![InnerInstructions {
            index: 0,
            instructions: vec![Instruction::Compiled(CompiledInstruction {
                data: bs58::encode([7u8, 7]).into_string(),
                accounts: vec![payer_idx],
                program_id_index: prog_idx,
                stack_height: Some(2),
            })],
        }];

        let tx = parse(&reply(&msg, Some(ok_meta(Some(inner))), 1)).expect("parses");
        assert_eq!(tx.instrs.len(), 2); // 1 top-level + 1 inner
        assert_eq!(tx.instrs[1].program, prog.to_bytes());
        assert_eq!(tx.instrs[1].accounts, vec![payer.to_bytes()]);
        assert_eq!(tx.instrs[1].data, vec![7, 7]);
    }

    #[test]
    fn a_failed_transaction_is_not_parsed() {
        let payer = Pubkey::new_unique();
        let msg = SolMessage::new(
            &[SolIx::new_with_bytes(
                Pubkey::new_unique(),
                &[0],
                vec![AccountMeta::new(payer, true)],
            )],
            Some(&payer),
        );
        let meta = TxMeta {
            status: TxStatus::Err(Reserved),
            inner_instructions: None,
            loaded_addresses: None,
        };
        assert!(parse(&reply(&msg, Some(meta), 1)).is_none());
    }

    #[test]
    fn many_accounts_exercise_multibyte_compact_u16() {
        // 200 accounts forces a program-account count above 127 → 2-byte short_u16
        // in the compiled instruction, exercising the multi-byte decoder.
        let payer = Pubkey::new_unique();
        let prog = Pubkey::new_unique();
        let extras: Vec<Pubkey> = (0..200).map(|_| Pubkey::new_unique()).collect();
        let mut metas = vec![AccountMeta::new(payer, true)];
        metas.extend(extras.iter().map(|k| AccountMeta::new_readonly(*k, false)));
        let msg = SolMessage::new(&[SolIx::new_with_bytes(prog, &[5], metas)], Some(&payer));
        let tx = parse(&reply(&msg, Some(ok_meta(None)), 1)).expect("parses");
        assert_eq!(tx.instrs.len(), 1);
        assert_eq!(tx.instrs[0].accounts.len(), 201);
        assert_eq!(tx.instrs[0].accounts[0], payer.to_bytes());
        assert_eq!(tx.instrs[0].accounts[200], extras[199].to_bytes());
    }

    #[test]
    fn a_lying_count_cannot_preallocate_beyond_the_buffer() {
        // A tiny message whose key count claims the maximum (65535, a 3-byte
        // short_u16) but carries no key bytes: the read must fail with `None`,
        // and the capped pre-allocation must never size to the lie. `remaining`
        // is the guard — this exercises it end to end via `parse_message`.
        let mut raw = vec![0u8]; // num_sigs = 0
        raw.push(0x00); // not versioned; header byte 0 …
        raw.extend_from_slice(&[0u8, 0u8]); // … header bytes 1,2
        raw.extend_from_slice(&[0xff, 0xff, 0x03]); // num_keys = 65535, no keys follow
        assert!(parse_message(&raw).is_none());
    }

    #[test]
    fn no_consensus_or_error_yields_nothing() {
        assert!(pick_consistent(MultiGetTransactionResult::Inconsistent(vec![])).is_none());
        assert!(pick_consistent(MultiGetTransactionResult::Consistent(
            GetTransactionResult::Err(Reserved)
        ))
        .is_none());
        assert!(pick_consistent(MultiGetTransactionResult::Consistent(
            GetTransactionResult::Ok(None)
        ))
        .is_none());
    }

    // ---- wire compatibility with the real SOL-RPC canister candid ----
    //
    // The `W*` types below mirror the published DFINITY SOL-RPC canister interface
    // (`tghme-zyaaa-aaaar-qarca-cai`, `getTransaction`) field-for-field, INCLUDING
    // fields our production types deliberately do not model (`fee`, `pre/postBalances`,
    // `computeUnitsConsumed`, `blockTime`, `version`). Encoding a reply exactly as the
    // canister would, then decoding it into our production `MultiGetTransactionResult`,
    // proves the `#[serde(rename)]` mapping matches the wire and that unmodeled fields
    // are skipped — i.e. a real settlement is not silently lost. Names verified against
    // the on-chain .did; a drift in either side breaks this test.
    use candid::{Decode, Encode};

    #[derive(CandidType, Deserialize)]
    enum WEnc {
        #[serde(rename = "base58")]
        Base58,
        #[allow(dead_code)]
        #[serde(rename = "base64")]
        Base64,
    }
    #[derive(CandidType, Deserialize)]
    enum WTx {
        #[serde(rename = "binary")]
        Binary(String, WEnc),
        #[allow(dead_code)]
        #[serde(rename = "legacyBinary")]
        LegacyBinary(String),
    }
    #[derive(CandidType, Deserialize)]
    struct WCompiled {
        data: String,
        accounts: Vec<u8>,
        #[serde(rename = "programIdIndex")]
        program_id_index: u8,
        #[serde(rename = "stackHeight")]
        stack_height: Option<u32>,
    }
    #[derive(CandidType, Deserialize)]
    enum WIx {
        #[serde(rename = "compiled")]
        Compiled(WCompiled),
    }
    #[derive(CandidType, Deserialize)]
    struct WInner {
        instructions: Vec<WIx>,
        index: u8,
    }
    #[derive(CandidType, Deserialize)]
    struct WLoaded {
        writable: Vec<String>,
        readonly: Vec<String>,
    }
    #[derive(CandidType, Deserialize)]
    enum WStatus {
        Ok,
        #[allow(dead_code)]
        Err(u16),
    }
    #[derive(CandidType, Deserialize)]
    struct WMeta {
        fee: u64, // unmodeled — must be skipped
        status: WStatus,
        #[serde(rename = "innerInstructions")]
        inner_instructions: Option<Vec<WInner>>,
        #[serde(rename = "preBalances")]
        pre_balances: Vec<u64>, // unmodeled
        #[serde(rename = "postBalances")]
        post_balances: Vec<u64>, // unmodeled
        #[serde(rename = "loadedAddresses")]
        loaded_addresses: Option<WLoaded>,
        #[serde(rename = "computeUnitsConsumed")]
        compute_units_consumed: Option<u64>, // unmodeled
    }
    #[derive(CandidType, Deserialize)]
    struct WTxMeta {
        meta: Option<WMeta>,
        transaction: WTx,
        version: Option<u8>, // unmodeled
    }
    #[derive(CandidType, Deserialize)]
    struct WReply {
        slot: u64,
        #[serde(rename = "blockTime")]
        block_time: Option<i64>, // unmodeled
        transaction: WTxMeta,
    }
    #[derive(CandidType, Deserialize)]
    enum WGetRes {
        Ok(Option<WReply>),
        #[allow(dead_code)]
        Err(u16),
    }
    #[derive(CandidType, Deserialize)]
    enum WMulti {
        Consistent(WGetRes),
        #[allow(dead_code)]
        Inconsistent(Vec<(u8, WGetRes)>),
    }

    #[test]
    fn real_wire_shape_decodes_and_skips_unmodeled_fields() {
        let wire = WMulti::Consistent(WGetRes::Ok(Some(WReply {
            slot: 4242,
            block_time: Some(1_700_000_000),
            transaction: WTxMeta {
                version: Some(0),
                meta: Some(WMeta {
                    fee: 5000,
                    status: WStatus::Ok,
                    inner_instructions: Some(vec![WInner {
                        index: 0,
                        instructions: vec![WIx::Compiled(WCompiled {
                            data: "aBc58".to_string(),
                            accounts: vec![0, 1],
                            program_id_index: 2,
                            stack_height: Some(2),
                        })],
                    }]),
                    pre_balances: vec![1, 2, 3],
                    post_balances: vec![1, 2, 3],
                    loaded_addresses: Some(WLoaded {
                        writable: vec!["Wr1".to_string()],
                        readonly: vec!["Ro1".to_string()],
                    }),
                    compute_units_consumed: Some(1234),
                }),
                transaction: WTx::Binary("txBase58".to_string(), WEnc::Base58),
            },
        })));

        // Encode as the canister would, decode into OUR production type.
        let bytes = Encode!(&wire).expect("candid encode");
        let multi = Decode!(&bytes, MultiGetTransactionResult).expect("wire decodes into ours");
        let reply = pick_consistent(multi).expect("Consistent Ok(Some)");

        // Every field our recognition depends on survived the rename + field-skip.
        assert_eq!(reply.slot, 4242);
        let meta = reply.transaction.meta.as_ref().expect("meta present");
        assert!(matches!(meta.status, TxStatus::Ok), "status Ok gate");
        assert!(matches!(
            reply.transaction.transaction,
            EncodedTransaction::Binary(ref s, Encoding::Base58) if s == "txBase58"
        ));
        let inner = meta.inner_instructions.as_ref().expect("innerInstructions");
        let Instruction::Compiled(ci) = &inner[0].instructions[0];
        assert_eq!(ci.program_id_index, 2); // programIdIndex
        assert_eq!(ci.stack_height, Some(2)); // stackHeight
        assert_eq!(ci.accounts, vec![0, 1]); // blob
        let la = meta.loaded_addresses.as_ref().expect("loadedAddresses");
        assert_eq!(la.writable, vec!["Wr1".to_string()]);
        assert_eq!(la.readonly, vec!["Ro1".to_string()]);
    }
}
