//! The paid-ingest gate: the fixed order of cheap checks that run *before* any
//! expensive work. Non-negativity invariant #1 (cost.md §6, spec §Поверхность):
//! no outcall — indeed nothing costly — happens until payment is accepted, so an
//! unpaid or duplicate ingest costs only reads. The gate is pure; the update
//! reads `is_applied`, `msg_cycles_available`, and `canister_cycle_balance`,
//! asks the gate, and only `Proceed` may accept cycles and make the RPC call.

/// The gate's verdict. Only `Proceed` is allowed to accept cycles and do work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// Signature already folded in — nothing to do, no charge, no outcall.
    Duplicate,
    /// Attached cycles below `INGEST_PRICE` — reject before any work.
    Underpaid,
    /// Canister balance below `CYCLE_FLOOR` — refuse to dip into the reserve.
    LowBalance,
    /// Paid and healthy — accept cycles, then recognize + RPC.
    Proceed,
}

/// Decide the gate purely, in spec order: `is_applied` → attached ≥
/// `INGEST_PRICE` → balance ≥ `CYCLE_FLOOR` → proceed. The cheapest, most
/// decisive check wins first: a duplicate is free even when underpaid, and
/// underpayment is rejected before the balance floor is even consulted.
pub fn gate(
    is_applied: bool,
    attached: u128,
    balance: u128,
    ingest_price: u128,
    cycle_floor: u128,
) -> Gate {
    if is_applied {
        return Gate::Duplicate;
    }
    if attached < ingest_price {
        return Gate::Underpaid;
    }
    if balance < cycle_floor {
        return Gate::LowBalance;
    }
    Gate::Proceed
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRICE: u128 = 10_000_000_000;
    const FLOOR: u128 = 1_000_000_000_000;

    #[test]
    fn unpaid_ingest_does_not_proceed() {
        // Nothing attached, healthy balance — must not proceed (no outcall).
        assert_eq!(gate(false, 0, FLOOR, PRICE, FLOOR), Gate::Underpaid);
        // One cycle short is still underpaid.
        assert_eq!(gate(false, PRICE - 1, FLOOR, PRICE, FLOOR), Gate::Underpaid);
    }

    #[test]
    fn duplicate_is_free_even_when_paid_or_underpaid() {
        // A duplicate wins over every other verdict — never charged, never worked.
        assert_eq!(gate(true, PRICE, FLOOR, PRICE, FLOOR), Gate::Duplicate);
        assert_eq!(gate(true, 0, 0, PRICE, FLOOR), Gate::Duplicate);
    }

    #[test]
    fn paid_but_low_balance_refuses_to_touch_reserve() {
        assert_eq!(
            gate(false, PRICE, FLOOR - 1, PRICE, FLOOR),
            Gate::LowBalance
        );
    }

    #[test]
    fn paid_and_healthy_proceeds() {
        assert_eq!(gate(false, PRICE, FLOOR, PRICE, FLOOR), Gate::Proceed);
        // Overpayment proceeds too (the update accepts exactly INGEST_PRICE).
        assert_eq!(
            gate(false, PRICE * 2, FLOOR * 2, PRICE, FLOOR),
            Gate::Proceed
        );
    }
}
