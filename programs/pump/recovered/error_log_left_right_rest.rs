//! Captured Pump `Left:` / `Right:` error log lines, continued: the sites
//! `error_log_left_right.rs` lists as unconfirmed, minus the
//! `claim_cashback_v2` sites in the token-incentives handlers, which stay
//! unconfirmed.
//!
//! Checked against `evidence/original/pump/deployed.so` on LiteSVM by
//! `tests/test_error_log_left_right_rest_captured.py`, which records the
//! failing transactions of the base packet's case selection, the
//! `multi_hop_curve_swap` routes of the Token-2022 multi-hop packet, and a
//! small fixture of its own for the `buy_v2.rs:121` token-owner check. The
//! log form is the one the base packet documents: an error line followed at
//! once by `Left:` / key / `Right:` / key while Pump is the running program.
//! This is not a byte-identity claim.
//!
//! The new side forms, beyond the base packet's:
//!
//! - `Remaining(n)` / `OwnerOfRemaining(n)`: the key (or its owner) passed
//!   at position `n` of the instruction's remaining accounts. `create_v2`
//!   reads its quote mint at 0, the mint's associated account at 1, the
//!   quote token program at 2, the quote-control account at 3, and the
//!   quote chain's pool records from 4 on.
//! - `StoredMint(slot)`: the mint field (data bytes 0..32) of the token
//!   account passed in the named slot.
//! - `StoredTokenOwner(slot)`: the owner field (data bytes 32..64) of the
//!   token account passed in the named slot.
//! - `QuoteAta`: the associated token address the ATA program derives for
//!   the bonding curve over the remaining quote mint and program — the
//!   test recomputes the derivation, so this side is checked exactly.
//! - `AncestorCurve`: the bonding-curve address the create_v2 chain walk
//!   derives for the remaining quote mint — also recomputed by the test.
//! - `HolderPassedAta` / `HolderDerivedAta`: `distribute_fee_to_holders`
//!   walks its remaining accounts in (recipient, token account) pairs; the
//!   pair is the first pair whose passed token account is not the address
//!   the ATA program derives for the recipient over the quote mint and
//!   quote token program, and the derived address for that pair.
//! - `HopQuoteMint`: `multi_hop_curve_swap` walks its remaining accounts in
//!   groups of five per hop, two of them the hop's mints; the running mint
//!   starts at the source account's stored mint, and each hop's other mint
//!   is the mint it swaps into. The buyback recipient is validated hop by
//!   hop, so this side is the first hop mint that differs from the
//!   recipient account's stored mint.
//! - `RouteFinalMint`: the running mint after the last hop of that walk.
//!
//! Unconfirmed (outside the checked inputs): the `claim_cashback_v2` sites
//! in `token_incentives/claim_token_incentives.rs`; the create_v2 chain
//! guards past the first pool record (the walk's deeper ancestor accounts);
//! and `buy_v2.rs:121` under the `buy`, `buy_v2` and `sell_v2` handlers,
//! whose corpora do not reach it — every call site checks the quote user
//! account against the user, and the rows below pin the v3 handlers the
//! fixture reaches.

/// How the line names the place that failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `AnchorError thrown in programs/pump/src/<file>:<line>.`
    Thrown,
    /// `AnchorError caused by account: <name>.`
    Account,
    /// `ProgramError caused by account: <name>.`
    Program,
    /// `AnchorError occurred.`
    Occurred,
}

/// What one side of a logged pair is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The Pump program itself.
    Pump,
    /// The unsupported quote mint, `9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP`.
    UnsupportedQuoteMint,
    /// The quote-control account, derived from the seed `quote-control`.
    QuoteControl,
    /// The key passed in the named instruction account slot.
    Slot(&'static str),
    /// The key passed at this position of the remaining accounts.
    Remaining(u32),
    /// The owner of the account passed at this position of the remaining
    /// accounts.
    OwnerOfRemaining(u32),
    /// The mint field stored in the token account passed in the named slot.
    StoredMint(&'static str),
    /// The owner field stored in the token account passed in the named slot.
    StoredTokenOwner(&'static str),
    /// The ATA derived for the bonding curve over the remaining quote mint
    /// and quote token program.
    QuoteAta,
    /// The bonding-curve address derived for the remaining quote mint.
    AncestorCurve,
    /// The passed token account of the first mismatching holder pair.
    HolderPassedAta,
    /// The ATA derived for the recipient of that pair.
    HolderDerivedAta,
    /// The first hop mint that differs from the buyback recipient's stored
    /// mint, in the multi-hop walk.
    HopQuoteMint,
    /// The running mint after the last hop of the multi-hop walk.
    RouteFinalMint,
}

impl Side {
    /// The constant key this side prints, when it is a constant.
    pub fn constant(self) -> Option<&'static str> {
        Some(match self {
            Side::Pump => "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P",
            Side::UnsupportedQuoteMint => "9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP",
            Side::QuoteControl => "6z6GDdfb2AjR9ZhJmAUQ5cipJCVxQvLJhB2H8mCwTFBP",
            _ => return None,
        })
    }

    /// Short name of the form, as the host driver reports it.
    pub fn form(self) -> String {
        match self {
            Side::Pump => "pump".to_string(),
            Side::UnsupportedQuoteMint => "unsupported_quote_mint".to_string(),
            Side::QuoteControl => "quote_control".to_string(),
            Side::Slot(name) => format!("slot:{name}"),
            Side::Remaining(n) => format!("remaining:{n}"),
            Side::OwnerOfRemaining(n) => format!("owner-remaining:{n}"),
            Side::StoredMint(name) => format!("stored-mint:{name}"),
            Side::StoredTokenOwner(name) => format!("stored-token-owner:{name}"),
            Side::QuoteAta => "quote_ata".to_string(),
            Side::AncestorCurve => "ancestor_curve".to_string(),
            Side::HolderPassedAta => "holder_passed_ata".to_string(),
            Side::HolderDerivedAta => "holder_derived_ata".to_string(),
            Side::HopQuoteMint => "hop_quote_mint".to_string(),
            Side::RouteFinalMint => "route_final_mint".to_string(),
        }
    }
}

/// Handler, line form, place, code, left side, right side.
pub const PAIRS: &[(&str, Kind, &str, u64, Side, Side)] = &[
    ("buy_exact_quote_in_v3", Kind::Thrown, "buy_v2.rs:121", 6010, Side::StoredTokenOwner("associated_quote_user"), Side::Slot("user")),
    ("buy_v3", Kind::Thrown, "buy_v2.rs:121", 6010, Side::StoredTokenOwner("associated_quote_user"), Side::Slot("user")),
    ("create_v2", Kind::Thrown, "create_v2.rs:220", 6063, Side::Remaining(0), Side::UnsupportedQuoteMint),
    ("create_v2", Kind::Thrown, "create_v2.rs:243", 6063, Side::OwnerOfRemaining(0), Side::Remaining(2)),
    ("create_v2", Kind::Thrown, "create_v2.rs:258", 6065, Side::Remaining(1), Side::QuoteAta),
    ("create_v2", Kind::Thrown, "create_v2.rs:348", 6075, Side::Remaining(3), Side::QuoteControl),
    ("create_v2", Kind::Thrown, "create_v2.rs:353", 6075, Side::OwnerOfRemaining(3), Side::Pump),
    ("create_v2", Kind::Thrown, "create_v2.rs:437", 6099, Side::Remaining(4), Side::AncestorCurve),
    ("create_v2", Kind::Thrown, "create_v2.rs:442", 6099, Side::OwnerOfRemaining(4), Side::Pump),
    ("distribute_fee_to_holders", Kind::Thrown, "creator/distribute_fee_to_holders.rs:122", 6085, Side::HolderPassedAta, Side::HolderDerivedAta),
    ("multi_hop_curve_swap", Kind::Thrown, "multi_hop_curve_swap.rs:262", 6098, Side::RouteFinalMint, Side::StoredMint("destination")),
    ("multi_hop_curve_swap", Kind::Thrown, "trade_v3.rs:180", 6004, Side::StoredMint("buyback_fee_recipient"), Side::HopQuoteMint),
    ("sell_v3", Kind::Thrown, "buy_v2.rs:121", 6010, Side::StoredTokenOwner("associated_quote_user"), Side::Slot("user")),
];

/// The two side forms a site logs, when the site is in the table.
pub fn forms(handler: &str, kind: Kind, place: &str, code: u64) -> Option<(Side, Side)> {
    PAIRS.iter()
        .find(|(h, k, p, c, _, _)| *h == handler && *k == kind && *p == place && *c == code)
        .map(|(_, _, _, _, left, right)| (*left, *right))
}

/// The logged block for a site and its two values, tab-joined as
/// `Left:` / left / `Right:` / right, when the site is in the table and every
/// constant side equals the value given.
pub fn block(handler: &str, kind: Kind, place: &str, code: u64, left: &str, right: &str) -> Option<String> {
    let (want_left, want_right) = forms(handler, kind, place, code)?;
    for (side, value) in [(want_left, left), (want_right, right)] {
        if let Some(constant) = side.constant() {
            if constant != value {
                return None;
            }
        }
    }
    Some(format!("Left:\t{left}\tRight:\t{right}"))
}
