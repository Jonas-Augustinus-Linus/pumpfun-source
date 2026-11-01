//! Captured precedence of the ATA-create reads over the errors of the
//! instructions that open them.
//!
//! `token_lengths.rs` names three reads that are neither `Load` nor
//! `Handler`: a shareholder ATA left to the token program (`Recipient`),
//! a holder ATA the idempotent create opens (`HolderAta`), and an account
//! the ATA program's idempotent create opens (`IdempotentAta`).
//! `token_lengths_precedence.rs` answers the precedence question for the
//! `Handler` reads and scopes these out. This model answers it for the
//! two ATA-create reads; the `Recipient` read stays unconfirmed (below).
//!
//! `precedence` takes the instruction, the slot, the twin outcome (the
//! outcome at the standard length, as the test harness names it: `ok`,
//! `panic`, `fees`, `rent`, or `<program>:<error>`) and whether the
//! reshaped length is empty, and says what reshaping the slot to a length
//! the Pump decoder refuses does to the call. Unlike the `Handler` reads,
//! the replacement is never Pump's `InvalidAccountData`: the reshaped
//! account is first seen by the ATA program or the token program, so a
//! preempted twin becomes the ATA program's `IllegalOwner` or the token
//! program's `InvalidAccountData`. The answer does not depend on which
//! refused length is stored, except at length zero for the holder ATA:
//! an empty account takes the create path (and the ATA program refuses
//! it), while a nonempty one is left to the transfer, whose decode fails
//! instead. The tables name every (instruction, slot, twin) the replay
//! produced; any other twin is unconfirmed.
//!
//! What the two reads show:
//!
//! - `migrate_v2`'s pool authority quote account is created after the
//!   checks that raise 6004 and 6006 (those twins stand) and before the
//!   points that raise 6027 and the token failure (the ATA program's
//!   `IllegalOwner` replaces both, and a passing twin).
//! - `distribute_fee_to_holders`' first holder ATA is opened late: the
//!   system, 6086 and privilege-escalation twins are all raised first and
//!   stand. A passing twin is the only one the read stops, and a
//!   `Token-2022 IncorrectProgramId` twin is stopped only by the empty
//!   reshape, through the create path.
//!
//! Still unconfirmed: the `Recipient` read of `distribute_creator_fees_v2`
//! (remaining slots 3-5). Its answer is case-split on passing twins — a
//! recipient slot is read only when the distribution reaches that
//! shareholder, so the same (slot, twin) pair stands in one replayed case
//! and is replaced in another — and its zero length is a not-created
//! signal rather than a refused length, so the question needs a per-case
//! form this replay does not express.
//!
//! Checked against `evidence/original/pump/deployed.so` and the captured
//! token programs by `tests/test_token_lengths_ata_precedence_captured.py`.
//! Not linked into the SBF crate. This is not a byte-identity claim.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Precedence {
    /// The twin outcome is unchanged: the error is raised first.
    Stands,
    /// The ATA program's idempotent create refuses the reshaped account:
    /// the outcome becomes its `IllegalOwner`.
    AtaIllegalOwner,
    /// The token program's decode of the reshaped account fails at the
    /// transfer: the outcome becomes its `InvalidAccountData`.
    TokenInvalidData,
    /// Both outcomes were seen, or the twin was never replayed.
    Unconfirmed,
}

const STANDS: &[(&str, &str, &str, bool)] = &[
    ("distribute_fee_to_holders", "rem1", "111111:1", false),
    ("distribute_fee_to_holders", "rem1", "111111:1", true),
    ("distribute_fee_to_holders", "rem1", "pump:6086", false),
    ("distribute_fee_to_holders", "rem1", "pump:6086", true),
    ("distribute_fee_to_holders", "rem1", "pump:PrivilegeEscalation", false),
    ("distribute_fee_to_holders", "rem1", "pump:PrivilegeEscalation", true),
    ("distribute_fee_to_holders", "rem1", "t22:IncorrectProgramId", false),
    ("migrate_v2", "pool_authority_quote_account", "pump:6004", false),
    ("migrate_v2", "pool_authority_quote_account", "pump:6004", true),
    ("migrate_v2", "pool_authority_quote_account", "pump:6006", false),
    ("migrate_v2", "pool_authority_quote_account", "pump:6006", true),
];

const ATA_ILLEGAL_OWNER: &[(&str, &str, &str, bool)] = &[
    ("distribute_fee_to_holders", "rem1", "ok", true),
    ("distribute_fee_to_holders", "rem1", "t22:IncorrectProgramId", true),
    ("migrate_v2", "pool_authority_quote_account", "ok", false),
    ("migrate_v2", "pool_authority_quote_account", "ok", true),
    ("migrate_v2", "pool_authority_quote_account", "pump:6027", false),
    ("migrate_v2", "pool_authority_quote_account", "pump:6027", true),
    ("migrate_v2", "pool_authority_quote_account", "token:1", false),
    ("migrate_v2", "pool_authority_quote_account", "token:1", true),
];

const TOKEN_INVALID_DATA: &[(&str, &str, &str, bool)] = &[
    ("distribute_fee_to_holders", "rem1", "ok", false),
];

/// What reshaping `slot` of `instruction` to a refused length does to a
/// call whose outcome at the standard length is `twin`; `empty` says the
/// reshaped length is zero.
pub fn precedence(instruction: &str, slot: &str, twin: &str, empty: bool) -> Precedence {
    let key = (instruction, slot, twin, empty);
    if STANDS.contains(&key) {
        Precedence::Stands
    } else if ATA_ILLEGAL_OWNER.contains(&key) {
        Precedence::AtaIllegalOwner
    } else if TOKEN_INVALID_DATA.contains(&key) {
        Precedence::TokenInvalidData
    } else {
        Precedence::Unconfirmed
    }
}
