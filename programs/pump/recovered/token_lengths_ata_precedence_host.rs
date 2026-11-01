//! Host driver for the ATA-create token-length precedence model.
//!
//! Reads `instruction,slot,twin,empty` lines on stdin — `empty` is `1`
//! when the reshaped length is zero — and answers one line per request:
//! `stands`, `ata-illegal-owner`, `token-invalid-data` or `unconfirmed`.
//!
//! Build: rustc --edition=2021 token_lengths_ata_precedence_host.rs

#[path = "token_lengths_ata_precedence.rs"]
mod model;

use std::io::Read as _;

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).expect("stdin");
    let mut out = String::new();
    for line in input.lines() {
        if line.is_empty() {
            out.push_str("unconfirmed\n");
            continue;
        }
        let mut fields = line.split(',');
        let answer = match (fields.next(), fields.next(), fields.next(), fields.next()) {
            (Some(instruction), Some(slot), Some(twin), Some(empty)) => {
                match model::precedence(instruction, slot, twin, empty == "1") {
                    model::Precedence::Stands => "stands",
                    model::Precedence::AtaIllegalOwner => "ata-illegal-owner",
                    model::Precedence::TokenInvalidData => "token-invalid-data",
                    model::Precedence::Unconfirmed => "unconfirmed",
                }
            }
            _ => "unconfirmed",
        };
        out.push_str(answer);
        out.push('\n');
    }
    print!("{out}");
}
