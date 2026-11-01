#!/usr/bin/env python3
"""Cross-transaction sequence differential for the Donation Relay.

The sibling `donation-relay-stateful` package submits exactly one
instruction per signed transaction. This package keeps its fixture, its
pinned inputs and its comparison witness, and submits the sequence shapes
that package does not declare:

- several donations inside ONE transaction (two, and three);
- a successful donation and a failing donation inside ONE transaction,
  where the whole transaction must roll back;
- a failing transaction followed by successful retries in later
  transactions, and a success / failure / success sandwich;
- a rejected epoch-close attempt interleaved between two donations,
  after which donations must keep working;
- a zero donation after a nonzero donation in the same epoch.

Every step is the same signed multi-instruction transaction executed in
independent LiteSVMs, compared with the stateful package's own
`Pair.compare_rows`. On top of the row comparison, each case pins the
original side's per-step errors and its decoded final state (debouncer
total, source and destination balances, epoch fields), and requires every
failed step to leave all non-fee accounts byte-identical.

The production relayer key boundary is unchanged from the stateful
package: no private key is retained and no signer bit is injected, so
relayer-only success families remain unsupported fixtures here too.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from solders.compute_budget import set_compute_unit_limit
from solders.instruction import Instruction
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.transaction import Transaction

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "scripts"))
from pump_differential_output import PumpReport
STATEFUL = HERE.parent / "donation-relay-stateful" / "producer.py"
SPEC = importlib.util.spec_from_file_location("relay_stateful", STATEFUL)
base = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = base
SPEC.loader.exec_module(base)

Fixture = base.Fixture
decoded_state = base.decoded_state
negative_control = base.negative_control
source_manifest = base.source_manifest
transaction_identity = base.transaction_identity
file_sha = base.file_sha

StepBuild = Callable[[Fixture], tuple[list[Instruction], list[Keypair] | None, set[Pubkey]]]


def step_donate(*donations: tuple[int, dict[str, Any]]) -> StepBuild:
    """One transaction carrying every listed donation instruction."""

    def build(fixture: Fixture) -> tuple[list[Instruction], list[Keypair] | None, set[Pubkey]]:
        return [fixture.donation(amount, **kwargs) for amount, kwargs in donations], None, set()

    return build


def step_close_wrong_signer() -> StepBuild:
    def build(fixture: Fixture) -> tuple[list[Instruction], list[Keypair] | None, set[Pubkey]]:
        instruction, new_accounts = fixture.close_wrong_signer()
        return [instruction], [fixture.outsider], set(new_accounts)

    return build


class SequencePair(base.Pair):
    """The stateful pair, submitting several instructions per transaction."""

    def transact_multi(self, instructions: list[Instruction], signers: list[Keypair],
                       watch: set[Pubkey]) -> dict[str, Any]:
        left, right = self.vms.values()
        left.expire_blockhash()
        right.expire_blockhash()
        if left.latest_blockhash() != right.latest_blockhash():
            raise RuntimeError("LiteSVM blockhashes diverged")
        tx = Transaction.new_signed_with_payer(
            [set_compute_unit_limit(1_400_000), *instructions],
            self.fixture.fee.pubkey(),
            [self.fixture.fee, *signers],
            left.latest_blockhash(),
        )
        if not tx.signatures or not all(tx.verify_with_results()):
            raise RuntimeError("locally signed transaction did not verify")
        addresses = watch | set(tx.message.account_keys)
        rows = {}
        for side, vm in self.vms.items():
            try:
                rows[side] = self._run(vm, tx, addresses)
            except AssertionError as exc:  # rollback guard tripped on this side
                rows[side] = {"error": f"ASSERT:{exc}", "logs": [], "events": [],
                              "inner_instructions": None, "return_data": None,
                              "before": {}, "after": {}}
        if rows["original"].get("after") and rows["candidate"].get("after"):
            mismatches = self.compare_rows(rows["original"], rows["candidate"])
        elif rows["original"]["error"] != rows["candidate"]["error"]:
            mismatches = ["assert_asymmetry"]
        else:
            mismatches = []
        return {
            "signature": str(tx.signatures[0]),
            "signature_verified": bool(tx.signatures) and all(tx.verify_with_results()),
            "mismatches": mismatches,
            "original": rows["original"],
            "candidate": rows["candidate"],
        }


def check_expectations(steps: list[dict[str, Any]], spec: dict[str, Any], fee_payer: str) -> list[str]:
    """Pin the original side's step errors, failed-step rollback and final state.

    This is a pure function of the recorded steps so the unit tests can
    replay corrupted expectations through it as a negative control.
    """
    problems: list[str] = []
    if len(steps) != len(spec["step_errors"]):
        return ["step_count"]
    for index, (step, expected_error) in enumerate(zip(steps, spec["step_errors"])):
        error = step["original"].get("error")
        if expected_error is None:
            if error is not None:
                problems.append(f"step_{index}_expected_success")
        elif expected_error.replace(" ", "") not in (error or "").replace(" ", ""):
            problems.append(f"step_{index}_expected_error")
        if error is not None:
            before, after = step["original"]["before"], step["original"]["after"]
            if any(before[k] != after[k] for k in before if k != fee_payer):
                problems.append(f"step_{index}_failed_state_changed")
    state = steps[-1]["original_state"]
    for field, expected_value in spec["final_state"].items():
        if state is None or state[field] != expected_value:
            problems.append("original_expected_" + field)
    return problems


CASES: dict[str, dict[str, Any]] = {
    "intra_tx_double_donate": {
        "steps": [step_donate((1_000_000, {}), (2_000_000, {"message": b"second in same tx"}))],
        "step_errors": [None],
        "final_state": {"epoch": 0, "epoch_state": 1, "debouncer_state": 1,
                        "debouncer_total": 3_000_000, "source_tokens": 7_000_000,
                        "destination_tokens": 3_000_000},
    },
    "intra_tx_triple_donate": {
        "steps": [step_donate((100, {}), (200, {}), (300, {}))],
        "step_errors": [None],
        "final_state": {"epoch": 0, "epoch_state": 1, "debouncer_state": 1,
                        "debouncer_total": 600, "source_tokens": 9_999_400,
                        "destination_tokens": 600},
    },
    "intra_tx_success_then_fail": {
        "steps": [step_donate((500_000, {}), (1, {"message": b"m" * 256}))],
        "step_errors": ["Custom(6009)"],
        "final_state": {"epoch": None, "epoch_state": None, "debouncer_state": None,
                        "debouncer_total": None, "source_tokens": 10_000_000,
                        "destination_tokens": None},
    },
    "fail_then_success_retry": {
        "steps": [step_donate((1, {"message": b"m" * 256})),
                  step_donate((1_000_000, {})),
                  step_donate((2_000_000, {"message": b"second donation"}))],
        "step_errors": ["Custom(6009)", None, None],
        "final_state": {"epoch": 0, "epoch_state": 1, "debouncer_state": 1,
                        "debouncer_total": 3_000_000, "source_tokens": 7_000_000,
                        "destination_tokens": 3_000_000},
    },
    "success_fail_success": {
        # The closing donation carries its own message so this case's third
        # transaction is not byte-identical to the interleaved-close case's
        # third transaction: both would otherwise be the same signed
        # transaction and the report's unique-signature rule would fail.
        "steps": [step_donate((777, {})),
                  step_donate((1, {"message": b"m" * 256})),
                  step_donate((223, {"message": b"after failure"}))],
        "step_errors": [None, "Custom(6009)", None],
        "final_state": {"epoch": 0, "epoch_state": 1, "debouncer_state": 1,
                        "debouncer_total": 1_000, "source_tokens": 9_999_000,
                        "destination_tokens": 1_000},
    },
    "failed_close_between_donations": {
        "steps": [step_donate((777, {"message": b"close setup"})),
                  step_close_wrong_signer(),
                  step_donate((223, {}))],
        "step_errors": [None, "Custom(2012)", None],
        "final_state": {"epoch": 0, "epoch_state": 1, "debouncer_state": 1,
                        "debouncer_total": 1_000, "source_tokens": 9_999_000,
                        "destination_tokens": 1_000},
    },
    "zero_after_nonzero": {
        "steps": [step_donate((1_000_000, {})), step_donate((0, {}))],
        "step_errors": [None, None],
        "final_state": {"epoch": 0, "epoch_state": 1, "debouncer_state": 1,
                        "debouncer_total": 1_000_000, "source_tokens": 9_000_000,
                        "destination_tokens": 1_000_000},
    },
}
CASE_NAMES = list(CASES)


def run_case(name: str, original: Path, candidate: Path, token: Path, associated: Path) -> dict[str, Any]:
    spec = CASES[name]
    fixture = Fixture.create()
    pair = SequencePair(original, candidate, token, associated, fixture)
    steps: list[dict[str, Any]] = []
    for build in spec["steps"]:
        instructions, signers, extra = build(fixture)
        for address in extra:
            pair.add_account(address, fixture.accounts[address])
        row = pair.transact_multi(instructions, signers or [fixture.donor], fixture.watch())
        row["original_state"] = decoded_state(row["original"]["after"], fixture) if row["original"].get("after") else None
        row["candidate_state"] = decoded_state(row["candidate"]["after"], fixture) if row["candidate"].get("after") else None
        steps.append(row)
    problems: list[str] = []
    for index, step in enumerate(steps):
        problems.extend(f"step_{index}:{field}" for field in step["mismatches"])
    problems.extend(check_expectations(steps, spec, str(fixture.fee.pubkey())))
    return {"name": name, "classification": "equal_observed_behavior" if not problems else "different_behavior",
            "problems": problems, "fee_payer": str(fixture.fee.pubkey()),
            "expected": {"step_errors": spec["step_errors"], "final_state": spec["final_state"]},
            "steps": steps}


def expected_state_control(case: dict[str, Any]) -> bool:
    """A corrupted expected debouncer total must be flagged by the check."""
    spec = json.loads(json.dumps({"step_errors": case["expected"]["step_errors"],
                                  "final_state": case["expected"]["final_state"]}))
    if spec["final_state"].get("debouncer_total") is None:
        return False
    spec["final_state"]["debouncer_total"] += 1
    problems = check_expectations(case["steps"], spec, case["fee_payer"])
    return "original_expected_debouncer_total" in problems


def execute(root: Path, candidate: Path, output: Path) -> bool:
    if output.exists() or output.is_symlink():
        raise SystemExit(f"refusing to overwrite existing report: {output}")
    original = root / "evidence/dependencies/donation_relay/deployed.so"
    token = root / "evidence/dependencies/spl_token/deployed.so"
    associated = root / "evidence/dependencies/associated_token/deployed.so"
    pins = {"original": (original, base.ORIGINAL_SHA), "spl_token": (token, base.TOKEN_SHA),
            "associated_token": (associated, base.ATA_SHA)}
    for label, (path, expected) in pins.items():
        if not path.is_file() or file_sha(path) != expected:
            raise SystemExit(f"{label} input is missing or fails its retained SHA-256 binding: {path}")
    if not candidate.is_file():
        raise SystemExit(f"candidate does not exist: {candidate}")
    sources, source_digest = source_manifest(root)
    publisher = PumpReport(output, root, candidate, __file__, overwrite=False,
                           extra_inputs=[STATEFUL, *[path for path, _ in pins.values()],
                                         *[root / name for name in sources]])
    # Each VM loads one private copy of exactly the bytes this receipt names.
    snapshots = {label: path.read_bytes() for label, (path, _) in pins.items()}
    snapshots['candidate'] = candidate.read_bytes()
    for label, (_, expected) in pins.items():
        if base.sha(snapshots[label]) != expected:
            raise SystemExit(f'{label} changed before snapshot admission')
    with tempfile.TemporaryDirectory(prefix='relay-xtx-inputs-') as scratch:
        private = {label: Path(scratch) / (label + '.so') for label in snapshots}
        for label, data in snapshots.items():
            private[label].write_bytes(data)
        cases = [run_case(name, private['original'], private['candidate'],
                          private['spl_token'], private['associated_token'])
                 for name in CASE_NAMES]
    identities = transaction_identity(cases)
    control = negative_control(cases[0]["steps"][-1])
    control_detected = all(control.values())
    total_control = expected_state_control(cases[0])
    unsupported = [
        {"family": "upsert_mint_whitelist_v1 success", "classification": "unsupported_fixture", "reason": "production relayer private key is not retained"},
        {"family": "close_donation_epoch_v1 success and next epoch", "classification": "unsupported_fixture", "reason": "production relayer private key is not retained"},
        {"family": "distribute_non_swap_output_mint_v1 success", "classification": "unsupported_fixture", "reason": "requires the same unavailable production relayer signature"},
        {"family": "Jupiter swap instructions", "classification": "unsupported_fixture", "reason": "non-swap lifecycle cannot legitimately cross its relayer gate"},
    ]
    report = {
        "schema": "donation-relay-xtx-sequences-v1",
        "program": str(base.RELAY),
        "authority_boundary": {"production_relayer": str(base.RELAYER), "private_key_retained": False, "privileged_signer_injection": False},
        "inputs": {label: {"path": str(path.relative_to(root)), "sha256": base.sha(snapshots[label])} for label, (path, _) in pins.items()},
        "candidate": {"sha256": base.sha(snapshots["candidate"]), "bytes": len(snapshots["candidate"]),
                      "source_manifest_sha256": source_digest, "source_files": sources},
        "comparison": "same signed multi-instruction transaction in independent LiteSVMs; error, relevant logs, events, inner instructions, return data, and full watched before/after accounts; original-side step errors, failed-step rollback and decoded final state pinned per case",
        "case_count": len(cases),
        "transaction_count": sum(len(row["steps"]) for row in cases),
        "transaction_identity": identities,
        "matching_cases": sum(row["classification"] == "equal_observed_behavior" for row in cases),
        "different_cases": [row["name"] for row in cases if row["classification"] == "different_behavior"],
        "negative_control": {"kind": "mutated step replayed through the case comparison", "fields": control, "detected": control_detected},
        "expected_state_control": {"kind": "corrupted expected debouncer total replayed through the expectation check", "detected": total_control},
        "unsupported": unsupported,
        "cases": cases,
    }
    publisher.write((json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    summary = {key: report[key] for key in ("case_count", "transaction_count", "matching_cases", "different_cases")}
    summary["negative_control_detected"] = control_detected
    summary["expected_state_control_detected"] = total_control
    print(json.dumps(summary, indent=2, sort_keys=True))
    return (report["matching_cases"] == report["case_count"] and control_detected and total_control
            and identities["count"] == identities["unique_count"]
            and identities["all_signatures_verified"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(0 if execute(args.root.resolve(), args.candidate.resolve(), args.output.resolve()) else 1)


if __name__ == "__main__":
    main()
