#!/usr/bin/env python3
"""Verify, and optionally replay, a stateful admin_cto report."""
import argparse
import gzip
import json
from pathlib import Path

import lifecycle


def read(path):
    raw = path.read_bytes()
    return json.loads(gzip.decompress(raw) if path.suffix == ".gz" else raw)


def verify(report, candidate):
    problems = []
    if report.get("schema") != "pump-admin-cto-stateful-v1":
        problems.append("schema")
    if report.get("program_sha256") != lifecycle.program_hashes(candidate):
        problems.append("program_sha256")
    sources, digest = lifecycle.source_manifest()
    if report.get("source_files") != sources or report.get("source_manifest_sha256") != digest:
        problems.append("source_manifest")
    if report.get("idl_sha256") != lifecycle.file_sha(lifecycle.IDL_PATH):
        problems.append("idl_sha256")
    planned = lifecycle.scenarios()
    rows = report.get("cases", [])
    if [row.get("case") for row in rows] != [row["name"] for row in planned]:
        problems.append("case_membership_or_order")
    if report.get("case_count") != len(rows):
        problems.append("case_count")
    mismatched, oracle, invalid, infrastructure = [], [], [], []
    transactions = 0
    for row in rows:
        transactions += len(row["original"]["receipts"])
        differences, comparison = lifecycle.compare_runs(row["original"], row["candidate"])
        if differences != row.get("mismatch_fields") or comparison != row.get("comparison"):
            problems.append(row["case"] + ":comparison")
        invariants = {"original": lifecycle.validate_run(row["original"]),
                      "candidate": lifecycle.validate_run(row["candidate"])}
        if invariants != row.get("invariant_failures"):
            problems.append(row["case"] + ":invariants")
        if differences:
            mismatched.append(row["case"])
        observed = [receipt["outcome"] for receipt in row["original"]["receipts"]]
        expected_outcomes = lifecycle.EXPECTED_OUTCOMES[row["case"]]
        expected_oracle = [] if observed == expected_outcomes else [{"expected": expected_outcomes, "observed": observed}]
        if row.get("expected_original_outcomes") != expected_outcomes or row.get("observed_original_outcomes") != observed or row.get("oracle_mismatches") != expected_oracle:
            problems.append(row["case"] + ":oracle")
        if expected_oracle:
            oracle.append(row["case"])
        if any(invariants.values()):
            invalid.append(row["case"])
        if row.get("infrastructure_failures"):
            infrastructure.append(row["case"])
    expected = {"transaction_count_per_image": transactions, "mismatch_cases": mismatched, "oracle_mismatch_cases": oracle,
                "invariant_failure_cases": invalid, "infrastructure_failure_cases": infrastructure}
    for key, value in expected.items():
        if report.get(key) != value:
            problems.append(key)
    controls = lifecycle.negative_control(report) if rows else {}
    if controls != {"error": True, "after": True, "events": True} or report.get("negative_controls") != controls:
        problems.append("negative_controls")
    if mismatched or oracle or invalid or infrastructure:
        problems.append("qualification_failures")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--replay", action="store_true")
    args = parser.parse_args()
    report = read(args.report)
    problems = verify(report, args.candidate.resolve())
    replay_equal = None
    if args.replay and not problems:
        replay = lifecycle.run_suite(args.candidate.resolve())
        replay["negative_controls"] = lifecycle.negative_control(replay)
        replay_equal = replay == report
        if not replay_equal:
            problems.append("deterministic_replay")
    print(json.dumps({"verified": not problems, "problems": problems,
                      "deterministic_replay_equal": replay_equal}, indent=2))
    return bool(problems)


if __name__ == "__main__":
    raise SystemExit(main())
