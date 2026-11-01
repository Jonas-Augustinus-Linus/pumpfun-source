#!/usr/bin/env python3
"""Fail-closed verifier for the PumpSwap incentive-updater edge-parity packet."""

import argparse
import base64
import gzip
import hashlib
import importlib.util
import itertools
import json
import os
import re
import sys
import tempfile
from pathlib import Path

P = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("REPOSITORY_ROOT_OVERRIDE", P.parents[1])).resolve()
UNION12 = Path(
    os.environ.get(
        "AMM_UNION12_PACKET_OVERRIDE",
        ROOT / "research/claude-amm-union12-20261028",
    )
).resolve()
ORIGINAL = Path(
    os.environ.get("AMM_ORIGINAL_OVERRIDE", ROOT / "evidence/original/pump_amm/deployed.so")
).resolve()
ORIGINAL_SHA = "6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7"
CANDIDATE_SHA = "97222480163636f6fc1470b71c516e89770eba0038e4e430eda30143b383abae"
SYMBOLS_SHA = "36a94b38f3c6fbc10a1f55c6526be07cd21356f1cc9da24ebaaa4bd28c79694e"
TARGET = "0x6db20"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fail(message):
    raise SystemExit("FAIL: " + message)


def check(condition, message):
    if not condition:
        fail(message)


def load_json(path):
    try:
        return json.loads(path.read_text())
    except Exception as error:
        fail(f"invalid JSON {path}: {error}")


def load_gzip_json(path):
    try:
        return json.loads(gzip.decompress(path.read_bytes()))
    except Exception as error:
        fail(f"invalid gzip JSON {path}: {error}")


def gunzip_bytes(path):
    try:
        return gzip.decompress(path.read_bytes())
    except Exception as error:
        fail(f"invalid gzip artifact {path}: {error}")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_membership():
    actual = set()
    for path in P.rglob("*"):
        check(not path.is_symlink(), "symlink in packet: " + str(path.relative_to(P)))
        check(path.is_file() or path.is_dir(), "special packet entry: " + str(path))
        if path.is_file():
            actual.add(path.relative_to(P).as_posix())
    manifest = load_json(P / "MANIFEST.json")
    check(set(manifest) == {"schema", "files"} and manifest["schema"] == 1, "manifest schema")
    check(actual == set(manifest["files"]) | {"MANIFEST.json"}, "packet membership")
    for name, expected in manifest["files"].items():
        check(re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "manifest digest format")
        check(digest((P / name).read_bytes()) == expected, "manifest digest: " + name)
    return len(manifest["files"])


def verify_attribution():
    data = load_json(P / "attribution.json")
    check(data["upstream_main"] == "7cd896fc309e566d4617b679bde48375bdacc717", "upstream base")
    check(data["union12"]["head_commit"] == "66ded863a2d905acab721f1883af031e736f1c95", "Union12 commit")
    check((data["union12"]["normalized_windows"], data["union12"]["raw_windows"]) == (783, 236), "Union12 census attribution")
    check(data["union12"]["candidate_sha256"] == CANDIDATE_SHA, "candidate attribution")
    check(data["union12"]["symbols_sha256"] == SYMBOLS_SHA, "symbols attribution")
    check(data["original"]["sha256"] == ORIGINAL_SHA, "original attribution")
    check(data["original"]["window"] == "0x6db20..0x6f3c8" and data["original"]["bytes"] == 6312, "target attribution")
    check(data["scope"] == {"focused_controls": 5, "edge_cases": 1730, "maintained_suites": 25, "maintained_cases": 17462, "transactions": 35074, "signatures": 35418}, "scope attribution")


def verify_artifacts_and_window():
    result = load_json(UNION12 / "builds/a/result.json")
    candidate = gunzip_bytes(UNION12 / "builds/a/candidate.so.gz")
    symbols = gunzip_bytes(UNION12 / "builds/a/symbols.so.gz")
    check(digest(candidate) == result["candidate_sha256"] == CANDIDATE_SHA, "Union12 stripped ELF")
    check(digest(symbols) == result["symbols_sha256"] == SYMBOLS_SHA, "Union12 unstripped ELF")
    check(digest(ORIGINAL.read_bytes()) == ORIGINAL_SHA, "original ELF")
    measure = load_module("edge_measure", UNION12 / "tools/measure.py")
    with tempfile.TemporaryDirectory() as directory:
        candidate_path = Path(directory) / "symbols.so"
        candidate_path.write_bytes(symbols)
        rows = measure.measure(ORIGINAL, candidate_path)
    matched = [row for row in rows if row["match"]]
    raw = [row for row in rows if row["raw"]]
    target = next(row for row in rows if row["original"] == TARGET)
    unmatched = [(row["original"], row["bytes"]) for row in rows if not row["match"]]
    check((len(rows), len(matched), len(raw)) == (785, 783, 236), "window census")
    check(target["bytes"] == 6312 and target["match"] and not target["raw"], "complete normalized updater window")
    check(unmatched == [("0x351a8", 8104), ("0x4c750", 9024)], "remaining frontier")
    return {"windows": 785, "normalized": 783, "raw": 236, "target": target}


def verify_transaction(raw, expected_digest, signature_count, signatures):
    check(digest(raw) == expected_digest, "transaction bytes")
    if not signatures:
        return
    try:
        from solders.transaction import Transaction
    except Exception as error:
        fail("solders required for --signatures: " + str(error))
    results = Transaction.from_bytes(raw).verify_with_results()
    check(bool(results) and all(results) and len(results) == signature_count, "transaction signature")


def verify_focused(candidate_sha, signatures):
    base = P / "runtime/focused"
    document = load_gzip_json(base / "receipts.json.gz")
    check(document["candidate_sha256"] == candidate_sha and document["original_sha256"] == ORIGINAL_SHA, "focused ELF binding")
    check(document["producer_sha256"] == digest((base / "producer.py").read_bytes()), "focused producer")
    check(document["fixture_sha256"] == digest((base / "fixture.py").read_bytes()), "focused fixture")
    check(len(document["cases"]) == 5, "focused case count")
    for case in document["cases"]:
        left, right = case["original"], case["candidate"]
        check(left["executed_program_sha256"] == ORIGINAL_SHA and right["executed_program_sha256"] == candidate_sha, "focused loaded ELF")
        check(left["signature_verification"] and right["signature_verification"], "focused signature verification")
        keys = (set(left) | set(right)) - {"executed_program_sha256"}
        check(all(left.get(key) == right.get(key) for key in keys), "focused exact parity: " + case["name"])
        raw_left = base64.b64decode(left["transaction_base64"], validate=True)
        raw_right = base64.b64decode(right["transaction_base64"], validate=True)
        check(raw_left == raw_right, "focused paired transaction")
        verify_transaction(raw_left, digest(raw_left), 1, signatures)
    return {"cases": 5, "transactions": 10, "mismatches": 0, "raw_log_differences": 0}


def expected_edge_cases():
    rows = []
    for start, end, period, now, day in itertools.product(
        [-2**63, -1, 0, 1, 20, 2**63 - 1],
        [-2**63, -1, 0, 1, 49, 2**63 - 1],
        [-1, 0, 1, 2**63 - 1],
        [-1, 0, 1, 2**63 - 1],
        [0, 30],
    ):
        rows.append({"instruction": "admin_update_token_incentives", "start": start, "end": end, "period": period, "new_start": 0, "new_end": 0, "new_period": period, "now": now, "day": day, "supply": 1})
    for start, end, period, now, supply in itertools.product(
        [-2**63, -1, 0, 1, 20, 2**63 - 1],
        [0, 1, 49, 2**63 - 1],
        [-1, 0, 1, 2**63 - 1],
        [-1, 0, 1],
        [0, 1],
    ):
        rows.append({"instruction": "admin_update_token_incentives", "start": 20, "end": 49, "period": 1, "new_start": start, "new_end": end, "new_period": period, "now": now, "day": 30, "supply": supply})
    rows.extend([{"instruction": "admin_update_token_incentives", "unsigned": "admin"}, {"instruction": "admin_update_token_incentives", "readonly": "admin"}])
    return rows


def verify_edge_cases(candidate_sha, signatures):
    base = P / "runtime/incentive1730"
    report = load_gzip_json(base / "report.json.gz")
    observed = load_gzip_json(base / "transactions.json.gz")
    check(report["candidate_sha256"] == candidate_sha and report["original_sha256"] == ORIGINAL_SHA, "edge ELF binding")
    check(report["producer_sha256"] == digest((base / "cases.py").read_bytes()), "edge producer")
    check(report["fixture_sha256"] == digest((base / "admin_fixture.py").read_bytes()), "edge fixture")
    check(report["case_count"] == len(report["cases"]) == 1730 and report["mismatch_count"] == 0, "edge result")
    check([row["input"] for row in report["cases"]] == expected_edge_cases(), "edge deterministic inputs and day indices")
    check(observed["script_sha256"] == digest((base / "cases.py").read_bytes()), "edge observed script")
    check(observed["observer_sha256"] == digest((base / "observer.py").read_bytes()), "edge observer")
    check(observed["transaction_count"] == len(observed["transactions"]) == 3460 and observed["signature_count"] == 3462, "edge transaction totals")
    for index, case in enumerate(report["cases"]):
        check(not case["different_fields"], "edge reported mismatch")
        left, right = case["original"], case["candidate"]
        check(left["executed_program_sha256"] == ORIGINAL_SHA and right["executed_program_sha256"] == candidate_sha, "edge loaded ELF")
        keys = (set(left) | set(right)) - {"executed_program_sha256"}
        check(all(left.get(key) == right.get(key) for key in keys), "edge exact state/CPI/result/log parity")
        for side_index, side in enumerate((left, right)):
            row = observed["transactions"][index * 2 + side_index]
            raw = base64.b64decode(row["transaction_base64"], validate=True)
            verify_transaction(raw, row["transaction_sha256"], row["signature_count"], signatures)
            check(row["all_signatures_verified"] and row["error"] == side["error"], "edge observed error")
            check(row["logs_sha256"] == digest(json.dumps(side["logs"], separators=(",", ":")).encode()), "edge observed logs")
            check(row["amm_program_sha256"] == (ORIGINAL_SHA if side_index == 0 else candidate_sha), "edge observed ELF")
            check(row["transaction_base64"] == side["transaction_base64"], "edge transaction correspondence")
    return {"cases": 1730, "transactions": 3460, "signatures": 3462, "mismatches": 0, "raw_log_differences": 0}


def verify_full(candidate_sha, signatures):
    base = P / "runtime/full17462"
    inputs = load_json(base / "inputs.json")
    summary = load_json(base / "summary.json")
    suites = load_json(base / "suites.json")
    check(inputs["candidate_sha256"] == summary["candidate_sha256"] == candidate_sha, "full candidate binding")
    check(inputs["original_sha256"] == summary["original_sha256"] == ORIGINAL_SHA, "full original binding")
    check(inputs["replay_driver_sha256"] == digest((base / "replay_parallel.py").read_bytes()), "full replay driver")
    observer = ROOT / "repro/pump_amm/owner6048-v144/runtime/observe_suite.py"
    check(inputs["observer_sha256"] == digest(observer.read_bytes()), "full observer")
    for name, expected in inputs["harness_sha256"].items():
        check(digest((ROOT / name).read_bytes()) == expected, "full harness: " + name)
    check((summary["suites"], summary["cases"], summary["transactions"], summary["signatures"], summary["mismatches"], summary["inputs_unchanged"]) == (25, 17462, 35074, 35418, [], True), "full summary")
    check(len(suites) == 25 and len({row["suite"] for row in suites}) == 25, "full suite inventory")
    totals = [0, 0, 0]
    for suite in suites:
        name = suite["suite"]
        report_raw = gzip.decompress((base / f"{name}.json.gz").read_bytes())
        report = json.loads(report_raw)
        sidecar_path = base / f"{name}-transactions.json.gz"
        observed = load_gzip_json(sidecar_path)
        check(suite["returncode"] == 0 and not suite["mismatches"], "full suite result: " + name)
        check(digest(report_raw) == suite["receipt_sha256"] and digest(sidecar_path.read_bytes()) == suite["sidecar_sha256"], "full receipt hashes: " + name)
        check(report["candidate_sha256"] == candidate_sha and report["original_sha256"] == ORIGINAL_SHA, "full report ELF binding: " + name)
        check(report["case_count"] == suite["case_count"] and not report.get("mismatches", []), "full report result: " + name)
        check(observed["transaction_count"] == suite["transactions"] and observed["signature_count"] == suite["signatures"], "full observed totals: " + name)
        loaded = set()
        for row in observed["transactions"]:
            raw = base64.b64decode(row["transaction_base64"], validate=True)
            verify_transaction(raw, row["transaction_sha256"], row["signature_count"], signatures)
            check(row["all_signatures_verified"], "full runtime signature verification: " + name)
            check(row["amm_program_sha256"] in {ORIGINAL_SHA, candidate_sha}, "full loaded ELF: " + name)
            loaded.add(row["amm_program_sha256"])
        check(loaded == {ORIGINAL_SHA, candidate_sha}, "full paired ELF coverage: " + name)
        totals[0] += suite["case_count"]
        totals[1] += suite["transactions"]
        totals[2] += suite["signatures"]
    check(totals == [17462, 35074, 35418], "full totals")
    incentive = {row["suite"]: row["case_count"] for row in suites if row["suite"].startswith("incentives_")}
    check(incentive == {"incentives_admin": 668, "incentives_claim": 807, "incentives_sync": 222}, "incentive family totals")
    return {"suites": 25, "cases": 17462, "transactions": 35074, "signatures": 35418, "mismatches": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signatures", action="store_true", help="cryptographically reverify every recorded transaction")
    args = parser.parse_args()
    files = verify_membership()
    verify_attribution()
    window = verify_artifacts_and_window()
    focused = verify_focused(CANDIDATE_SHA, args.signatures)
    edge = verify_edge_cases(CANDIDATE_SHA, args.signatures)
    full = verify_full(CANDIDATE_SHA, args.signatures)
    print(json.dumps({"status": "PASS", "packet_files": files, "window": window, "focused": focused, "edge": edge, "full": full, "signature_reverification": args.signatures}, indent=2))


if __name__ == "__main__":
    main()
