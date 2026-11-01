#!/usr/bin/env python3
"""Fail-closed verification for the Union10 PumpSwap cashback witness."""

import base64
import gzip
import hashlib
import json
from pathlib import Path

from solders.transaction import Transaction


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RECEIPT = HERE / "runtime/cashback-union10.json.gz"
ORIGINAL = ROOT / "evidence/original/pump_amm/deployed.so"
CANDIDATE = ROOT / "research/claude-amm-union10-20261028/builds/a/candidate.so.gz"
PRODUCER = HERE / "produce_cashback_receipt.py"
HARNESS = ROOT / "scripts/pump_amm_reusable_harness.py"
FIXTURE = ROOT / "research/imported-lab/analysis/pump_fun/amm-v2-trade-fixture.json"
DEPENDENCIES = {
    "spl_token": ROOT / "evidence/dependencies/spl_token/deployed.so",
    "spl_token_2022": ROOT / "evidence/dependencies/spl_token_2022/deployed.so",
}
PROGRAM_ID = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA"
ORIGINAL_SHA256 = "6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7"
CANDIDATE_SHA256 = "c5f40baa226d181e16e95eaa8838e0fa7967acb05e17ae78d5d3858fb77484f7"
PRODUCER_SHA256 = "5ef79cb94c3ba761f019199834ad016c5e07b8b8fcc6c1d2f6b00b90029ea850"
CASE_IDENTITIES_SHA256 = "7602d9eb321d52f3e9a0a8be52eeba6fe611aa46a7a14488c8440c9540535778"
TOP_LEVEL_FIELDS = {
    "scope", "original_sha256", "candidate_sha256", "script_sha256",
    "harness_sha256", "fixture_sha256", "dependencies", "case_count",
    "mismatches", "cases",
}
OUTCOME_FIELDS = {
    "case", "program_sha256", "error", "before", "after", "logs",
    "inner", "return_data", "tx", "signature_verified", "events",
}
COMPARISON_FIELDS = OUTCOME_FIELDS - {"program_sha256"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), f"regular file required: {path}")
    return sha256_bytes(path.read_bytes())


def gzip_payload_sha256(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), f"regular gzip file required: {path}")
    with gzip.open(path, "rb") as handle:
        return sha256_bytes(handle.read())


def read_receipt(path=RECEIPT):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "receipt file")
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        return json.load(handle)


def verify_manifest(base=HERE):
    base = Path(base)
    manifest_path = base / "MANIFEST.json"
    require(manifest_path.is_file() and not manifest_path.is_symlink(), "manifest file")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(set(manifest) == {"files"}, "manifest fields")
    expected = manifest["files"]
    require(isinstance(expected, dict), "manifest file table")

    actual = set()
    for path in base.rglob("*"):
        require(not path.is_symlink(), f"symlink rejected: {path.relative_to(base)}")
        if path.is_file() and path != manifest_path:
            actual.add(path.relative_to(base).as_posix())
    require(actual == set(expected), "unexpected or missing packet files")
    for relative, digest in expected.items():
        require(sha256_file(base / relative) == digest, f"manifest hash: {relative}")


def verify_data(data):
    require(set(data) == TOP_LEVEL_FIELDS, "receipt fields")
    require(data["original_sha256"] == sha256_file(ORIGINAL) == ORIGINAL_SHA256,
            "original executable hash")
    require(data["candidate_sha256"] == gzip_payload_sha256(CANDIDATE) == CANDIDATE_SHA256,
            "candidate executable hash")
    require(data["script_sha256"] == sha256_file(PRODUCER) == PRODUCER_SHA256,
            "producer hash")
    require(data["harness_sha256"] == sha256_file(HARNESS), "harness hash")
    require(data["fixture_sha256"] == sha256_file(FIXTURE), "fixture hash")
    require(set(data["dependencies"]) == set(DEPENDENCIES), "dependency inventory")
    for name, path in DEPENDENCIES.items():
        require(data["dependencies"][name] == sha256_file(path), f"dependency hash: {name}")
    require(data["mismatches"] == [], "saved mismatch summary")

    rows = data["cases"]
    require(isinstance(rows, list) and len(rows) == data["case_count"] == 146,
            "cashback case inventory")
    identities = []
    transactions = set()
    signature_count = 0
    for index, row in enumerate(rows):
        require(set(row) == {"case", "original", "candidate", "diff"},
                f"case {index} fields")
        identity = json.dumps(row["case"], sort_keys=True, separators=(",", ":"))
        identities.append(identity)
        require(row["diff"] == [], f"case {index} saved difference")
        original = row["original"]
        candidate = row["candidate"]
        require(set(original) == OUTCOME_FIELDS and set(candidate) == OUTCOME_FIELDS,
                f"case {index} outcome fields")
        require(original["case"] == candidate["case"] == row["case"],
                f"case {index} identity")
        require(original["program_sha256"] == ORIGINAL_SHA256,
                f"case {index} original program")
        require(candidate["program_sha256"] == CANDIDATE_SHA256,
                f"case {index} candidate program")
        require(original["tx"] == candidate["tx"],
                f"case {index} paired transaction")
        for role, outcome in (("original", original), ("candidate", candidate)):
            require(outcome["signature_verified"] is True,
                    f"case {index} {role} signature flag")
            try:
                raw = base64.b64decode(outcome["tx"], validate=True)
                transaction = Transaction.from_bytes(raw)
            except Exception as exc:
                raise ValueError(f"case {index} {role} transaction encoding") from exc
            checks = transaction.verify_with_results()
            require(bool(checks) and all(checks),
                    f"case {index} {role} cryptographic signature")
            require(bytes(transaction) == raw,
                    f"case {index} {role} canonical transaction")
            require(PROGRAM_ID in {str(key) for key in transaction.message.account_keys},
                    f"case {index} {role} PumpSwap program identity")
            signature_count += len(checks)
            transactions.add(sha256_bytes(raw))
            require(isinstance(outcome["before"], dict) and isinstance(outcome["after"], dict),
                    f"case {index} {role} state")
            require(outcome["events"] == [line for line in outcome["logs"]
                                           if line.startswith("Program data: ")],
                    f"case {index} {role} event extraction")
        recomputed = [field for field in sorted(COMPARISON_FIELDS)
                      if original[field] != candidate[field]]
        require(recomputed == row["diff"] == [], f"case {index} outcome mismatch")

    require(len(set(identities)) == len(identities), "duplicate case identity")
    identity_bytes = "\n".join(identities).encode("utf-8")
    require(sha256_bytes(identity_bytes) == CASE_IDENTITIES_SHA256,
            "case identity inventory")
    require(signature_count == 292, "signature count")
    require(len(transactions) == 35, "distinct transaction count")
    return {
        "cases": len(rows),
        "distinct_transactions": len(transactions),
        "executions": 2 * len(rows),
        "mismatches": 0,
        "signatures": signature_count,
    }


def main():
    verify_manifest()
    print(json.dumps(verify_data(read_receipt()), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(f"verification failed: {exc}")
