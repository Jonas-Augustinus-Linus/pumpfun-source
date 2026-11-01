#!/usr/bin/env python3
"""Independent re-verification for amm-claim-token-incentives-token22-transfer-fee-20261029.

Checks, without trusting producer.py:
- MANIFEST.json file hashes match the packet files on disk;
- report.json.gz case_count / counts / empty mismatches / repo input
  hashes match the repository files;
- receipt parts arrive in order with matching sha256, receipt
  counts, and per-receipt transaction sha256;
- every receipt transaction verifies with exactly 1 signature field;
- the 3 images agree on every case's observed values;
- success cases match expected vault drain (gross claim), net dest
  gain, withheld amount, claimed total, unclaimed/volume/last/needs
  state, destination length, gross event amount, event claimed
  total, event volume, and payer fee (5,000, or 2,162,600 for the
  missing-ATA creation case);
- the zero-claim case matches no transfer, no event, the "No tokens
  to claim" log, and advanced last/needs state;
- error cases match the error code and log fragment, roll back
  everything except the payer fee, emit 0 events, and cost 5,000.

Note: the program-level error cases (0xd, 2023) and the panic case
carry no "thrown in" / "caused by account" site marker requirement
here, so verify checks code + fragment + rollback for them, as the
packet README states; the 2005 case does carry a site line
(caused by account: user_ata) and it is checked.
"""
import base64
import gzip
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import os
os.chdir(Path(__file__).resolve().parents[2])
from solders.transaction import Transaction
from pump_amm_liquidity_differential import PAYER

ROOT = Path(__file__).resolve().parents[2]
PACKET = ROOT / "research/amm-claim-token-incentives-token22-transfer-fee-20261029"
M = 2 ** 64 - 1

# (label, expected) — must match producer.py CASES.
# ok: ("ok", claim, gain, withheld, claimed, unclaimed, volume, last,
#      needs, dest_len, event_amount, payer_delta)
# zero: ("zero", claimed, unclaimed, volume, last, needs, dest_len)
# error: ("error", code, fragment)
EXPECTED = [
    ("token-baseline", ("ok", 5, 5, None, 5, 0, 20, 10, 1, 165, 5, 5000)),
    ("token22-nofee", ("ok", 5, 5, 0, 5, 0, 20, 10, 1, 182, 5, 5000)),
    ("token22-nofee-plain-dest", ("ok", 5, 5, None, 5, 0, 20, 10, 1, 165, 5, 5000)),
    ("tf100", ("ok", 5, 4, 1, 5, 0, 20, 10, 1, 182, 5, 5000)),
    ("tf5000", ("ok", 5, 2, 3, 5, 0, 20, 10, 1, 182, 5, 5000)),
    ("tf10000", ("ok", 5, 0, 5, 5, 0, 20, 10, 1, 182, 5, 5000)),
    ("tf5000-max100", ("ok", 100000, 99900, 100, 100000, 0, 20, 10, 1, 182, 100000, 5000)),
    ("tf100-amount1000", ("ok", 1000, 990, 10, 1000, 0, 20, 10, 1, 182, 1000, 5000)),
    ("tf100-amount1", ("ok", 1, 0, 1, 1, 0, 20, 10, 1, 182, 1, 5000)),
    ("tf100-amount0", ("zero", 7, 0, 0, 21, 0, 182)),
    ("tf100-prewithheld", ("ok", 5, 4, 1001, 5, 0, 20, 10, 1, 182, 5, 5000)),
    ("tf100-dest-noext", ("error", "InstructionErrorCustom(13)", "custom program error: 0xd")),
    ("tf100-dest-underfunded-rent", ("error", "2005", "ConstraintRentExempt")),
    ("tf-epoch0", ("ok", 5, 4, 1, 5, 0, 20, 10, 1, 182, 5, 5000)),
    ("tf-epoch9", ("ok", 5, 4, 1, 5, 0, 20, 10, 1, 182, 5, 5000)),
    ("tf-epoch10", ("ok", 5, 2, 3, 5, 0, 20, 10, 1, 182, 5, 5000)),
    ("tf-epoch11", ("ok", 5, 2, 3, 5, 0, 20, 10, 1, 182, 5, 5000)),
    ("tf100-reward-day", ("ok", 205, 202, 3, 212, 0, 0, 21, 0, 182, 205, 5000)),
    ("tf100-claimed-max", ("error", "ProgramFailedToComplete",
     "called `Option::unwrap()` on a `None` value")),
    ("tf100-missing-user-ata", ("ok", 5, 4, 1, 5, 0, 20, 10, 1, 182, 5, 2162600)),
    ("prog-mismatch", ("error", "2023", "ConstraintAssociatedTokenTokenProgram")),
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fail(msg):
    raise SystemExit(f"verify FAIL: {msg}")


def main():
    manifest = json.loads((PACKET / "MANIFEST.json").read_text())
    for rel, digest in manifest["files"].items():
        if rel == "MANIFEST.json":
            continue
        data = (PACKET / rel).read_bytes()
        if sha(data) != digest:
            fail(f"MANIFEST hash mismatch for {rel}")
    for rel, digest in manifest["repository_inputs"].items():
        if sha((ROOT / rel).read_bytes()) != digest:
            fail(f"repo input hash mismatch for {rel}")
    report = json.loads(gzip.decompress((PACKET / "runtime/report.json.gz").read_bytes()))
    if report["case_count"] != len(EXPECTED):
        fail(f"case_count {report['case_count']} != {len(EXPECTED)}")
    if report["mismatches"]:
        fail(f"mismatches non-empty: {report['mismatches']}")
    if report["counts"]["transactions"] != len(EXPECTED) * 3:
        fail(f"transaction count {report['counts']['transactions']}")
    if report["counts"]["signature_fields"] != len(EXPECTED) * 3:
        fail("signature_fields count")
    for rel, digest in report["input_sha256"].items():
        if sha((ROOT / rel).read_bytes()) != digest:
            fail(f"report input hash mismatch for {rel}")

    receipts = []
    for part in report["transaction_receipts"]["parts"]:
        data = (PACKET / part["path"]).read_bytes()
        if sha(data) != part["sha256"]:
            fail(f"part hash mismatch for {part['path']}")
        rows = [json.loads(l) for l in gzip.decompress(data).decode().splitlines() if l]
        if len(rows) != part["receipts"]:
            fail(f"part receipt count mismatch for {part['path']}")
        receipts.extend(rows)
    if len(receipts) != len(EXPECTED) * 3:
        fail(f"total receipts {len(receipts)}")

    for r in receipts:
        raw = base64.b64decode(r["transaction_base64"])
        if sha(raw) != r["transaction_sha256"]:
            fail(f"transaction sha mismatch seq {r['sequence']}")
        tx = Transaction.from_bytes(raw)
        checks = tx.verify_with_results()
        if not checks or not all(checks) or len(checks) != 1:
            fail(f"signature check seq {r['sequence']}: {checks}")
        if r["signature_fields"] != 1 or not r["all_signatures_verified"]:
            fail(f"signature fields seq {r['sequence']}")

    for i, (label, expected) in enumerate(EXPECTED):
        case_receipts = receipts[i * 3:(i + 1) * 3]
        images = [r["context"]["image"] for r in case_receipts]
        if images != ["original", "control", "candidate"]:
            fail(f"{label}: image order {images}")
        observed = [r["observed"] for r in case_receipts]
        if not (observed[0] == observed[1] == observed[2]):
            fail(f"{label}: images disagree: {observed}")
        obs = observed[0]
        rep_case = report["cases"][i]
        if rep_case["case"]["label"] != label:
            fail(f"case {i} label {rep_case['case']['label']} != {label}")
        if expected[0] == "ok":
            _, claim, gain, withheld, claimed, unclaimed, volume, last, needs, \
                dest_len, event_amount, payer_delta = expected
            if obs["vault_before"] - obs["vault_after"] != claim:
                fail(f"{label}: vault drain {obs}")
            if (obs["dest_after"] or 0) - (obs["dest_before"] or 0) != gain:
                fail(f"{label}: dest gain {obs}")
            if obs["dest_withheld_after"] != withheld:
                fail(f"{label}: withheld {obs}")
            if obs["claimed_after"] != claimed:
                fail(f"{label}: claimed {obs}")
            if obs["unclaimed_after"] != unclaimed:
                fail(f"{label}: unclaimed {obs}")
            if obs["volume_after"] != volume:
                fail(f"{label}: volume {obs}")
            if obs["last_after"] != last:
                fail(f"{label}: last {obs}")
            if obs["needs_after"] != needs:
                fail(f"{label}: needs {obs}")
            if obs["dest_len_after"] != dest_len:
                fail(f"{label}: dest len {obs}")
            if obs["event_count"] != 1 or obs["event_amount"] != event_amount:
                fail(f"{label}: event {obs}")
            if obs["event_claimed"] != claimed:
                fail(f"{label}: event claimed {obs}")
            if obs["event_volume"] != volume:
                fail(f"{label}: event volume {obs}")
            if obs["payer_delta"] != payer_delta:
                fail(f"{label}: payer {obs}")
            if label == "tf100-missing-user-ata":
                if obs["dest_before"] is not None:
                    fail(f"{label}: dest should start missing")
                if obs["dest_lamports_after"] != 2157600:
                    fail(f"{label}: created dest lamports {obs}")
        elif expected[0] == "zero":
            _, claimed, unclaimed, volume, last, needs, dest_len = expected
            if obs["vault_before"] != obs["vault_after"]:
                fail(f"{label}: vault moved {obs}")
            if obs["dest_after"] != obs["dest_before"]:
                fail(f"{label}: dest moved {obs}")
            if obs["claimed_after"] != claimed or obs["unclaimed_after"] != unclaimed:
                fail(f"{label}: accumulator {obs}")
            if obs["volume_after"] != volume or obs["last_after"] != last:
                fail(f"{label}: accumulator {obs}")
            if obs["needs_after"] != needs or obs["dest_len_after"] != dest_len:
                fail(f"{label}: state {obs}")
            if obs["event_count"] != 0 or obs["payer_delta"] != 5000:
                fail(f"{label}: event/payer {obs}")
            for r in case_receipts:
                if not any("No tokens to claim" in l for l in r["metadata"]["logs"]):
                    fail(f"{label}: no-claim log missing")
        else:
            _, code, fragment = expected
            for r in case_receipts:
                if r["error"] is None or code not in r["error"]:
                    fail(f"{label}: error code {r['error']}")
                logs = "\n".join(r["metadata"]["logs"])
                if fragment not in logs:
                    fail(f"{label}: fragment {fragment} missing")
                if r["observed"]["event_count"] != 0:
                    fail(f"{label}: events on error")
                if r["payer_fee_lamports"] != 5000:
                    fail(f"{label}: payer fee {r['payer_fee_lamports']}")
                before, after = r["before"], r["after"]
                payer = str(PAYER.pubkey())
                for k in before:
                    if k != payer and before[k] != after[k]:
                        fail(f"{label}: rollback violated at {k}")
            if label == "tf100-dest-underfunded-rent":
                for r in case_receipts:
                    logs = "\n".join(r["metadata"]["logs"])
                    if "caused by account: user_ata" not in logs:
                        fail(f"{label}: site missing")
    print(f"verify PASS: {len(EXPECTED)} cases x 3 images = {len(receipts)} receipts, all checks passed")


if __name__ == "__main__":
    main()
