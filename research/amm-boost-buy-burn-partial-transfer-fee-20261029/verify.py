"""Independent re-verification for amm-boost-buy-burn-partial-transfer-fee-20261029.

Checks, without trusting producer.py:
- MANIFEST.json file hashes match the packet files on disk;
- report.json.gz case_count / counts / empty mismatches / repo input
  hashes match the repository files;
- receipt parts arrive in order with matching sha256, receipt
  counts, and per-receipt transaction sha256;
- every receipt transaction verifies with exactly 1 signature field;
- the 3 images agree on every case's observed values;
- success cases match expected pool quote gain, base burn, boost
  vault spend, vault closure (always False here: partial spends
  never close), payer delta 5,000, pool quote withheld tail,
  event count 2, and the decoded BoostBuyAndBurnEvent (used /
  burned / remaining), re-derived from the receipt snapshots and
  log events, not from the recorded observed values alone;
- error cases match the error code and log fragment, roll back
  everything except the payer fee, cost 5,000, emit 0 events,
  and carry the recorded thrown-in site line;
- the recorded error sites match the receipts' logs.
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
from pump_amm_liquidity_differential import PAYER, vaultbase, vaultquote
from pump_amm_boost_burn_differential import BOOST

ROOT = Path(__file__).resolve().parents[2]
PACKET = ROOT / "research/amm-boost-buy-burn-partial-transfer-fee-20261029"
M = 2 ** 64 - 1
CONTROL = ROOT / "research/amm-multi-hop-group-slice-recovery/artifacts/candidate.so.gz"
CANDIDATE = ROOT / "research/amm-transfer-fee-diagnostic-recovery/artifacts/candidate.so.gz"

# (label, expected) — must match producer.py CASES.
# ok: ("ok", vq_gained, vb_spent, boost_spent, closed, payer_delta,
#      pool_withheld_after, ev_used, ev_burned, ev_remaining)
# error: ("error", code, fragment, event_count,
#         ev_used_or_None, ev_burned_or_None, ev_remaining_or_None)
EXPECTED = [
    ("p-nofee-1e9-anchor", ("ok", 10 ** 9, 5391870655895, 10 ** 9, False,
                            5000, None, 10 ** 9, 5391870655895, 999000000000)),
    ("p-tf100-1e9", ("ok", 990000000, 5338379201831, 10 ** 9, False, 5000,
                     10000000, 10 ** 9, 5338379201831, 999000000000)),
    ("p-tf5000-1e9", ("ok", 500000000, 2706767012738, 10 ** 9, False, 5000,
                      500000000, 10 ** 9, 2706767012738, 999000000000)),
    ("p-tf100-1e11", ("ok", 99000000000, 299156461930852, 10 ** 11, False,
                      5000, 1000000000, 10 ** 11, 299156461930852, 900000000000)),
    ("p-tf100-5e11", ("ok", 495000000000, 538785845334673, 5 * 10 ** 11, False,
                      5000, 5000000000, 5 * 10 ** 11, 538785845334673, 500000000000)),
    ("p-tf100-cap123-1e9", ("ok", 999999877, 5391869998003, 10 ** 9, False,
                            5000, 123, 10 ** 9, 5391869998003, 999000000000)),
    ("p-tf100-nowrite-1e9", ("ok", 990000000, 5338379201831, 10 ** 9, False,
                             5000, 10000000, 10 ** 9, 5338379201831, 999000000000)),
    ("p-tf5000-nowrite-1e9", ("ok", 500000000, 2706767012738, 10 ** 9, False,
                              5000, 500000000, 10 ** 9, 2706767012738, 999000000000)),
    ("p-tf100-3", ("ok", 2, 5435, 3, False, 5000, 1, 3, 5435, 999999999997)),
    ("p-tf100-4", ("ok", 3, 10870, 4, False, 5000, 1, 4, 10870, 999999999996)),
    ("p-tf100-10", ("ok", 9, 43482, 10, False, 5000, 1, 10, 43482, 999999999990)),
    ("p-tf100-100", ("ok", 99, 532666, 100, False, 5000, 1, 100, 532666, 999999999900)),
    ("p-tf100-floor-exact", ("ok", 990000000, 5338379201831, 10 ** 9, False,
                             5000, 10000000, 10 ** 9, 5338379201831, 999000000000)),
    ("p-tf100-floor-plus1", ("error", "6004", "ExceededSlippage", 0, None, None, None)),
    ("p-nofee-floor-exact", ("ok", 10 ** 9, 5391870655895, 10 ** 9, False,
                             5000, None, 10 ** 9, 5391870655895, 999000000000)),
    ("p-nofee-floor-plus1", ("error", "6004", "ExceededSlippage", 0, None, None, None)),
    ("p-nearbal-tf5000", ("ok", 499999999999, 539866951722110, 999999999999,
                          False, 5000, 500000000000, 999999999999, 539866951722110, 1)),
    ("p-nearbal-tf100-cap", ("ok", 999999999876, 599402446277846, 999999999999,
                             False, 5000, 123, 999999999999, 599402446277846, 1)),
    ("p-accrued-mid", ("ok", 10 ** 9, 5391870655895, 10 ** 9, False, 5000,
                       None, 10 ** 9, 5391870655895, 999000000000)),
    ("p-accrued-thr", ("ok", 10 ** 9, 5391870655895, 10 ** 9, False, 5000,
                       None, 10 ** 9, 5391870655895, 999000000000)),
    ("p-accrued-thr-plus1", ("error", "6023", "Overflow", 0, None, None, None)),
    ("p-accrued-sum", ("error", "6023", "Overflow", 0, None, None, None)),
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fail(msg):
    raise SystemExit(f"verify FAIL: {msg}")


def tok_amount(entry):
    if entry is None:
        return None
    data = bytes.fromhex(entry["data_hex"])
    return struct.unpack_from("<Q", data, 64)[0] if len(data) >= 72 else None


def withheld_at(entry):
    if entry is None:
        return None
    data = bytes.fromhex(entry["data_hex"])
    return struct.unpack_from("<Q", data, 170)[0] if len(data) >= 178 else None


def decode_boost_event(events):
    raws = [base64.b64decode(e[len('Program data: '):])
            for e in events if e.startswith('Program data: ')]
    boosts = [r for r in raws if len(r) == 208]
    if not boosts:
        return None
    if len(boosts) != 1:
        fail(f"expected one 208-byte event, got {len(boosts)}")
    r = boosts[0]
    return {"used": struct.unpack_from("<Q", r, 152)[0],
            "burned": struct.unpack_from("<Q", r, 160)[0],
            "remaining": struct.unpack_from("<Q", r, 200)[0]}


def find_boost_ata(before, after):
    """The boost ATA the instruction actually used: the holder==BOOST
    account whose state changed (tf cases carry both the unused
    Token ATA and the effective Token-2022 ATA; no-fee cases carry
    only one)."""
    boost_hex = bytes(BOOST).hex()
    changed = []
    for k, entry in before.items():
        if entry is not None and len(entry["data_hex"]) >= 330 \
                and entry["data_hex"][64:128] == boost_hex \
                and before[k] != after.get(k):
            changed.append(k)
    if len(changed) != 1:
        fail(f"expected exactly one changed boost ATA, got {changed}")
    return changed[0]


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
    report = json.loads(gzip.decompress(
        (PACKET / "runtime/report.json.gz").read_bytes()))
    expected_images = {
        "original": sha((ROOT / "evidence/original/pump_amm/deployed.so").read_bytes()),
        "control": sha(gzip.decompress(CONTROL.read_bytes())),
        "candidate": sha(gzip.decompress(CANDIDATE.read_bytes())),
    }
    if report["image_sha256"] != expected_images:
        fail("report image hashes differ from actual historical images")
    if report["case_count"] != len(EXPECTED):
        fail(f"case_count {report['case_count']} != {len(EXPECTED)}")
    if report["mismatches"]:
        fail(f"mismatches non-empty: {report['mismatches']}")
    if report["counts"]["transactions"] != len(EXPECTED) * 3:
        fail(f"transaction count {report['counts']['transactions']}")
    if report["counts"]["signature_fields"] != len(EXPECTED) * 3:
        fail("signature_fields count")
    if [p["receipts"] for p in report["transaction_receipts"]["parts"]] != \
            [10, 10, 10, 10, 10, 10, 6]:
        fail("part receipt counts")
    for rel, digest in report["input_sha256"].items():
        if sha((ROOT / rel).read_bytes()) != digest:
            fail(f"report input hash mismatch for {rel}")

    receipts = []
    for part in report["transaction_receipts"]["parts"]:
        data = (PACKET / part["path"]).read_bytes()
        if sha(data) != part["sha256"]:
            fail(f"part hash mismatch for {part['path']}")
        if len(data) >= 25 * 1024 * 1024:
            fail(f"part over 25MB: {part['path']}")
        rows = [json.loads(l) for l in gzip.decompress(data).decode().splitlines() if l]
        if len(rows) != part["receipts"]:
            fail(f"part receipt count mismatch for {part['path']}")
        receipts.extend(rows)
    if len(receipts) != len(EXPECTED) * 3:
        fail(f"total receipts {len(receipts)}")

    for r in receipts:
        image = r["context"]["image"]
        if image not in expected_images or r["loaded_programs"]["pAMM"]["sha256"] != expected_images[image]:
            fail(f"AMM image declaration mismatch seq {r['sequence']}")
        raw = base64.b64decode(r["transaction_base64"])
        if sha(raw) != r["transaction_sha256"]:
            fail(f"transaction sha mismatch seq {r['sequence']}")
        tx = Transaction.from_bytes(raw)
        checks = tx.verify_with_results()
        if not checks or not all(checks) or len(checks) != 1:
            fail(f"signature check seq {r['sequence']}: {checks}")
        if r["signature_fields"] != 1 or not r["all_signatures_verified"]:
            fail(f"signature fields seq {r['sequence']}")

    vq_key, vb_key, payer_key = str(vaultquote), str(vaultbase), str(PAYER.pubkey())
    for i, (label, expected) in enumerate(EXPECTED):
        case_receipts = receipts[i * 3:(i + 1) * 3]
        images = [r["context"]["image"] for r in case_receipts]
        if images != ["original", "control", "candidate"]:
            fail(f"{label}: image order {images}")
        observed = [r["observed"] for r in case_receipts]
        if not (observed[0] == observed[1] == observed[2]):
            fail(f"{label}: images disagree: {observed}")
        rep_case = report["cases"][i]
        if rep_case["case"]["label"] != label:
            fail(f"case {i} label {rep_case['case']['label']} != {label}")
        if expected[0] == "ok":
            (_, vq_gained, vb_spent, boost_spent, closed, payer_delta,
             withheld, ev_used, ev_burned, ev_remaining) = expected
            for r in case_receipts:
                if r["error"] is not None:
                    fail(f"{label}: unexpected error {r['error']}")
                before, after = r["before"], r["after"]
                if tok_amount(after[vq_key]) - tok_amount(before[vq_key]) != vq_gained:
                    fail(f"{label}: vq gain {r['observed']}")
                if tok_amount(before[vb_key]) - tok_amount(after[vb_key]) != vb_spent:
                    fail(f"{label}: vb spent {r['observed']}")
                ata = find_boost_ata(before, after)
                b_before = tok_amount(before[ata])
                b_after = tok_amount(after[ata])
                if b_before - (b_after or 0) != boost_spent:
                    fail(f"{label}: boost spent {r['observed']}")
                if (after[ata] is None) != closed:
                    fail(f"{label}: closed {r['observed']}")
                if before[payer_key]["lamports"] - after[payer_key]["lamports"] \
                        != payer_delta:
                    fail(f"{label}: payer {r['observed']}")
                if withheld_at(after[vq_key]) != withheld:
                    fail(f"{label}: withheld {r['observed']}")
                events = r["metadata"]["events"]
                if len(events) != 2:
                    fail(f"{label}: event count {len(events)}")
                ev = decode_boost_event(events)
                if ev is None or (ev["used"], ev["burned"], ev["remaining"]) != \
                        (ev_used, ev_burned, ev_remaining):
                    fail(f"{label}: boost event {ev}")
                if r["observed"] != rep_case[r["context"]["image"]]["observed"]:
                    fail(f"{label}: report observed mismatch")
        else:
            (_, code, fragment, event_count, ev_used, ev_burned, ev_remaining) = expected
            for r in case_receipts:
                if r["error"] is None or code not in r["error"]:
                    fail(f"{label}: error code {r['error']}")
                logs = "\n".join(r["metadata"]["logs"])
                if fragment not in logs:
                    fail(f"{label}: fragment {fragment} missing")
                if len(r["metadata"]["events"]) != event_count:
                    fail(f"{label}: event count {len(r['metadata']['events'])}")
                if r["payer_fee_lamports"] != 5000:
                    fail(f"{label}: payer fee {r['payer_fee_lamports']}")
                before, after = r["before"], r["after"]
                for k in before:
                    if k != payer_key and before[k] != after[k]:
                        fail(f"{label}: rollback violated at {k}")
                site = next((l for l in r["metadata"]["logs"]
                             if "thrown in" in l or "caused by account" in l), None)
                if rep_case["error_sites"][r["context"]["image"]] != site:
                    fail(f"{label}: site mismatch {site}")
                ev = decode_boost_event(r["metadata"]["events"])
                if ev_used is None:
                    if ev is not None:
                        fail(f"{label}: unexpected boost event {ev}")
                elif ev is None or (ev["used"], ev["burned"], ev["remaining"]) != \
                        (ev_used, ev_burned, ev_remaining):
                    fail(f"{label}: boost event {ev}")
    print(f"verify PASS: {len(EXPECTED)} cases x 3 images = {len(receipts)} receipts, all checks passed")


if __name__ == "__main__":
    main()
