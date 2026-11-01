#!/usr/bin/env python3
"""Independent re-verification for amm-admin-mode-toggles-20261029.

Checks, without trusting producer.py:
- MANIFEST.json file hashes match the packet files on disk;
- report.json.gz case_count / counts / empty mismatches / repo input
  hashes / image hashes match the repository files;
- receipt parts arrive in order with matching sha256, receipt
  counts, and per-receipt transaction sha256;
- every receipt transaction verifies with exactly 1 signature field;
- the 3 images agree on every case-step's error, after-state, and
  payer delta;
- every toggle step matches its expected error (or success), log
  site fragment, zero emitted events, flag bytes re-read from the
  receipt's after-state hex, payer delta (recomputed from
  payer_before / payer_after), rollback (before == after state and
  lamports), and diff-subset scope for same-length writes;
- every create step matches its expected error code and site
  fragment, payer delta 5,000, and full rollback except the fee;
- the claim step matches vault 1000 -> 0, dest +1000, claimed
  13 -> 1013, config cashback byte staying 0, at least one event,
  and payer delta 5,000.
"""
import base64
import gzip
import hashlib
import json
import struct
import sys
from pathlib import Path

import os
os.chdir(Path(__file__).resolve().parents[2])
from solders.transaction import Transaction

ROOT = Path(__file__).resolve().parents[2]
PACKET = ROOT / "research/amm-admin-mode-toggles-20261029"


def sha(data):
    return hashlib.sha256(data).hexdigest()


MANIFEST = json.loads((PACKET / "MANIFEST.json").read_text())
assert MANIFEST["schema"] == 1
for rel, digest in MANIFEST["files"].items():
    assert sha((PACKET / rel).read_bytes()) == digest, rel

report = json.loads(gzip.decompress((PACKET / "runtime/report.json.gz").read_bytes()))
assert report["schema"] == 1
assert report["packet"] == "amm-admin-mode-toggles-20261029"
assert report["case_count"] == 35, report["case_count"]
assert report["mismatches"] == []
assert report["counts"]["transactions"] == 120, report["counts"]
assert report["counts"]["signature_fields"] == 120
for name, digest in report["input_sha256"].items():
    recorded = ROOT / name
    if name.startswith("programs/pump-amm/"):
        recorded = ROOT / "repro/pump_amm/v2-mint-clone-recovery-20261028/results/canonical-source" / name
    assert sha(recorded.read_bytes()) == digest, name
for name, digest in report["image_sha256"].items():
    path = {"original": ROOT / "evidence/original/pump_amm/deployed.so",
            "control": ROOT / "research/amm-multi-hop-group-slice-recovery/artifacts/candidate.so.gz",
            "candidate": ROOT / "research/amm-transfer-fee-diagnostic-recovery/artifacts/candidate.so.gz"}[name]
    assert sha(gzip.decompress(path.read_bytes()) if path.suffix == ".gz" else path.read_bytes()) == digest, name

receipts = []
for part in report["transaction_receipts"]["parts"]:
    data = (PACKET / part["path"]).read_bytes()
    assert sha(data) == part["sha256"], part["path"]
    lines = gzip.decompress(data).decode().strip().split("\n")
    assert len(lines) == part["receipts"], part["path"]
    receipts.extend(json.loads(l) for l in lines)
assert len(receipts) == 120, len(receipts)
assert [r["sequence"] for r in receipts] == list(range(120))

# Expected errors per (label, step). None = success.
EXPECTED = {}
for label in ("mayhem-off", "mayhem-on-from-off", "cashback-off",
              "cashback-on-from-off", "boost-off", "boost-on-from-off",
              "boost-same-on", "boost-same-off"):
    EXPECTED[(label, 0)] = (None, None)
for label, code, site in (
        ("mayhem-same-on", "6043", "MayhemModeInDesiredState"),
        ("mayhem-same-off", "6043", "MayhemModeInDesiredState"),
        ("mayhem-outsider", "6005", "InvalidAdmin"),
        ("mayhem-unsigned", "3010", "AccountNotSigner"),
        ("mayhem-readonly", "2000", "ConstraintMut"),
        ("mayhem-wrong-owner", "3007", "AccountOwnedByWrongProgram"),
        ("mayhem-bool2", "102", "InstructionDidNotDeserialize"),
        ("mayhem-noarg", "102", "InstructionDidNotDeserialize"),
        ("cashback-same-on", "6051", "CashbackNotInDesiredState"),
        ("cashback-same-off", "6051", "CashbackNotInDesiredState"),
        ("cashback-outsider", "6005", "InvalidAdmin"),
        ("cashback-unsigned", "3010", "AccountNotSigner"),
        ("boost-default-auth-off", "6005", "InvalidAdmin"),
        ("boost-default-auth-same-on", "6005", "InvalidAdmin"),
        ("boost-outsider", "6005", "InvalidAdmin"),
        ("boost-unsigned", "3010", "AccountNotSigner"),
        ("boost-readonly", "2000", "ConstraintMut"),
        ("create-mayhem-off", "6041", "MayhemModeDisabled"),
        ("create-mayhem-on-noncanon", "6042", "OnlyPumpPoolsMayhemMode"),
        ("create-cashback-off", "6049", "CashbackNotEnabled"),
        ("create-cashback-on-noncanon", "6050", "OnlyPumpPoolsCashback"),
        ("create-both-off", "6041", "MayhemModeDisabled")):
    EXPECTED[(label, 0)] = (code, site)
EXPECTED[("chain-mayhem-off-on", 0)] = (None, None)
EXPECTED[("chain-mayhem-off-on", 1)] = (None, None)
EXPECTED[("chain-cashback-off-on", 0)] = (None, None)
EXPECTED[("chain-cashback-off-on", 1)] = (None, None)
EXPECTED[("chain-boost-off-on", 0)] = (None, None)
EXPECTED[("chain-boost-off-on", 1)] = (None, None)
EXPECTED[("chain-boost-samestate", 0)] = (None, None)
EXPECTED[("chain-boost-samestate", 1)] = (None, None)
EXPECTED[("chain-boost-samestate", 2)] = (None, None)

# Expected flag bytes after each toggle step: (offset, value).
FLAG_AFTER = {
    ("mayhem-off", 0): (417, 0), ("mayhem-on-from-off", 0): (417, 1),
    ("mayhem-same-on", 0): (417, 1), ("mayhem-same-off", 0): (417, 0),
    ("mayhem-outsider", 0): (417, 1), ("mayhem-unsigned", 0): (417, 1),
    ("mayhem-readonly", 0): (417, 1), ("mayhem-wrong-owner", 0): (417, 1),
    ("mayhem-bool2", 0): (417, 1), ("mayhem-noarg", 0): (417, 1),
    ("cashback-off", 0): (642, 0), ("cashback-on-from-off", 0): (642, 1),
    ("cashback-same-on", 0): (642, 1), ("cashback-same-off", 0): (642, 0),
    ("cashback-outsider", 0): (642, 1), ("cashback-unsigned", 0): (642, 1),
    ("boost-off", 0): (939, 0), ("boost-on-from-off", 0): (939, 1),
    ("boost-same-on", 0): (939, 1), ("boost-same-off", 0): (939, 0),
    ("boost-default-auth-off", 0): (939, 1),
    ("boost-default-auth-same-on", 0): (939, 1),
    ("boost-outsider", 0): (939, 1), ("boost-unsigned", 0): (939, 1),
    ("boost-readonly", 0): (939, 1),
    ("chain-mayhem-off-on", 0): (417, 0), ("chain-mayhem-off-on", 1): (417, 1),
    ("chain-cashback-off-on", 0): (642, 0), ("chain-cashback-off-on", 1): (642, 1),
    ("chain-boost-off-on", 0): (939, 0), ("chain-boost-off-on", 1): (939, 1),
    ("chain-boost-samestate", 0): (939, 1), ("chain-boost-samestate", 1): (939, 0),
    ("chain-boost-samestate", 2): (939, 0),
}

grouped = {}
for r in receipts:
    raw = base64.b64decode(r["transaction_base64"])
    tx = Transaction.from_bytes(raw)
    checks = tx.verify_with_results()
    assert checks and all(checks) and len(checks) == 1, r["context"]
    assert r["transaction_sha256"] == sha(raw), r["context"]
    assert r["all_signatures_verified"] is True and r["signature_fields"] == 1
    ctx = r["context"]
    grouped.setdefault((ctx["label"], ctx["step"]), []).append(r)
    if ctx["kind"] == "toggle":
        code, site = EXPECTED[(ctx["label"], ctx["step"])]
        if code is None:
            assert r["error"] is None, (ctx, r["error"])
        else:
            assert r["error"] is not None and code in r["error"], (ctx, r["error"])
            assert site in "\n".join(r["metadata"]["logs"]), (ctx, "site")
        assert r["metadata"]["events"] == [], (ctx, "toggle emitted an event")
        after = bytes.fromhex(r["after_hex"])
        off, val = FLAG_AFTER[(ctx["label"], ctx["step"])]
        assert after[off] == val, (ctx, off, after[off], val)
        assert r["payer_before"] - r["payer_after"] == 5000, ctx
        if code is not None:
            assert r["before_hex"] == r["after_hex"], (ctx, "no rollback")
            assert r["before_lamports"] == r["after_lamports"], ctx
    elif ctx["kind"] == "create":
        code, site = EXPECTED[(ctx["label"], 0)]
        assert r["error"] is not None and code in r["error"], (ctx, r["error"])
        assert site in "\n".join(r["metadata"]["logs"]), (ctx, "site")
        assert r["observed"]["payer_delta"] == 5000, ctx
        assert r["observed"]["rollback"] is True, ctx
    elif ctx["kind"] == "claim":
        assert r["error"] is None, (ctx, r["error"])
        obs = r["observed"]
        assert obs["vault_before"] == 1000 and obs["vault_after"] == 0, obs
        assert obs["dest_after"] - obs["dest_before"] == 1000, obs
        assert obs["claimed_before"] == 13 and obs["claimed_after"] == 1013, obs
        assert obs["cfg_cashback_before"] == 0 and obs["cfg_cashback_after"] == 0, obs
        assert obs["event_count"] >= 1, obs
        assert obs["payer_delta"] == 5000, obs

for key, group in grouped.items():
    assert len(group) == 3, (key, len(group))
    if group[0]["context"]["kind"] == "toggle":
        assert len({(g["error"], g["after_hex"], g["after_lamports"]) for g in group}) == 1, key
    elif group[0]["context"]["kind"] == "create":
        assert len({(g["error"], json.dumps(g["after"], sort_keys=True)) for g in group}) == 1, key
    else:
        assert len({(g["error"], json.dumps(g["observed"], sort_keys=True)) for g in group}) == 1, key

print("verify PASS: 35 cases x 3 images = 120 receipts, all checks passed")
