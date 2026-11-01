#!/usr/bin/env python3
"""Independent re-verification for amm-cashback-claim-chains-20261029.

Checks, from the packet files alone (plus the three program images retained in the
repository: evidence/original/pump_amm/deployed.so and the two
candidate.so.gz artifacts named in IMAGE_PATHS):
- MANIFEST.json lists every packet file with a matching sha256.
- runtime/report.json.gz: 15 cases, 120 receipts, 12 parts (12x10),
  part sha256/byte counts match the part files.
- Every receipt transaction parses (solders) and all signatures verify.
- Every receipt's recorded before/after snapshots reproduce the
  report's expected values: fee-payer lamport deltas (per step, so
  harness setup differences cannot matter), the user accumulator
  state (parsed fields plus lamports), the accumulator ATA token
  balance / withheld / lamports, the user quote token delta (and
  its withheld field on transfer-fee claims), the anchor token-leg
  deltas, and the decoded event fields (buy cb/uqin, buy_exact cb,
  claim amount/totals).
- Failure steps roll back every watched account except the fee payer
  (fee 5,000) and carry the expected error code plus the recorded
  per-image site line in their logs. Site lines are checked per
  image, never compared across images, because original and rebuilt
  sources differ in line numbers.
- The observed surface of every case (step, error, event count, and
  snapshots with fee-payer lamports zeroed) is identical across the
  original, control, and candidate images.
- The three program images hash to the values recorded in the report.

Usage (from the repository root):
    python3 -I -B research/amm-cashback-claim-chains-20261029/verify.py
"""
import base64
import gzip
import hashlib
import json
import struct
import sys
from pathlib import Path

from solders.pubkey import Pubkey
from solders.transaction import Transaction

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[1]
# The three program images are retained in the repository; the two
# rebuilt images are stored gzip-compressed and hashed decompressed.
IMAGE_PATHS = {
    "original": REPO / "evidence/original/pump_amm/deployed.so",
    "control": REPO / "research/amm-multi-hop-group-slice-recovery/artifacts/candidate.so.gz",
    "candidate": REPO / "research/amm-transfer-fee-diagnostic-recovery/artifacts/candidate.so.gz",
}
PROGRAM = Pubkey.from_string("pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA")
TOKEN = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
TOKEN22 = Pubkey.from_string("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
ATA = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
PAYER_KEY = Pubkey.from_string("DXyM8yAHqpMzDtvwz5DXoEUQmPxjJPMKCASCPhLMKpEx")
BASE = Pubkey.from_string("7LSsEoJGhLeZzGvDofTdNg7M3JttxQqGWNLo6vWMpump")
QUOTE = Pubkey.from_string("So11111111111111111111111111111111111111112")
PROTOCOL = Pubkey.from_string("62qc2CNXwrYqQScmEdiZFFAnJR262PxWEuNQtxfafNgV")
BBOWNER = Pubkey.from_string("5YxQFdt3Tr9zJLvkFccqXVUwhdTWJQc1fFg2YPbxvxeD")
VOLUME, _ = Pubkey.find_program_address([b"user_volume_accumulator", bytes(PAYER_KEY)], PROGRAM)
UVATA = Pubkey.find_program_address([bytes(VOLUME), bytes(TOKEN), bytes(QUOTE)], ATA)[0]
UVATA22 = Pubkey.find_program_address([bytes(VOLUME), bytes(TOKEN22), bytes(QUOTE)], ATA)[0]
PROTOCOL_ATA = Pubkey.find_program_address([bytes(PROTOCOL), bytes(TOKEN), bytes(QUOTE)], ATA)[0]
PROTO22 = Pubkey.find_program_address([bytes(PROTOCOL), bytes(TOKEN22), bytes(QUOTE)], ATA)[0]
BUYBACK = Pubkey.find_program_address([bytes(BBOWNER), bytes(TOKEN), bytes(QUOTE)], ATA)[0]
BB22 = Pubkey.find_program_address([bytes(BBOWNER), bytes(TOKEN22), bytes(QUOTE)], ATA)[0]
USERBASE = None  # recovered from receipts: the base token account whose owner is PAYER
USERQUOTE = None
VAULTBASE = None
VAULTQUOTE = None


def fail(msg):
    raise SystemExit(f"FAIL: {msg}")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tok_amount(entry):
    if entry is None:
        return None
    raw = bytes.fromhex(entry["data_hex"])
    if len(raw) < 72:
        return None
    return struct.unpack_from("<Q", raw, 64)[0]


def tok_delta(rec, key):
    b = rec["before"][str(key)]
    a = rec["after"][str(key)]
    return (tok_amount(a) or 0) - (tok_amount(b) or 0)


def lam_delta(rec, key):
    b = rec["before"][str(key)]
    a = rec["after"][str(key)]
    return (a["lamports"] if a else 0) - (b["lamports"] if b else 0)


def withheld(entry):
    if entry is None:
        return None
    raw = bytes.fromhex(entry["data_hex"])
    if len(raw) == 182:
        return struct.unpack_from("<Q", raw, 174)[0]
    if len(raw) == 178:
        return struct.unpack_from("<Q", raw, 170)[0]
    return None


def parse_uva(entry):
    if entry is None:
        return None
    raw = bytes.fromhex(entry["data_hex"])
    if len(raw) < 90:
        return None
    v = struct.unpack_from("<BQQQqBQQ", raw, 40)
    return {"lamports": entry["lamports"], "needs": v[0], "unc": v[1],
            "claimed": v[2], "vol": v[3], "last": v[4], "has": v[5],
            "cb": v[6], "cbcl": v[7]}


def u64(raw, off):
    return struct.unpack_from("<Q", raw, off)[0]


def i64(raw, off):
    return struct.unpack_from("<q", raw, off)[0]


def ev_data(logs):
    lines = [l for l in logs if l.startswith("Program data: ")]
    if len(lines) != 1:
        return None
    return base64.b64decode(lines[0].split("Program data: ", 1)[1].strip())


def decode_event(kind, rec):
    raw = ev_data(rec["logs"])
    if raw is None:
        return None
    if kind in ("buy", "buy_small", "buy_one", "buy0"):
        return {"len": len(raw), "cb": u64(raw, 416), "uqin": u64(raw, 112)}
    if kind == "buyex":
        return {"len": len(raw), "cb": u64(raw, 431)}
    if kind == "claim":
        return {"disc": raw[:8].hex(), "user": raw[8:40].hex(), "len": len(raw),
                "amount": u64(raw, 40), "ts": i64(raw, 48),
                "total_claimed": u64(raw, 56), "total_earned": u64(raw, 64)}
    return None


def main():
    manifest = json.loads((ROOT / "MANIFEST.json").read_text())
    for entry in manifest["files"]:
        path = ROOT / entry["path"]
        if not path.exists():
            fail(f"missing file {entry['path']}")
        if sha(path.read_bytes()) != entry["sha256"]:
            fail(f"sha mismatch {entry['path']}")
    with gzip.open(ROOT / "runtime" / "report.json.gz", "rt", encoding="utf-8") as fh:
        report = json.load(fh)
    if report["case_count"] != 15 or report["receipt_count"] != 120:
        fail(f"counts {report['case_count']} cases / {report['receipt_count']} receipts")
    if report["counts"] != {"cases": 15, "receipts": 120, "parts": 12}:
        fail(f"counts block {report['counts']}")
    if report["mismatches"] != []:
        fail(f"mismatches recorded: {report['mismatches']}")
    for name, path in IMAGE_PATHS.items():
        data = path.read_bytes()
        if path.suffix == ".gz":
            data = gzip.decompress(data)
        if sha(data) != report["images"][name]:
            fail(f"image hash mismatch {name}")
    receipts = []
    for part in report["parts"]:
        path = ROOT / part["file"]
        data = path.read_bytes()
        if sha(data) != part["sha256"] or len(data) != part["bytes"]:
            fail(f"part hash/size mismatch {part['file']}")
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            chunk = [json.loads(line) for line in fh if line.strip()]
        if len(chunk) != part["count"]:
            fail(f"part count mismatch {part['file']}")
        receipts.extend(chunk)
    if len(receipts) != 120:
        fail(f"receipt total {len(receipts)}")
    # Recover the fixture token-account keys from a buy receipt's
    # snapshots: userbase/vaultbase hold the base mint, userquote /
    # vaultquote hold the quote mint. Identify them by mint field.
    global USERBASE, USERQUOTE, VAULTBASE, VAULTQUOTE
    for rec in receipts:
        if rec["step"] == "buy":
            for k, entry in rec["before"].items():
                if entry is None:
                    continue
                raw = bytes.fromhex(entry["data_hex"])
                if len(raw) < 72:
                    continue
                mint = raw[:32]
                owner = raw[32:64]
                if mint == bytes(BASE) and owner == bytes(PAYER_KEY):
                    USERBASE = Pubkey.from_string(k)
                elif mint == bytes(QUOTE) and owner == bytes(PAYER_KEY):
                    USERQUOTE = Pubkey.from_string(k)
            break
    if USERBASE is None or USERQUOTE is None:
        fail("could not recover user token accounts")
    # vault accounts: same mint, owner = pool vault authority is not
    # PAYER; recover by elimination from the same receipt's snapshot
    # keys that are token accounts of the right mint and not the user
    # accounts, protocol, buyback, or uvata keys.
    known = {str(PAYER_KEY), str(VOLUME), str(UVATA), str(UVATA22),
             str(USERBASE), str(USERQUOTE), str(PROTOCOL_ATA), str(PROTO22),
             str(BUYBACK), str(BB22)}
    for rec in receipts:
        if rec["step"] == "buy":
            for k, entry in rec["before"].items():
                if entry is None or k in known:
                    continue
                raw = bytes.fromhex(entry["data_hex"])
                if len(raw) < 72:
                    continue
                if raw[:32] == bytes(BASE):
                    VAULTBASE = Pubkey.from_string(k)
                elif raw[:32] == bytes(QUOTE):
                    VAULTQUOTE = Pubkey.from_string(k)
            break
    if VAULTBASE is None or VAULTQUOTE is None:
        fail("could not recover vault token accounts")
    by_case = {}
    for rec in receipts:
        by_case.setdefault(rec["case"], {}).setdefault(rec["image"], []).append(rec)
    for case in report["cases"]:
        label = case["label"]
        tf = case.get("tf", False)
        uvata_key = UVATA22 if tf else UVATA
        proto_key = PROTO22 if tf else PROTOCOL_ATA
        buyback_key = BB22 if tf else BUYBACK
        expect = case["steps"]
        for image in ("original", "control", "candidate"):
            recs = by_case.get(label, {}).get(image)
            if recs is None or len(recs) != len(expect):
                fail(f"{label}/{image}: {0 if recs is None else len(recs)} receipts, expected {len(expect)}")
            for rec, exp in zip(recs, expect):
                tag = f"{label}/{image}/{rec['step']}"
                tx = Transaction.from_bytes(base64.b64decode(rec["transaction_base64"]))
                if not all(tx.verify_with_results()):
                    fail(f"{tag}: signature verification failed")
                if exp["error"] is None:
                    if rec["error"] is not None:
                        fail(f"{tag}: unexpected error {rec['error']}")
                else:
                    if rec["error"] is None or exp["error"] not in rec["error"]:
                        fail(f"{tag}: expected error {exp['error']}, got {rec['error']}")
                if len(rec["events"]) != exp["events"]:
                    fail(f"{tag}: events {len(rec['events'])} != {exp['events']}")
                if lam_delta(rec, PAYER_KEY) != exp["dPAYER"]:
                    fail(f"{tag}: dPAYER {lam_delta(rec, PAYER_KEY)} != {exp['dPAYER']}")
                if parse_uva(rec["after"][str(VOLUME)]) != exp["uva"]:
                    fail(f"{tag}: uva {parse_uva(rec['after'][str(VOLUME)])} != {exp['uva']}")
                if tok_amount(rec["after"][str(uvata_key)]) != exp["uvata_bal"]:
                    fail(f"{tag}: uvata {tok_amount(rec['after'][str(uvata_key)])} != {exp['uvata_bal']}")
                if exp["uvata_withheld"] is not None and withheld(rec["after"][str(uvata_key)]) != exp["uvata_withheld"]:
                    fail(f"{tag}: withheld {withheld(rec['after'][str(uvata_key)])} != {exp['uvata_withheld']}")
                if exp["uvata_lamports"] is not None and rec["after"][str(uvata_key)]["lamports"] != exp["uvata_lamports"]:
                    fail(f"{tag}: uvata lamports {rec['after'][str(uvata_key)]['lamports']} != {exp['uvata_lamports']}")
                if tok_delta(rec, USERQUOTE) != exp["userquote_delta"]:
                    fail(f"{tag}: userquote delta {tok_delta(rec, USERQUOTE)} != {exp['userquote_delta']}")
                if exp.get("uq_withheld") is not None and withheld(rec["after"][str(USERQUOTE)]) != exp["uq_withheld"]:
                    fail(f"{tag}: userquote withheld {withheld(rec['after'][str(USERQUOTE)])} != {exp['uq_withheld']}")
                for role, want in exp["deltas"].items():
                    key = {"userbase": USERBASE, "vaultbase": VAULTBASE, "vaultquote": VAULTQUOTE,
                           "proto": proto_key, "buyback": buyback_key}[role]
                    if tok_delta(rec, key) != want:
                        fail(f"{tag}: delta {role} {tok_delta(rec, key)} != {want}")
                if exp.get("rollback"):
                    for k, b in rec["before"].items():
                        if k == str(PAYER_KEY):
                            continue
                        if rec["after"][k] != b:
                            fail(f"{tag}: rollback violated for {k}")
                if exp.get("event") is not None:
                    got = decode_event(rec["step"], rec)
                    if got is None:
                        fail(f"{tag}: event decode failed")
                    for fkey, want in exp["event"].items():
                        if got.get(fkey) != want:
                            fail(f"{tag}: event {fkey} {got.get(fkey)} != {want}")
                if exp.get("site_fragment"):
                    blob = "\n".join(rec["logs"])
                    if exp["site_fragment"] not in blob:
                        fail(f"{tag}: site fragment {exp['site_fragment']} not in logs")
        def surface(recs):
            out = []
            for rec in recs:
                def strip(snap):
                    d = dict(snap)
                    if d.get(str(PAYER_KEY)) is not None:
                        d[str(PAYER_KEY)] = dict(d[str(PAYER_KEY)])
                        d[str(PAYER_KEY)]["lamports"] = 0
                    return d
                out.append({"step": rec["step"], "error": rec["error"],
                            "events": len(rec["events"]),
                            "before": strip(rec["before"]), "after": strip(rec["after"])})
            return out
        base = surface(by_case[label]["original"])
        for image in ("control", "candidate"):
            if surface(by_case[label][image]) != base:
                fail(f"{label}: {image} surface differs from original")
        for image in ("original", "control", "candidate"):
            sites = case["error_sites"][image]
            recs = by_case[label][image]
            if len(sites) != len(recs):
                fail(f"{label}/{image}: site count mismatch")
            for rec, site in zip(recs, sites):
                if site is not None and site not in "\n".join(rec["logs"]):
                    fail(f"{label}/{image}: recorded site line not in logs: {site}")
    print("PASS: 15 cases, 120 receipts, 12 parts, 3 images agree (signatures, deltas, events, error codes/sites, rollback)")


if __name__ == "__main__":
    main()
