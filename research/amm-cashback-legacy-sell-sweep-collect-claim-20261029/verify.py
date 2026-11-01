#!/usr/bin/env python3
"""Independent re-verification for amm-cashback-legacy-sell-sweep-collect-claim-20261029.

Checks, from the packet files alone (plus the three program images retained in the
repository: evidence/original/pump_amm/deployed.so and the two
candidate.so.gz artifacts named in IMAGE_PATHS):
- MANIFEST.json lists every packet file with a matching sha256.
- runtime/report.json.gz: 15 cases, 123 receipts, 13 parts
  (12x10 + 3), part sha256/byte counts match the part files.
- Every receipt transaction parses (solders) and all signatures verify.
- Every receipt's recorded before/after snapshots reproduce the
  report's expected values: fee-payer lamport deltas, the token-leg
  deltas (user base/quote/LP, vault base/quote, buyback, protocol
  ATA, creator vault ATA, collect DEST, cashback uvata), the pool
  state (virtual_quote_reserves i128, protocol_fees, creator_fees,
  lp_supply), the user volume accumulator state (lamports/length/
  user) and its cashback fields (earned @74..82, claimed @82..90),
  uvata lamport checkpoints, and the decoded event fields
  (legacy sell curve/lp/protocol/quote/uout, cashback sell
  curve/lp/protocol/quote/uout/creator/cashback/buyback, sweep
  amount/bucket/recipient, collect fee/vault/dest, claim
  amount/total_claimed/total_earned).
- Failure steps roll back every watched account except the fee payer
  (fee 5,000) and carry the expected error code plus the recorded
  per-image site line in their logs. Site lines are checked per
  image, never compared across images, because original and rebuilt
  sources differ in line numbers.
- Silent no-op collects (no error, 0 events) leave every watched
  account except the fee payer unchanged; the payer pays 5,000.
- The observed surface of every case (step, error, event count, and
  snapshots with fee-payer lamports zeroed) is identical across the
  original, control, and candidate images.
- The three program images hash to the values recorded in the report.

Usage (from the repository root):
    python3 -I -B research/amm-cashback-legacy-sell-sweep-collect-claim-20261029/verify.py
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
PAYER_KEY = Pubkey.from_string("DXyM8yAHqpMzDtvwz5DXoEUQmPxjJPMKCASCPhLMKpEx")
POOL = Pubkey.from_string("GseMAnNDvntR5uFePZ51yZBXzNSn7GdFPkfHwfr6d77J")
USERBASE = Pubkey.from_string("5jKh25biPsnrmLWXXuqKNH2Q67j69T4Q7Zew5c8wJKaV")
USERQUOTE = Pubkey.from_string("5oEzAP4izB65uRm2yDAEf9oALGwHpWkDfyKb8zBY3euC")
USERLP = Pubkey.from_string("5sAHJgXjaUPK3X1YQWV9x2ZvaS9VVaS3ENzFCNE8nzDu")
VAULTBASE = Pubkey.from_string("5jMpkf4JF4noHftLgNKyPNh6roVfPSGSjuEk3U4eLKRa")
VAULTQUOTE = Pubkey.from_string("43DVcZR4kQFjh4Xm2i3DcneRxNjZp7HMud8yDrJWrDr8")
BUYBACK = Pubkey.from_string("HjQjngTDqoHE6aaGhUqfz9aQ7WZcBRjy5xB8PScLSr8i")
VOLUME = Pubkey.from_string("8NyBnxo9mS5MsqY4qoKmrt7MS89d7MNV6rh5fu2YsQPT")
PROTOCOL_ATA = Pubkey.from_string("94qWNrtmfn42h3ZjUZwWvK1MEo9uVmmrBPd2hpNjYDjb")
CREATOR_ATA = Pubkey.from_string("3E6RtRCxo7Yz64zi8aSmC9DtNKcaMp5rFUcBnJKsc2fg")
DEST = Pubkey.from_string("7MNnTJmxb2vJ7WWi15fNMHYhwvmvJyY5XMegUjDKEKKT")
UVATA = Pubkey.from_string("BEaaJNs1cVZKv29qYcXaaDSgm6Defa5b6kt5pRcUkHWe")
ROLE_KEY = {"userbase": USERBASE, "userquote": USERQUOTE, "userlp": USERLP,
            "vaultbase": VAULTBASE, "vaultquote": VAULTQUOTE, "buyback": BUYBACK,
            "protoata": PROTOCOL_ATA, "creatorata": CREATOR_ATA, "dest": DEST,
            "uvata": UVATA}


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


def pool_state(entry):
    if entry is None:
        return None
    d = bytes.fromhex(entry["data_hex"])
    return [int.from_bytes(d[245:261], "little", signed=True),
            struct.unpack_from("<Q", d, 271)[0],
            struct.unpack_from("<Q", d, 279)[0],
            struct.unpack_from("<Q", d, 203)[0]]


def vol_state(entry):
    if entry is None:
        return None
    raw = bytes.fromhex(entry["data_hex"])
    return {"lamports": entry["lamports"], "len": len(raw),
            "user": raw[8:40].hex()}


def uva_fields(entry):
    if entry is None:
        return None
    raw = bytes.fromhex(entry["data_hex"])
    return {"earned": struct.unpack_from("<Q", raw, 74)[0],
            "claimed": struct.unpack_from("<Q", raw, 82)[0]}


def u64(raw, off):
    return struct.unpack_from("<Q", raw, off)[0]


def ev_data(logs):
    lines = [l for l in logs if l.startswith("Program data: ")]
    if len(lines) != 1:
        return None
    return base64.b64decode(lines[0].split("Program data: ", 1)[1].strip())


def decode_event(kind, rec):
    raw = ev_data(rec["logs"])
    if raw is None:
        return None
    if kind in ("lsell", "msell"):
        return {"disc": raw[:8].hex(), "len": len(raw),
                "curve": u64(raw, 64), "lp_bps": u64(raw, 72),
                "lp_fee": u64(raw, 80), "proto_bps": u64(raw, 88),
                "proto_fee": u64(raw, 96), "quote": u64(raw, 104),
                "uout": u64(raw, 112)}
    if kind == "cbsell":
        return {"disc": raw[:8].hex(), "len": len(raw),
                "curve": u64(raw, 64), "lp_fee": u64(raw, 80),
                "protocol_fee": u64(raw, 96), "quote": u64(raw, 104),
                "user_out": u64(raw, 112),
                "creator_bps": u64(raw, 344), "creator_fee": u64(raw, 352),
                "cashback_bps": u64(raw, 360), "cashback": u64(raw, 368),
                "buyback_fee": u64(raw, 384)}
    if kind in ("swp", "swc"):
        return {"disc": raw[:8].hex(), "len": len(raw),
                "timestamp": struct.unpack_from("<q", raw, 8)[0],
                "recipient": raw[112:144].hex(),
                "amount": u64(raw, 176), "bucket": raw[184]}
    if kind == "col":
        return {"disc": raw[:8].hex(), "len": len(raw),
                "timestamp": struct.unpack_from("<q", raw, 8)[0],
                "creator": raw[16:48].hex(), "fee": u64(raw, 48),
                "vault_ata": raw[56:88].hex(), "dest": raw[88:120].hex()}
    if kind == "claim":
        return {"disc": raw[:8].hex(), "len": len(raw),
                "user": raw[8:40].hex(), "amount": u64(raw, 40),
                "ts": struct.unpack_from("<q", raw, 48)[0],
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
    if report["case_count"] != 15 or report["receipt_count"] != 123:
        fail(f"counts {report['case_count']} cases / {report['receipt_count']} receipts")
    if report["counts"] != {"cases": 15, "receipts": 123, "parts": 13}:
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
    if len(receipts) != 123:
        fail(f"receipt total {len(receipts)}")
    by_case = {}
    for rec in receipts:
        by_case.setdefault(rec["case"], {}).setdefault(rec["image"], []).append(rec)
    for case in report["cases"]:
        label = case["label"]
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
                for role, want in exp["deltas"].items():
                    if tok_delta(rec, ROLE_KEY[role]) != want:
                        fail(f"{tag}: delta {role} {tok_delta(rec, ROLE_KEY[role])} != {want}")
                for role, want in exp.get("lam_after", {}).items():
                    got = rec["after"][str(ROLE_KEY[role])]
                    if got is None or got["lamports"] != want:
                        fail(f"{tag}: lam_after {role} {None if got is None else got['lamports']} != {want}")
                for role in exp.get("absent", []):
                    if rec["after"][str(ROLE_KEY[role])] is not None:
                        fail(f"{tag}: {role} should stay absent")
                if pool_state(rec["after"][str(POOL)]) != exp["pool_after"]:
                    fail(f"{tag}: pool {pool_state(rec['after'][str(POOL)])} != {exp['pool_after']}")
                if vol_state(rec["after"][str(VOLUME)]) != exp["volume"]:
                    fail(f"{tag}: volume {vol_state(rec['after'][str(VOLUME)])} != {exp['volume']}")
                if exp.get("uva") is not None:
                    if uva_fields(rec["after"][str(VOLUME)]) != exp["uva"]:
                        fail(f"{tag}: uva {uva_fields(rec['after'][str(VOLUME)])} != {exp['uva']}")
                # A silent no-op collect (no error, 0 events) must leave every
                # watched account except the fee payer unchanged.
                silent_noop = (rec["step"] == "col" and exp["error"] is None
                               and exp["events"] == 0)
                if exp.get("rollback") or silent_noop:
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
                if exp.get("log_fragment"):
                    blob = "\n".join(rec["logs"])
                    if exp["log_fragment"] not in blob:
                        fail(f"{tag}: log fragment {exp['log_fragment']} not in logs")
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
    print("PASS: 15 cases, 123 receipts, 13 parts, 3 images agree (signatures, deltas, uva, events, error codes/sites, rollback)")


if __name__ == "__main__":
    main()
