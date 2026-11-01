#!/usr/bin/env python3
"""Independent re-verification for amm-liquidity-mode-pools-sweep-collect-chains-20261029.

Checks, from the packet files alone (plus the three program images retained in the
repository: evidence/original/pump_amm/deployed.so and the two
candidate.so.gz artifacts named in IMAGE_PATHS):
- MANIFEST.json lists every packet file with a matching sha256.
- runtime/report.json.gz: 21 cases, 243 receipts, 25 parts
  (24x10 + 3), part sha256/byte counts match the part files.
- Every receipt transaction parses (solders) and all signatures verify.
- Every receipt's recorded before/after snapshots reproduce the
  report's expected values: fee-payer lamport deltas, the token-leg
  deltas (user base/quote/LP, vault base/quote, buyback, protocol
  ATA, creator vault ATA, collect DEST, cashback uvata), the pool
  state (virtual_quote_reserves i128, protocol_fees, creator_fees,
  lp_supply), the user volume accumulator state (lamports/length/
  user) and its cashback fields (earned, claimed), the global
  volume accumulator never changing, and the decoded event fields
  (deposit/withdraw, v2 buy/sell, legacy cashback buy/sell, sweep
  amount/bucket/recipient, collect fee/vault/dest, cashback claim).
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

Receipts are stored per case in image order (original, then
control, then candidate), each block in case step order.

Usage (from the repository root):
    python3 -I -B research/amm-liquidity-mode-pools-sweep-collect-chains-20261029/verify.py

It re-checks the recorded receipts against the report's expected
values; it does not re-execute any transaction.
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
GVA = Pubkey.from_string("C2aFPdENg4A2HQsmrd5rTw5TaYBX5Ku887cWjbFKtZpw")
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
    if len(raw) == 0:
        return None
    return {"lamports": entry["lamports"], "len": len(raw),
            "user": raw[8:40].hex()}


def uva_fields(entry):
    if entry is None:
        return None
    raw = bytes.fromhex(entry["data_hex"])
    if len(raw) < 90:
        return None
    return [struct.unpack_from("<Q", raw, 74)[0],
            struct.unpack_from("<Q", raw, 82)[0]]


def u64(raw, off):
    return struct.unpack_from("<Q", raw, off)[0]


def ev_lines(logs):
    return [base64.b64decode(l.split("Program data: ", 1)[1].strip())
            for l in logs if l.startswith("Program data: ")]


def decode_event(kind, rec):
    lines = ev_lines(rec["logs"])
    if kind in ("dep", "wd"):
        if len(lines) != 1:
            return None
        raw = lines[0]
        return {"disc": raw[:8].hex(), "len": len(raw),
                "base": u64(raw, 72), "quote": u64(raw, 80)}
    if kind == "buy":
        if len(lines) != 1:
            return None
        raw = lines[0]
        return {"disc": raw[:8].hex(), "len": len(raw),
                "curve": u64(raw, 64), "lp_bps": u64(raw, 72),
                "lp_fee": u64(raw, 80), "proto_bps": u64(raw, 88),
                "proto_fee": u64(raw, 96), "qwlp": u64(raw, 104),
                "uin": u64(raw, 112)}
    if kind == "sell":
        if len(lines) != 1:
            return None
        raw = lines[0]
        return {"disc": raw[:8].hex(), "len": len(raw),
                "curve": u64(raw, 64), "lp_bps": u64(raw, 72),
                "lp_fee": u64(raw, 80), "proto_bps": u64(raw, 88),
                "proto_fee": u64(raw, 96), "quote": u64(raw, 104),
                "uout": u64(raw, 112)}
    if kind in ("swp", "swc"):
        if len(lines) != 1:
            return None
        raw = lines[0]
        return {"disc": raw[:8].hex(), "len": len(raw),
                "timestamp": struct.unpack_from("<q", raw, 8)[0],
                "recipient": raw[112:144].hex(),
                "amount": u64(raw, 176), "bucket": raw[184]}
    if kind == "col":
        if len(lines) != 1:
            return None
        raw = lines[0]
        return {"disc": raw[:8].hex(), "len": len(raw),
                "timestamp": struct.unpack_from("<q", raw, 8)[0],
                "creator": raw[16:48].hex(), "fee": u64(raw, 48),
                "vault_ata": raw[56:88].hex(), "dest": raw[88:120].hex()}
    if kind == "claim":
        if len(lines) != 1:
            return None
        raw = lines[0]
        return {"disc": raw[:8].hex(), "len": len(raw),
                "user": raw[8:40].hex(), "amount": u64(raw, 40),
                "ts": struct.unpack_from("<q", raw, 48)[0],
                "total_claimed": u64(raw, 56), "total_earned": u64(raw, 64)}
    if kind == "cbbuy":
        for raw in lines:
            if len(raw) == 497:
                return {"disc": raw[:8].hex(), "len": len(raw),
                        "out": u64(raw, 16), "max": u64(raw, 24),
                        "curve": u64(raw, 64), "lp_bps": u64(raw, 72),
                        "lp_fee": u64(raw, 80), "proto_bps": u64(raw, 88),
                        "proto_fee": u64(raw, 96), "quote": u64(raw, 104),
                        "uout": u64(raw, 112), "creator_bps": u64(raw, 344),
                        "creator_fee": u64(raw, 352), "track": raw[360],
                        "cb_bps": u64(raw, 408), "cb": u64(raw, 416),
                        "bb_bps": u64(raw, 424), "bb": u64(raw, 432)}
        return None
    if kind == "cbsell":
        if len(lines) != 1:
            return None
        raw = lines[0]
        return {"disc": raw[:8].hex(), "len": len(raw),
                "curve": u64(raw, 64), "lp_fee": u64(raw, 80),
                "protocol_fee": u64(raw, 96), "quote": u64(raw, 104),
                "user_out": u64(raw, 112),
                "creator_bps": u64(raw, 344), "creator_fee": u64(raw, 352),
                "cashback_bps": u64(raw, 360), "cashback": u64(raw, 368),
                "buyback_fee": u64(raw, 384)}
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
    if report["case_count"] != 21 or report["receipt_count"] != 243:
        fail(f"counts {report['case_count']} cases / {report['receipt_count']} receipts")
    if report["counts"] != {"cases": 21, "receipts": 243, "parts": 25}:
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
    if len(receipts) != 243:
        fail(f"receipt total {len(receipts)}")
    pos = 0
    for case in report["cases"]:
        label = case["label"]
        expect = case["steps"]
        nsteps = len(expect)
        by_image = {}
        for image in ("original", "control", "candidate"):
            block = receipts[pos:pos + nsteps]
            pos += nsteps
            if len(block) != nsteps:
                fail(f"{label}/{image}: short receipt block")
            by_image[image] = block
            for rec, exp in zip(block, expect):
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
                    if len(rec["events"]) != 0:
                        fail(f"{tag}: failed step emitted events")
                    for k, b in rec["before"].items():
                        if k == str(PAYER_KEY):
                            continue
                        if rec["after"][k] != b:
                            fail(f"{tag}: rollback violated for {k}")
                # A silent no-op collect (no error, 0 events) must leave every
                # watched account except the fee payer unchanged.
                if rec["step"] == "col" and exp["error"] is None and exp["events"] == 0:
                    if lam_delta(rec, PAYER_KEY) != -5000:
                        fail(f"{tag}: silent no-op collect payer delta {lam_delta(rec, PAYER_KEY)}")
                    for k, b in rec["before"].items():
                        if k != str(PAYER_KEY) and rec["after"][k] != b:
                            fail(f"{tag}: silent no-op collect changed {k}")
                if exp["events"] is not None and len(rec["events"]) != exp["events"]:
                    fail(f"{tag}: events {len(rec['events'])} != {exp['events']}")
                if lam_delta(rec, PAYER_KEY) != exp["dPAYER"]:
                    fail(f"{tag}: dPAYER {lam_delta(rec, PAYER_KEY)} != {exp['dPAYER']}")
                for role, want in exp["deltas"].items():
                    if tok_delta(rec, ROLE_KEY[role]) != want:
                        fail(f"{tag}: delta {role} {tok_delta(rec, ROLE_KEY[role])} != {want}")
                if exp["pool_after"] is not None and pool_state(rec["after"][str(POOL)]) != exp["pool_after"]:
                    fail(f"{tag}: pool {pool_state(rec['after'][str(POOL)])} != {exp['pool_after']}")
                if vol_state(rec["after"][str(VOLUME)]) != exp["volume"]:
                    fail(f"{tag}: volume {vol_state(rec['after'][str(VOLUME)])} != {exp['volume']}")
                if exp["uva"] is not None:
                    if uva_fields(rec["after"][str(VOLUME)]) != exp["uva"]:
                        fail(f"{tag}: uva {uva_fields(rec['after'][str(VOLUME)])} != {exp['uva']}")
                else:
                    if vol_state(rec["after"][str(VOLUME)]) is not None:
                        fail(f"{tag}: volume should stay absent")
                if rec["after"][str(GVA)] != rec["before"][str(GVA)]:
                    fail(f"{tag}: global volume accumulator changed")
                if exp.get("event") is not None:
                    got = decode_event(rec["step"], rec)
                    if got is None:
                        fail(f"{tag}: event decode failed")
                    for fkey, want in exp["event"].items():
                        if got.get(fkey) != want:
                            fail(f"{tag}: event {fkey} {got.get(fkey)} != {want}")
            sites = case["error_sites"][image]
            if len(sites) != nsteps:
                fail(f"{label}/{image}: site count mismatch")
            for rec, site in zip(block, sites):
                if site is not None and site not in "\n".join(rec["logs"]):
                    fail(f"{label}/{image}: recorded site line not in logs: {site}")

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
        base = surface(by_image["original"])
        for image in ("control", "candidate"):
            if surface(by_image[image]) != base:
                fail(f"{label}: {image} surface differs from original")
    if pos != len(receipts):
        fail(f"consumed {pos} of {len(receipts)} receipts")
    print("PASS: 21 cases, 243 receipts, 25 parts, 3 images agree (signatures, deltas, uva, events, error codes/sites, rollback, silent no-op collects)")


if __name__ == "__main__":
    main()
