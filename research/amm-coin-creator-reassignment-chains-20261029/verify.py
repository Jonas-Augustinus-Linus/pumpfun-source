#!/usr/bin/env python3
"""Independent re-verification for amm-coin-creator-reassignment-chains-20261029.

Checks, from the packet files alone (plus the three program images retained in the
repository: evidence/original/pump_amm/deployed.so and the two
candidate.so.gz artifacts named in IMAGE_PATHS):
- MANIFEST.json lists every packet file with a matching sha256.
- runtime/report.json.gz: 16 cases, 168 receipts, 17 parts
  (16x10 + 8), part sha256/byte counts match the part files.
- Every receipt transaction parses (solders) and all signatures verify.
- Every receipt's recorded before/after snapshots reproduce the
  report's expected values: fee-payer lamport deltas, the token-leg
  deltas (user base/quote, vault base/quote, Token-2022
  protocol/creator/buyback ATAs plus the new/bonding-curve/sharing/
  zero creator vault and destination ATAs), lamport deltas for the
  quote accounts (sweep moves lamports with the tokens, collect
  moves tokens only), the withheld balances after each step
  (178-byte override accounts at offset 170, 182-byte t22acct
  accounts at offset 174), the pool state
  (virtual_quote_reserves i128, protocol_fees, creator_fees,
  lp_supply), the user volume accumulator state (absent, or
  1,844,400 lamports / 137 bytes / payer user for a trade-created
  accumulator), and the decoded event fields (v2 buy/sell/exact,
  sweep amount/bucket/recipient, collect fee/creator/vault-ATA/
  dest, set coin_creator, migrate old/new coin_creator).
- Failure steps roll back every watched account except the fee
  payer (fee 5,000) and carry the expected error code plus the
  recorded per-image site line in their logs. Site lines are
  checked per image, never compared across images, because
  original and rebuilt sources differ in line numbers.
- The observed surface of every case (step, error, event count,
  and snapshots with fee-payer lamports zeroed) is identical
  across the original, control, and candidate images.
- Every silent no-op set (no error, 0 events) leaves every watched
  account except the fee payer unchanged and costs the payer 5,000.
- Every successful set moves the pool's coin_creator (bytes 211..243)
  from zero to the event's creator; every successful migrate moves it
  from the event's old value to the event's new value.
- The three program images hash to the values recorded in the
  report.

Usage (from the repository root):
    python3 -I -B research/amm-coin-creator-reassignment-chains-20261029/verify.py
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
PROTOCOL_ATA = Pubkey.from_string("2tZUDAsQqirqn1pdnYBVM7pDao57zsTSUspuFD2tAwTS")
CREATOR_ATA = Pubkey.from_string("HShRmMRVQBgRz1eCD1aSr1hUm2BdrALVimjNXRduJwZB")
DEST = Pubkey.from_string("Dv7PMRUFDTJywhzw88zJ3tpyBmj9HqLbNq8BZwXWb7MW")
BBATA = Pubkey.from_string("8imwZyx4D4zdUQ67TvftjjyGattafMNWMLs6HV8WNn1Y")
UVAATA = Pubkey.from_string("3RCdkkac8dWSnHdn6bu84a684wFXVRPZwpUFCp3G8q8y")
NEWVAULT22 = Pubkey.from_string("5GWYW1giwv9JvNFLjbWA4yUG6STzp93E3jRybpTXDBTy")
NEWDEST22 = Pubkey.from_string("HiaDPjMojq8s9nxZfR7A8WLFpc6fvBXe2uBk4TYRyCjc")
BCVAULT22 = Pubkey.from_string("AsXUCL3rpZmKgqXUsX3TFffsy6tjk78EbycoQ8aoRq1k")
BCDEST22 = Pubkey.from_string("3D6PeVh59L9i8GNhYWjKDqyKyPTrnvJFevyvFT3z9ivN")
SHVAULT22 = Pubkey.from_string("7vmDZC25QefmsBzpCdxcNe3vKLZo18fYjFVqAdUTr1iH")
SHDEST22 = Pubkey.from_string("Ea1RHzBD6Nuh6X5Lk8GKfujd6AUXqXYZTZspk4gXBJSj")
ZEROVAULT22 = Pubkey.from_string("CtzzHDfaH7NX6Zu6w5JpRiJRTctPVE5wMhqcnohx9mig")
ZERODEST22 = Pubkey.from_string("2sZUUBGq1i6aE47ZoxCaCW89jmYm2EXLPPmNMgMDXHMS")
ROLE_KEY = {"userbase": USERBASE, "userquote": USERQUOTE, "userlp": USERLP,
            "vaultbase": VAULTBASE, "vaultquote": VAULTQUOTE, "buyback": BUYBACK,
            "protoata": PROTOCOL_ATA, "creatorata": CREATOR_ATA, "dest": DEST,
            "bbata": BBATA, "uvata": UVAATA, "newvault": NEWVAULT22, "newdest": NEWDEST22,
            "bcvault": BCVAULT22, "bcdest": BCDEST22, "shvault": SHVAULT22,
            "shdest": SHDEST22, "zerovault": ZEROVAULT22, "zerodest": ZERODEST22}


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


def tok_withheld(entry):
    if entry is None:
        return None
    raw = bytes.fromhex(entry["data_hex"])
    if len(raw) >= 182:
        return struct.unpack_from("<Q", raw, 174)[0]
    if len(raw) >= 178:
        return struct.unpack_from("<Q", raw, 170)[0]
    return None


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


def pool_creator(entry):
    return bytes.fromhex(entry["data_hex"])[211:243].hex()


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
    if len(raw) < 90:
        return None
    return [struct.unpack_from("<Q", raw, 74)[0],
            struct.unpack_from("<Q", raw, 82)[0]]


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
    if kind in ("buy",):
        return {"disc": raw[:8].hex(), "len": len(raw),
                "curve": u64(raw, 64), "lp_bps": u64(raw, 72),
                "lp_fee": u64(raw, 80), "proto_bps": u64(raw, 88),
                "proto_fee": u64(raw, 96), "qwlp": u64(raw, 104),
                "uin": u64(raw, 112)}
    if kind == "sell":
        return {"disc": raw[:8].hex(), "len": len(raw),
                "curve": u64(raw, 64), "lp_bps": u64(raw, 72),
                "lp_fee": u64(raw, 80), "proto_bps": u64(raw, 88),
                "proto_fee": u64(raw, 96), "quote": u64(raw, 104),
                "uout": u64(raw, 112)}
    if kind == "buyx":
        return {"disc": raw[:8].hex(), "len": len(raw),
                "out": u64(raw, 16), "quote_in": u64(raw, 64),
                "lp_bps": u64(raw, 72), "lp_fee": u64(raw, 80),
                "proto_bps": u64(raw, 88), "proto_fee": u64(raw, 96),
                "qwlp": u64(raw, 104), "uin": u64(raw, 112)}
    if kind == "set":
        return {"disc": raw[:8].hex(), "len": len(raw),
                "creator": raw[112:144].hex()}
    if kind == "mig":
        return {"disc": raw[:8].hex(), "len": len(raw),
                "old": raw[112:144].hex(), "new": raw[144:176].hex()}
    if kind == "cbbuy":
        return {"disc": raw[:8].hex(), "len": len(raw),
                "out": u64(raw, 16), "curve": u64(raw, 64),
                "lp_fee": u64(raw, 80), "proto_fee": u64(raw, 96),
                "quote": u64(raw, 104), "uout": u64(raw, 112),
                "cb_bps": u64(raw, 408), "cb": u64(raw, 416),
                "bb_bps": u64(raw, 424), "bb": u64(raw, 432)}
    if kind == "cbexact":
        return {"disc": raw[:8].hex(), "len": len(raw),
                "out": u64(raw, 16), "curve": u64(raw, 64),
                "lp_fee": u64(raw, 80), "proto_fee": u64(raw, 96),
                "quote": u64(raw, 104), "uout": u64(raw, 112)}
    if kind in ("cbsell", "lsell"):
        return {"disc": raw[:8].hex(), "len": len(raw),
                "curve": u64(raw, 64), "lp_fee": u64(raw, 80),
                "proto_fee": u64(raw, 96), "quote": u64(raw, 104),
                "uout": u64(raw, 112)}
    if kind == "claim":
        return {"disc": raw[:8].hex(), "len": len(raw),
                "amount": u64(raw, 40), "claimed": u64(raw, 56),
                "earned": u64(raw, 64)}
    if kind in ("swp", "swc"):
        return {"disc": raw[:8].hex(), "len": len(raw),
                "timestamp": struct.unpack_from("<q", raw, 8)[0],
                "recipient": raw[112:144].hex(),
                "amount": u64(raw, 176), "bucket": raw[184]}
    if kind in ("dep", "wd"):
        return {"disc": raw[:8].hex(), "len": len(raw),
                "base": u64(raw, 72), "quote": u64(raw, 80)}
    if kind == "col":
        return {"disc": raw[:8].hex(), "len": len(raw),
                "timestamp": struct.unpack_from("<q", raw, 8)[0],
                "creator": raw[16:48].hex(), "fee": u64(raw, 48),
                "vault_ata": raw[56:88].hex(), "dest": raw[88:120].hex()}
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
    if report["case_count"] != 16 or report["receipt_count"] != 168:
        fail(f"counts {report['case_count']} cases / {report['receipt_count']} receipts")
    if report["counts"] != {"cases": 16, "receipts": 168, "parts": 17}:
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
    if len(receipts) != 168:
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
                for role, want in exp.get("lam_deltas", {}).items():
                    if lam_delta(rec, ROLE_KEY[role]) != want:
                        fail(f"{tag}: lam_delta {role} {lam_delta(rec, ROLE_KEY[role])} != {want}")
                for role, want in exp.get("wh_after", {}).items():
                    got = rec["after"][str(ROLE_KEY[role])]
                    if tok_withheld(got) != want:
                        fail(f"{tag}: wh_after {role} {tok_withheld(got)} != {want}")
                if pool_state(rec["after"][str(POOL)]) != exp["pool_after"]:
                    fail(f"{tag}: pool {pool_state(rec['after'][str(POOL)])} != {exp['pool_after']}")
                if vol_state(rec["after"][str(VOLUME)]) != exp["volume"]:
                    fail(f"{tag}: volume {vol_state(rec['after'][str(VOLUME)])} != {exp['volume']}")
                if "uva" in exp and uva_fields(rec["after"][str(VOLUME)]) != exp["uva"]:
                    fail(f"{tag}: uva {uva_fields(rec['after'][str(VOLUME)])} != {exp['uva']}")
                if exp.get("rollback"):
                    for k, b in rec["before"].items():
                        if k == str(PAYER_KEY):
                            continue
                        if rec["after"][k] != b:
                            fail(f"{tag}: rollback violated for {k}")
                # A silent no-op set (no error, 0 events) must leave every
                # watched account except the fee payer unchanged and cost 5,000.
                if rec["step"] == "set" and exp["error"] is None and exp["events"] == 0:
                    if exp["dPAYER"] != -5000:
                        fail(f"{tag}: silent no-op set expected dPAYER {exp['dPAYER']}")
                    for k, b in rec["before"].items():
                        if k != str(PAYER_KEY) and rec["after"][k] != b:
                            fail(f"{tag}: silent no-op set changed {k}")
                # Successful set/migrate: the pool's coin_creator (bytes 211..243)
                # must move from the event's old value to its new value.
                if rec["step"] in ("set", "mig") and exp["error"] is None and exp["events"] == 1:
                    ev = decode_event(rec["step"], rec)
                    cc_before = pool_creator(rec["before"][str(POOL)])
                    cc_after = pool_creator(rec["after"][str(POOL)])
                    new = ev["creator"] if rec["step"] == "set" else ev["new"]
                    if cc_after != new:
                        fail(f"{tag}: pool coin_creator {cc_after} != event {new}")
                    if rec["step"] == "set" and cc_before != "00" * 32:
                        fail(f"{tag}: set fired on a non-zero coin_creator {cc_before}")
                    if rec["step"] == "mig" and cc_before != ev["old"]:
                        fail(f"{tag}: pool coin_creator before {cc_before} != event old {ev['old']}")
                if exp.get("event") is not None:
                    got = decode_event(rec["step"], rec)
                    if got is None:
                        fail(f"{tag}: event decode failed")
                    for fkey, want in exp["event"].items():
                        if got.get(fkey) != want:
                            fail(f"{tag}: event {fkey} {got.get(fkey)} != {want}")
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
    print("PASS: 16 cases, 168 receipts, 17 parts, 3 images agree (signatures, deltas, withheld, events, error codes/sites, rollback, silent no-op set, coin_creator moves)")


if __name__ == "__main__":
    main()
