#!/usr/bin/env python3
"""Independent re-verification for amm-coin-creator-downstream-binding-20261029.

Checks, from the packet files alone (plus the three program images):
- MANIFEST.json lists every packet file with a matching sha256.
- runtime/report.json.gz: 18 cases, 117 receipts, 12 parts (11x10 + 7),
  part sha256/byte counts match the part files.
- Every receipt transaction parses (solders) and all signatures verify.
- Every receipt's recorded before/after snapshots reproduce the
  report's expected values: payer delta, pool coin_creator bytes,
  pool protocol/creator fee fields, per-account token deltas,
  event count, and decoded event fields (buy/v2buy/sell/set/mig/
  sweep/collect layouts documented in README).
- Failure steps roll back every watched account except the payer
  (fee 5,000) and carry the expected error code plus the recorded
  per-image site line ("thrown in" / "caused by account") in their
  logs. Site lines are checked per image, never compared across
  images, because original and rebuilt sources differ in line
  numbers.
- The observed surface of every case (step, error, event count,
  pool bytes/fees, all token deltas, payer delta) is identical
  across the original, control, and candidate images.
- The three program images hash to the values recorded in the
  report.

Usage: python3 verify.py   (run from this packet directory)
"""
if not __debug__: raise SystemExit("Run without -O")
import base64
import gzip
import hashlib
import json
import struct
import sys
from pathlib import Path

from solders.transaction import Transaction

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[1]
IMAGE_PATHS = {
    "original": REPOSITORY / "evidence/original/pump_amm/deployed.so",
    "control": REPOSITORY / "research/amm-multi-hop-group-slice-recovery/artifacts/candidate.so.gz",
    "candidate": REPOSITORY / "research/amm-transfer-fee-diagnostic-recovery/artifacts/candidate.so.gz",
}
IMAGE_PINS = {"original": "6a7ad34596d83b4c435b32f458a56e718e9f82eb4ad38e4316616d15d24d8ff7", "control": "7a300434dced61413bde10788594b427d5649563e0223efcf09e6b214aff7ad3", "candidate": "d17a657baf5cc19736a924c41e75424604411ddbe9f6e72cddf41ab72a695007"}
FIXTURE_SHA256 = '10d77247c4fbecd0aa05a9a67b34de3100e5998ca0f078dcc9f4b2ebc7428647'
EVENT_LAYOUTS = {"buy": ("67f4521f2cf57777", 497), "v2buy": ("67f4521f2cf57777", 500), "sell": ("3e2f370aa503dc2a", 449), "set": ("966bc77b7ccf66e4", 144), "mig": ("aadd52c793a5f72e", 176), "sweep": ("82a42461e48287a5", 185), "collect": ("e8f5c2eeeada3a59", 120)}
WATCH_ORDER = ["pool", "userquote", "userbase", "vaultbase", "vaultquote",
               "PROTOCOL_ATA", "CREATOR_ATA", "NEW_ATA", "SH_ATA", "DEF_ATA",
               "volume", "buyback", "payer", "DEST_OLD", "DEST_NEW", "DEST_SH"]


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


def tok_delta(before, after):
    return (tok_amount(after) or 0) - (tok_amount(before) or 0)


def lam_delta(before, after):
    return (after["lamports"] if after else 0) - (before["lamports"] if before else 0)


def pool_cc(entry):
    return bytes.fromhex(entry["data_hex"])[211:243].hex()


def pool_fees(entry):
    raw = bytes.fromhex(entry["data_hex"])
    return [struct.unpack_from("<Q", raw, 271)[0],
            struct.unpack_from("<Q", raw, 279)[0]]


def ev_data(logs):
    lines = [l for l in logs if l.startswith("Program data: ")]
    if len(lines) != 1:
        return None
    return base64.b64decode(lines[0].split("Program data: ", 1)[1].strip())


def u64(raw, off):
    return struct.unpack_from("<Q", raw, off)[0]


def decode_event(kind, rec):
    raw = ev_data(rec["logs"])
    if raw is None:
        return None
    if kind in ("buy", "v2buy"):
        return {"curve": u64(raw, 64), "lp_fee": u64(raw, 80),
                "proto_fee": u64(raw, 96), "qwlp": u64(raw, 104),
                "uqin": u64(raw, 112), "creator_bps": u64(raw, 344),
                "creator_fee": u64(raw, 352),
                "buyback_fee": u64(raw, 432) if kind == "buy" else u64(raw, 435),
                "quote": u64(raw, 64)}
    if kind == "sell":
        return {"proto_fee": u64(raw, 96)}
    if kind == "set":
        return {"coin_creator": raw[112:144].hex()}
    if kind == "mig":
        return {"old": raw[112:144].hex(), "new": raw[144:176].hex()}
    if kind == "sweep":
        return {"amount": u64(raw, 176), "bucket": raw[184]}
    if kind == "collect":
        return {"fee": u64(raw, 48)}
    return None


def main():
    manifest = json.loads((ROOT / "MANIFEST.json").read_text())
    paths = list(ROOT.rglob("*"))
    if any(p.is_symlink() for p in paths) or {p.relative_to(ROOT).as_posix() for p in paths if p.is_file() and p.name != "MANIFEST.json"} != set(manifest["files"]):
        fail("exact manifest file inventory")
    if sha((ROOT / "fixture-bindings.json").read_bytes()) != FIXTURE_SHA256:
        fail("reviewed fixture binding")
    fixture = json.loads((ROOT / "fixture-bindings.json").read_text())
    if sha((ROOT / "producer.py").read_bytes()) != fixture["producer_sha256"]:
        fail("unchanged original producer")
    role_keys = fixture["roles"]
    for rel, want in manifest["files"].items():
        path = ROOT / rel
        if not path.exists():
            fail(f"manifest file missing: {rel}")
        if sha(path.read_bytes()) != want:
            fail(f"manifest sha mismatch: {rel}")
    with gzip.open(ROOT / "runtime" / "report.json.gz", "rt", encoding="utf-8") as fh:
        report = json.load(fh)
    if report["case_count"] != 18:
        fail(f"case_count {report['case_count']} != 18")
    if report["receipt_count"] != 117:
        fail(f"receipt_count {report['receipt_count']} != 117")
    if report["counts"] != {"cases": 18, "receipts": 117, "parts": 12}:
        fail(f"counts {report['counts']}")
    if report["mismatches"] != []:
        fail(f"mismatches non-empty: {report['mismatches']}")
    if report["input_sha256"] != IMAGE_PINS or report["images"] != IMAGE_PINS:
        fail("declared historical image binding")
    for name, want in IMAGE_PINS.items():
        raw = IMAGE_PATHS[name].read_bytes()
        raw = gzip.decompress(raw) if IMAGE_PATHS[name].suffix == ".gz" else raw
        if sha(raw) != want:
            fail(f"image sha mismatch: {name}")
    layout = [{"label": c["label"], "family": c["family"], "steps": [s["name"] for s in c["steps"]]} for c in report["cases"]]
    expected_layout = [{"label": c["label"], "family": c["family"], "steps": [s["name"] for s in c["steps"]]} for c in fixture["cases"]]
    if layout != expected_layout:
        fail("exact 18-case family and step membership")
    wire_pins = {(c["label"], s["name"]): s["wire_sha256"] for c in fixture["cases"] for s in c["steps"]}
    expected_steps = {(c["label"], s["name"]): s["reviewed_expected"] for c in fixture["cases"] for s in c["steps"]}
    receipts = []
    for part in report["parts"]:
        path = ROOT / part["file"]
        if sha(path.read_bytes()) != part["sha256"]:
            fail(f"part sha mismatch: {part['file']}")
        if path.stat().st_size != part["bytes"]:
            fail(f"part bytes mismatch: {part['file']}")
        with gzip.open(path, "rt", encoding="utf-8") as fh:
            chunk = [json.loads(line) for line in fh]
        if len(chunk) != part["count"]:
            fail(f"part count mismatch: {part['file']}")
        receipts.extend(chunk)
    if len(receipts) != 117:
        fail(f"total receipts {len(receipts)} != 117")
    if [p["count"] for p in report["parts"]] != [10] * 11 + [7]:
        fail(f"part counts {[p['count'] for p in report['parts']]}")

    # expected receipt order: cases x images x steps
    expected_order = []
    for case in report["cases"]:
        for image in ("original", "control", "candidate"):
            for step in case["steps"]:
                expected_order.append((case["label"], image, step["name"]))
    got_order = [(r["case"], r["image"], r["step"]) for r in receipts]
    if got_order != expected_order:
        fail("receipt order does not match report cases")

    for c in fixture["cases"]:
        for image in ("original", "control", "candidate"):
            chain = [r for r in receipts if r["case"] == c["label"] and r["image"] == image]
            for previous, current in zip(chain, chain[1:]):
                if previous["after"] != current["before"]:
                    fail("chained account continuity")

    # per-receipt checks + observed surface per case
    surfaces = {}
    for (case, image, step_name), rec, exp in zip(
            expected_order, receipts,
            [s for c in report["cases"] for _ in ("original", "control", "candidate") for s in c["steps"]]):
        tag = f"{case}/{image}/{step_name}"
        raw_wire = base64.b64decode(rec["transaction_base64"], validate=True)
        tx = Transaction.from_bytes(raw_wire)
        if bytes(tx) != raw_wire or len(tx.signatures) != 1 or sha(raw_wire) != wire_pins[(case, step_name)]:
            fail("reviewed signed instruction/account/privilege binding")
        if len(tx.message.instructions) != 1 or str(tx.message.account_keys[tx.message.instructions[0].program_id_index]) != "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA":
            fail("signed AMM instruction")
        if set(exp) - {"name", "error", "events", "payer", "deltas", "pool_cc", "pool_fees", "event", "rollback", "site_fragment", "log_fragment"}:
            fail("unsupported expected field")
        if set(rec["before"]) != set(role_keys.values()) or set(rec["after"]) != set(role_keys.values()):
            fail("fixed watched account roles")
        if rec["events"] != [line for line in rec["logs"] if line.startswith("Program data: ")]:
            fail("actual event logs")
        if rec["events"]:
            raw_event = ev_data(rec["logs"])
            if step_name not in EVENT_LAYOUTS or (raw_event[:8].hex(), len(raw_event)) != EVENT_LAYOUTS[step_name]:
                fail("event discriminator and layout")
        for name, wanted in exp.get("deltas", {}).items():
            if name not in role_keys or tok_delta(rec["before"][role_keys[name]], rec["after"][role_keys[name]]) != wanted:
                fail("expected token delta: " + name)
        if case == "set-then-buy-uncreated-ata" and step_name == "buy":
            entry = rec["after"][role_keys["NEW_ATA"]]
            if rec["before"][role_keys["NEW_ATA"]] is not None or entry["lamports"] != 2039280 + 5475:
                fail("actual created ATA rent and fee lamports")
        if not all(tx.verify_with_results()):
            fail(f"{tag}: signature verification failed")
        # snapshot keys must cover the watch set exactly
        if set(rec["before"]) != set(rec["after"]):
            fail(f"{tag}: before/after key sets differ")
        pool_key = role_keys["pool"]
        pool_before, pool_after = rec["before"][pool_key], rec["after"][pool_key]
        if pool_cc(pool_after) != exp["pool_cc"]:
            fail(f"{tag}: pool_cc {pool_cc(pool_after)} != {exp['pool_cc']}")
        if pool_fees(pool_after) != exp["pool_fees"]:
            fail(f"{tag}: pool_fees {pool_fees(pool_after)} != {exp['pool_fees']}")
        if exp["error"] is None:
            if rec["error"] is not None:
                fail(f"{tag}: unexpected error {rec['error']}")
        else:
            if rec["error"] is None or exp["error"] not in rec["error"]:
                fail(f"{tag}: expected error {exp['error']}, got {rec['error']}")
        if len(rec["events"]) != exp["events"]:
            fail(f"{tag}: events {len(rec['events'])} != {exp['events']}")
        # payer delta: the only key allowed to move on failure, and the
        # fee on success; recompute from the snapshot with the largest
        # lamport move among non-token accounts is fragile, so use the
        # report-independent rule: payer is the account whose lamports
        # change equals -expected payer fee and which is not a token acct
        payer_key = str(tx.message.account_keys[0])
        if payer_key != role_keys["payer"] or lam_delta(rec["before"][payer_key], rec["after"][payer_key]) != -exp["payer"]:
            fail("actual signed payer delta")
        if exp.get("rollback"):
            for k in rec["before"]:
                if k == payer_key:
                    continue
                if rec["before"][k] != rec["after"][k]:
                    fail(f"{tag}: rollback violated for {k}")
        if exp.get("site_fragment"):
            blob = "\n".join(rec["logs"])
            if exp["site_fragment"] not in blob:
                fail(f"{tag}: site fragment {exp['site_fragment']} not in logs")
        if exp.get("log_fragment"):
            blob = "\n".join(rec["logs"])
            if exp["log_fragment"] not in blob:
                fail(f"{tag}: log fragment {exp['log_fragment']} not in logs")
        if exp.get("event") is not None:
            got = decode_event(step_name, rec)
            if got is None:
                fail(f"{tag}: event decode failed")
            if set(exp["event"]) - set(got):
                fail("unsupported expected event field")
            for fkey, want in exp["event"].items():
                if got.get(fkey) != want:
                    fail(f"{tag}: event {fkey} {got.get(fkey)} != {want}")
        if exp != expected_steps[(case, step_name)]:
            fail("complete reviewed expected-step obligations")
        # recorded per-image site line must appear in that receipt's logs
        site = report["cases"][[c["label"] for c in report["cases"]].index(case)]["error_sites"][image][
            [s["name"] for s in report["cases"][[c["label"] for c in report["cases"]].index(case)]["steps"]].index(step_name)]
        if site is not None and site not in rec["logs"]:
            fail(f"{tag}: recorded site line not in logs")
        surface = {"step": step_name, "error": rec["error"],
                   "events": len(rec["events"]),
                   "pool_cc": pool_cc(pool_after),
                   "pool_fees": pool_fees(pool_after),
                   "payer": lam_delta(rec["before"][payer_key], rec["after"][payer_key]),
                   "deltas": {k: tok_delta(rec["before"][k], rec["after"][k]) for k in rec["before"]}}
        surfaces.setdefault(case, {}).setdefault(image, []).append(surface)
    for case, by_image in surfaces.items():
        base = by_image["original"]
        for image in ("control", "candidate"):
            if by_image[image] != base:
                fail(f"{case}: {image} observed surface differs from original")
    print("PASS: 18 cases, 117 receipts, 12 parts, 3 images agree "
          "(signatures, deltas, events, error codes/sites, rollback)")


if __name__ == "__main__":
    main()
