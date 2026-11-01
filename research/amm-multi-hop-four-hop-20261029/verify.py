"""Verify the retained multi-hop four-hop receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, harness scripts, fixture) hash to the
  recorded values;
- 24 cases x 3 images = 72 receipts, ordered, with contexts matching
  the report, stored as 8 parts (10 x 7 + 2), each under 25MB;
- every transaction verifies (all signatures valid, 1 signature
  field each);
- all three images agree on every case (identical error and observed
  values), and the recorded error sites match the receipts' logs
  ("thrown in" and "caused by account" forms);
- success cases: the eleven token-amount deltas (userquote, u4,
  buyback, vb1, vq1, vb2, vq2, vb3, vq3, vb4, vq4) match the case's
  expected deltas, the payer is charged exactly 1,849,400 lamports
  (1,844,400 volume-accumulator rent + 5,000 fee), the volume
  account holds 1,844,400 lamports in 137 bytes keyed to the payer,
  and exactly 4 hop events are emitted;
- error cases: fail with the expected code and log fragment, roll
  back every account except the fee payer's 5,000 fee, and carry the
  recorded hop-event count in their logs (limit failures 4, buy
  pool4owner 3, all others 0 -- the count must agree across images
  but is not forced to 0, since hops emit events before the final
  limit check and before buy-side hop4 validation).
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

if not __debug__:
    raise SystemExit("Run without -O")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CONTROL = ROOT / "research/amm-multi-hop-group-slice-recovery/artifacts/candidate.so.gz"
CANDIDATE = ROOT / "research/amm-transfer-fee-diagnostic-recovery/artifacts/candidate.so.gz"
IMAGES = ("original", "control", "candidate")
WATCH = ("userquote", "u4", "buyback", "vb1", "vq1", "vb2", "vq2",
          "vb3", "vq3", "vb4", "vq4")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tok_amount(snapshot, key):
    row = snapshot.get(key)
    assert row is not None, f"missing snapshot row {key}"
    return struct.unpack("<Q", bytes.fromhex(row["data_hex"])[64:72])[0]


def main():
    paths = list(HERE.rglob("*"))
    assert not any(p.is_symlink() for p in paths)
    manifest = json.loads((HERE / "MANIFEST.json").read_text())
    files = {p.relative_to(HERE).as_posix() for p in paths
             if p.is_file() and p.name != "MANIFEST.json"}
    assert files == set(manifest["files"]), sorted(files ^ set(manifest["files"]))
    for name, digest in manifest["files"].items():
        assert sha((HERE / name).read_bytes()) == digest, name
    for name, digest in manifest["repository_inputs"].items():
        path = ROOT / name
        assert path.is_file() and not path.is_symlink(), name
        assert sha(path.read_bytes()) == digest, name

    report = json.loads(gzip.decompress((HERE / "runtime/report.json.gz").read_bytes()))
    parts = report["transaction_receipts"]["parts"]
    assert [p["receipts"] for p in parts] == [10] * 7 + [2]
    receipts = []
    for part in parts:
        part_data = (HERE / part["path"]).read_bytes()
        assert sha(part_data) == part["sha256"], part["path"]
        assert len(part_data) < 25 * 1024 * 1024, part["path"]
        receipts += [json.loads(line) for line in gzip.decompress(part_data).splitlines()]
    assert report["case_count"] == len(report["cases"]) == 24
    assert len(receipts) == 72
    assert report["counts"]["vms"] == 72
    assert report["counts"]["transactions"] == 72
    assert report["counts"]["signature_fields"] == sum(
        r["signature_fields"] for r in receipts) == 72
    assert report["mismatches"] == []
    assert report["image_sha256"] == {
        "original": sha((ROOT / "evidence/original/pump_amm/deployed.so").read_bytes()),
        "control": sha(gzip.decompress(CONTROL.read_bytes())),
        "candidate": sha(gzip.decompress(CANDIDATE.read_bytes())),
    }
    for name, digest in report["input_sha256"].items():
        assert sha((ROOT / name).read_bytes()) == digest, name

    for index, row in enumerate(report["cases"]):
        case = row["case"]
        kind = case["expected"]["kind"]
        observed_set = set()
        for image_offset, image in enumerate(IMAGES):
            rec = receipts[index * 3 + image_offset]
            assert rec["sequence"] == rec["vm"] == index * 3 + image_offset
            assert rec["context"] == {"index": index, "image": image,
                                      "instruction": case["instruction"],
                                      "label": case["label"]}
            assert rec["clock"] == {"slot": 100, "epoch_start_timestamp": 1234567890,
                                    "epoch": 0, "leader_schedule_epoch": 0,
                                    "unix_timestamp": 1234567890}
            raw = base64.b64decode(rec["transaction_base64"])
            tx = Transaction.from_bytes(raw)
            checks = tx.verify_with_results()
            assert checks and all(checks) and len(checks) == rec["signature_fields"] == 1
            assert rec["transaction_sha256"] == sha(raw)
            assert rec["all_signatures_verified"] is True
            assert rec["signatures"] == [str(s) for s in tx.signatures]
            assert rec["loaded_programs"]["pAMM"]["sha256"] == report["image_sha256"][image]
            assert rec["error"] == row[image]["error"]
            assert rec["metadata"]["logs"] == row[image]["logs"]
            assert rec["observed"] == row[image]["observed"]
            assert len(rec["metadata"]["events"]) == rec["observed"]["event_count"]
            observed_set.add(json.dumps(rec["observed"], sort_keys=True))
            before, after = rec["before"], rec["after"]
            roles = rec["roles"]
            fee_key = roles["fee_payer"]
            payer_delta = (after[fee_key]["lamports"] if after.get(fee_key) else 0) - \
                          (before[fee_key]["lamports"] if before.get(fee_key) else 0)
            assert payer_delta == rec["payer_delta_lamports"]
            logs = rec["metadata"]["logs"]
            if kind == "hop4":
                got = {name: tok_amount(after, roles[name]) - tok_amount(before, roles[name])
                       for name in WATCH}
                assert got == case["expected"]["deltas"], (case["label"], got)
                assert rec["observed"]["deltas"] == got
                assert rec["error"] is None
                assert payer_delta == -1849400
                vol = after[roles["volume"]]
                assert vol is not None and vol["lamports"] == 1844400
                vol_data = bytes.fromhex(vol["data_hex"])
                assert len(vol_data) == 137
                assert vol_data[8:40] == bytes(Pubkey.from_string(fee_key))
                assert rec["observed"]["event_count"] == 4
            else:
                code = case["expected"]["code"]
                fragment = case["expected"]["fragment"]
                assert rec["error"] is not None and code in rec["error"]
                assert fragment in "\n".join(logs)
                assert payer_delta == -5000
                assert all(before[k] == after[k] for k in before if k != fee_key)
                site = row.get("error_sites", {}).get(image)
                assert site is not None and site in logs, (case["label"], image, site)
                assert ("thrown in" in site or "caused by account" in site)
        assert len(observed_set) == 1, (case["label"], "images disagree")
    print("verify PASS: 24 cases x 3 images = 72 receipts, all checks passed")


if __name__ == "__main__":
    main()
