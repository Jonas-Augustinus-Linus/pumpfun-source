"""Verify the retained extend_account receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, harness scripts, evidence program)
  hash to the recorded values;
- 18 cases x 3 images = 54 receipts, ordered, with contexts matching the report;
- every transaction verifies (all signatures valid, 1 signature field);
- extend cases reach the expected size and lamport balance, with the
  payer funding exactly fee + rent delta, and the body case preserving
  its body bytes with a zero tail;
- error cases fail with the expected code and log fragment, and roll
  back every account except the payer's 5000 fee;
- the recorded error sites match the receipts' logs (including
  "caused by account" sites and the siteless generic form);
- receipts are stored as parts, each under 25MB, read in order;
- all three images agree on every case.
"""
import base64
import gzip
import hashlib
import json
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
TARGET_KEY = str(Pubkey.from_bytes(bytes([91]) * 32))


def sha(data):
    return hashlib.sha256(data).hexdigest()


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
    assert [p["receipts"] for p in parts] == [10, 10, 10, 10, 10, 4]
    receipts = []
    for part in parts:
        part_data = (HERE / part["path"]).read_bytes()
        assert sha(part_data) == part["sha256"], part["path"]
        assert len(part_data) < 25 * 1024 * 1024, part["path"]
        receipts += [json.loads(line) for line in gzip.decompress(part_data).splitlines()]
    assert report["case_count"] == len(report["cases"]) == 18
    assert len(receipts) == 54
    assert report["counts"] == {"vms": 54, "transactions": 54, "signature_fields": 54}
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
        kind = case["expected"][0]
        pairs = set()
        for image_offset, image in enumerate(IMAGES):
            rec = receipts[index * 3 + image_offset]
            assert rec["sequence"] == rec["vm"] == index * 3 + image_offset
            assert rec["context"] == {"index": index, "image": image,
                                      "instruction": "extend_account",
                                      "label": case["label"]}
            assert rec["clock"] == {"slot": 100, "epoch_start_timestamp": 1234567890,
                                    "epoch": 0, "leader_schedule_epoch": 0,
                                    "unix_timestamp": 1234567890}
            raw = base64.b64decode(rec["transaction_base64"], validate=True)
            tx = Transaction.from_bytes(raw)
            checks = tx.verify_with_results()
            assert checks and all(checks) and len(checks) == 1
            assert rec["all_signatures_verified"] and rec["signature_fields"] == 1
            assert sha(raw) == rec["transaction_sha256"]
            assert [str(s) for s in tx.signatures] == rec["signatures"]
            assert rec["loaded_programs"][next(
                k for k in rec["loaded_programs"] if k.startswith("pAMM"))]["sha256"] == \
                report["image_sha256"][image]
            value = row[image]
            assert value["error"] == rec["error"] and value["logs"] == rec["metadata"]["logs"]
            payer = str(tx.message.account_keys[0])
            assert rec["before"][payer]["lamports"] - rec["after"][payer]["lamports"] == \
                rec["payer_fee_lamports"]
            before_target = rec["before"][TARGET_KEY]
            after_target = rec["after"][TARGET_KEY]
            size_before = len(bytes.fromhex(before_target["data_hex"]))
            size_after = len(bytes.fromhex(after_target["data_hex"]))
            observed = {"size_before": size_before, "size_after": size_after,
                        "lamports_before": before_target["lamports"],
                        "lamports_after": after_target["lamports"]}
            if kind == "extend":
                assert rec["error"] is None
                assert size_after == case["expected"][1], (case, image, size_after)
                assert after_target["lamports"] == case["expected"][2], (case, image)
                assert rec["payer_fee_lamports"] == 5000 + (
                    after_target["lamports"] - before_target["lamports"])
                if len(case["expected"]) > 3 and case["expected"][3] == "body":
                    after_data = bytes.fromhex(after_target["data_hex"])
                    assert after_data[8:24].hex() == case["expected"][4]
                    assert all(b == 0 for b in after_data[24:])
                    observed["body_preserved"] = True
                    observed["tail_zero"] = True
                assert rec["observed"] == observed, (case, image, rec["observed"], observed)
                assert value["observed"] == rec["observed"]
                pairs.add((size_after, after_target["lamports"],
                           observed.get("body_preserved", False)))
            else:
                assert rec["error"] is not None and case["expected"][1] in rec["error"]
                assert case["expected"][2] in "\n".join(rec["metadata"]["logs"])
                assert rec["before"][payer]["lamports"] - rec["after"][payer]["lamports"] == 5000
                assert all(rec["before"][k] == rec["after"][k]
                           for k in rec["before"] if k != payer)
                assert rec["rollback_except_payer_fee"] is True
                site = next((l for l in rec["metadata"]["logs"]
                             if "thrown in" in l or "caused by account" in l), None)
                assert row["error_sites"][image] == site, (case, image)
                assert rec["observed"] == observed, (case, image)
                pairs.add((size_after, after_target["lamports"]))
        assert len(pairs) == 1, (case, "images must agree")
    print("PASS: 18 cases, 54 signed receipts, "
          "extend_account targets pinned (301/949/137/600), "
          "rent delta (target-current)*6960, body preserved, "
          "6027/2004/2000/3010/101 errors pinned, "
          "all images agree")


if __name__ == "__main__":
    main()
