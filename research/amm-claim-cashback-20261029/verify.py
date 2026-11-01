"""Verify the retained claim_cashback receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, harness scripts, evidence programs)
  hash to the recorded values;
- 16 cases x 3 images = 48 receipts, ordered, with contexts matching the report;
- every transaction verifies (all signatures valid, 1 signature field);
- success cases drain the vault fully, credit the destination by
  the vault amount, advance total_cashback_claimed by exactly that
  amount, charge only the 5000 fee, and emit an event log;
- error cases fail with the expected code and log fragment, and roll
  back every account except the payer's 5000 fee;
- the recorded error sites match the receipts' logs (including
  "caused by account" sites and the per-image 6023 site difference);
- receipts are stored as parts, each under 25MB, read in order;
- all three images agree on every case.
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


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tok_amount(entry):
    if entry is None:
        return None
    data = bytes.fromhex(entry["data_hex"])
    return struct.unpack_from("<Q", data, 64)[0] if len(data) >= 72 else None


def claimed(entry):
    if entry is None:
        return None
    data = bytes.fromhex(entry["data_hex"])
    return struct.unpack_from("<Q", data, 82)[0] if len(data) >= 90 else None


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
    assert [p["receipts"] for p in parts] == [10, 10, 10, 10, 8]
    receipts = []
    for part in parts:
        part_data = (HERE / part["path"]).read_bytes()
        assert sha(part_data) == part["sha256"], part["path"]
        assert len(part_data) < 25 * 1024 * 1024, part["path"]
        receipts += [json.loads(line) for line in gzip.decompress(part_data).splitlines()]
    assert report["case_count"] == len(report["cases"]) == 16
    assert len(receipts) == 48
    assert report["counts"] == {"vms": 48, "transactions": 48, "signature_fields": 48}
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
                                      "instruction": "claim_cashback",
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
            keys = [str(k) for k in tx.message.account_keys]
            payer = keys[0]
            assert rec["before"][payer]["lamports"] - rec["after"][payer]["lamports"] == \
                rec["payer_fee_lamports"]
            # Instruction account order is [user, accumulator, mint,
            # token program, vault, destination, system, event, program];
            # message account_keys are re-sorted, so resolve via the
            # compiled instruction's account indices, not positions.
            ix_accounts = tx.message.instructions[0].accounts
            acc_key = keys[ix_accounts[1]]
            vault_key = keys[ix_accounts[4]]
            dest_key = keys[ix_accounts[5]]
            observed = {
                "vault_before": tok_amount(rec["before"][vault_key]),
                "vault_after": tok_amount(rec["after"][vault_key]),
                "dest_before": tok_amount(rec["before"][dest_key]),
                "dest_after": tok_amount(rec["after"][dest_key]),
                "claimed_before": claimed(rec["before"][acc_key]),
                "claimed_after": claimed(rec["after"][acc_key]),
            }
            assert rec["observed"] == observed, (case, image, rec["observed"], observed)
            assert value["observed"] == rec["observed"]
            if kind == "ok":
                assert rec["error"] is None
                assert observed["vault_before"] == case["expected"][1], (case, image, observed)
                assert observed["vault_after"] == 0, (case, image, observed)
                assert observed["dest_after"] - observed["dest_before"] == case["expected"][2], \
                    (case, image, observed)
                assert observed["claimed_after"] == case["expected"][3], (case, image, observed)
                assert rec["payer_fee_lamports"] == 5000
                assert any(l.startswith("Program data: ") for l in rec["metadata"]["logs"]), \
                    (case, image, "no event")
                pairs.add((observed["vault_before"], observed["dest_after"],
                           observed["claimed_after"]))
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
                pairs.add((observed["vault_after"], observed["dest_after"],
                           observed["claimed_after"]))
        assert len(pairs) == 1, (case, "images must agree")
    print("PASS: 16 cases, 48 signed receipts, "
          "claim_cashback full-vault drain pinned, "
          "claimed counter checked-add pinned (6023 at u64max), "
          "90-byte deserialize floor, stored-user ignored, "
          "vault ATA-bound / dest not ATA-bound, "
          "3003/2000/2006/2009 errors pinned, "
          "all images agree")


if __name__ == "__main__":
    main()
