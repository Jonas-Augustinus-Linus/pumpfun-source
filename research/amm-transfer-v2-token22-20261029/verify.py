"""Verify the retained transfer_v2 Token-2022 receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, fixture) hash to the recorded values;
- 20 cases x 3 images = 60 receipts, ordered, with contexts matching
  the report, stored as 6 parts (10 x 6), each under 25MB;
- every transaction verifies (all signatures valid, 1 signature
  field each);
- all three images agree on every case (identical error and observed
  values), and the recorded logs match the receipts' logs;
- transfer cases: the vault drains by the expected delta, the
  destination gains the expected delta and ends at the expected
  amount, the withheld amount at offset 174 matches (unless the
  destination has no extension, in which case it is 165 bytes),
  the payer pays only the 5,000 fee, and no event is emitted;
- create case: the destination starts missing, ends at the expected
  amount with the expected withheld amount and lamports, the
  payer pays 2,162,600 (ATA creation + fee), and no event is
  emitted;
- error cases: fail with the expected code and log fragment, roll
  back every account except the fee payer's 5,000 fee, and emit no
  event. The 0xd failure is program-level (Token-2022 program) and
  the 11 failure is a Token program close failure, so no
  "thrown in" / "caused by account" site is required for them; the
  2023/2006/6007 failures carry Anchor constraint fragments.
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


def tok_amount(snapshot, key):
    row = snapshot.get(str(key))
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
    assert [p["receipts"] for p in parts] == [10] * 6
    receipts = []
    for part in parts:
        part_data = (HERE / part["path"]).read_bytes()
        assert sha(part_data) == part["sha256"], part["path"]
        assert len(part_data) < 25 * 1024 * 1024, part["path"]
        receipts += [json.loads(line) for line in gzip.decompress(part_data).splitlines()]
    assert report["case_count"] == len(report["cases"]) == 20
    assert len(receipts) == 60
    assert report["counts"]["vms"] == 60
    assert report["counts"]["transactions"] == 60
    assert report["counts"]["signature_fields"] == sum(
        r["signature_fields"] for r in receipts) == 60
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
        observed_set = set()
        for image_offset, image in enumerate(IMAGES):
            rec = receipts[index * 3 + image_offset]
            assert rec["sequence"] == rec["vm"] == index * 3 + image_offset
            assert rec["context"] == {"index": index, "image": image,
                                      "instruction": case["instruction"],
                                      "label": case["label"]}
            assert rec["clock"] == {"slot": 100, "epoch_start_timestamp": 1234567890,
                                    "epoch": case["epoch"], "leader_schedule_epoch": 0,
                                    "unix_timestamp": 1234567890}
            raw = base64.b64decode(rec["transaction_base64"])
            tx = Transaction.from_bytes(raw)
            checks = tx.verify_with_results()
            assert checks and all(checks) and len(checks) == rec["signature_fields"] == 1
            assert rec["transaction_sha256"] == sha(raw)
            assert rec["all_signatures_verified"] is True
            assert rec["signatures"] == [str(s) for s in tx.signatures]
            amm_entries = [v for v in rec["loaded_programs"].values()
                           if v["path"] == "evidence/original/pump_amm/deployed.so"]
            assert len(amm_entries) == 1
            assert amm_entries[0]["sha256"] == report["image_sha256"][image]
            assert rec["error"] == row[image]["error"]
            assert rec["metadata"]["logs"] == row[image]["logs"]
            assert rec["observed"] == row[image]["observed"]
            observed_set.add(json.dumps(rec["observed"], sort_keys=True))
            before, after = rec["before"], rec["after"]
            payer_key = str(tx.message.account_keys[0])
            logs = rec["metadata"]["logs"]
            events = [l for l in logs if l.startswith("Program data: ")]
            # Message account_keys are deduplicated/sorted, so
            # resolve accounts through the compiled instruction's
            # account indices, which preserve metas order.
            ix_accounts = tx.message.instructions[0].accounts
            if case["instruction"].endswith("_v2"):
                vault_key = str(tx.message.account_keys[ix_accounts[7]])
                dest_key = str(tx.message.account_keys[ix_accounts[9]])
            else:
                vault_key = str(tx.message.account_keys[ix_accounts[6]])
                dest_key = None
            if kind == "transfer":
                _, vault_delta, dest_delta, dest_final, withheld, dest_len, exp_payer = \
                    case["expected"]
                assert rec["error"] is None
                assert events == [], (case["label"], image, events)
                assert tok_amount(after, vault_key) - tok_amount(before, vault_key) \
                    == vault_delta, (case["label"], image)
                assert tok_amount(after, dest_key) - tok_amount(before, dest_key) \
                    == dest_delta, (case["label"], image)
                assert tok_amount(after, dest_key) == dest_final, (case["label"], image)
                assert len(bytes.fromhex(after[dest_key]["data_hex"])) == dest_len
                if withheld is None:
                    assert dest_len == 165, (case["label"], image)
                else:
                    got = struct.unpack_from(
                        "<Q", bytes.fromhex(after[dest_key]["data_hex"]), 174)[0]
                    assert got == withheld, (case["label"], image, got)
                assert rec["payer_delta_lamports"] == exp_payer
                assert after[payer_key]["lamports"] - before[payer_key]["lamports"] == -exp_payer
                assert rec["observed"] == {"vault_delta": vault_delta, "dest_delta": dest_delta,
                                           "dest_final": dest_final, "withheld": withheld,
                                           "dest_len": dest_len, "payer_delta": exp_payer,
                                           "events": 0}, (case["label"], rec["observed"])
            elif kind == "create":
                _, vault_delta, dest_final, withheld, dest_len, exp_payer, dest_lamp = \
                    case["expected"]
                assert rec["error"] is None
                assert events == [], (case["label"], image, events)
                assert before[dest_key] is None, (case["label"], image)
                assert tok_amount(after, vault_key) - tok_amount(before, vault_key) \
                    == vault_delta, (case["label"], image)
                assert tok_amount(after, dest_key) == dest_final, (case["label"], image)
                got = struct.unpack_from(
                    "<Q", bytes.fromhex(after[dest_key]["data_hex"]), 174)[0]
                assert got == withheld, (case["label"], image, got)
                assert len(bytes.fromhex(after[dest_key]["data_hex"])) == dest_len
                assert after[dest_key]["lamports"] == dest_lamp, (case["label"], image)
                assert rec["payer_delta_lamports"] == exp_payer
                assert after[payer_key]["lamports"] - before[payer_key]["lamports"] == -exp_payer
                assert rec["observed"] == {"vault_delta": vault_delta, "dest_final": dest_final,
                                           "withheld": withheld, "dest_len": dest_len,
                                           "payer_delta": exp_payer, "dest_lamports": dest_lamp,
                                           "events": 0}, (case["label"], rec["observed"])
            else:
                code = case["expected"][1]
                fragment = case["expected"][2]
                assert rec["error"] is not None and code in rec["error"]
                assert fragment in "\n".join(logs)
                assert events == [], (case["label"], image, events)
                assert rec["payer_delta_lamports"] == 5000
                assert all(before[k] == after[k] for k in before if k != payer_key)
                assert rec["observed"] == {"error": code, "fragment": fragment,
                                           "payer_delta": 5000}
        assert len(observed_set) == 1, (case["label"], "images disagree")
    print("verify PASS: 20 cases x 3 images = 60 receipts, all checks passed")


if __name__ == "__main__":
    main()
