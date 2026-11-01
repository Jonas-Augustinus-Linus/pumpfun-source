"""Verify the retained transfer v1 native receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, fixture) hash to the recorded values;
- 19 cases x 3 images = 60 receipts (the repeat case contributes
  2 receipts per image, one per call), ordered, with contexts
  matching the report, stored as 6 parts (10 x 6), each under 25MB;
- every transaction verifies (all signatures valid, 1 signature
  field each);
- all three images agree on every case (identical error and observed
  values), and the recorded logs match the receipts' logs;
- success cases: no error, no event, payer pays only the 5,000
  fee, the vault ATA is recreated at exactly 2,039,280 lamports
  with amount 0 and 165 bytes, the authority drains to nothing,
  the pump vault gains exactly the expected delta, and its data
  is unchanged;
- repeat case: the first call matches the success checks with
  the expected delta, the second call's before-state equals the
  first call's after-state and it transfers 0 to the pump vault;
- no-op cases: no error, no event, payer pays only 5,000, every
  account except the payer is unchanged, and the log carries the
  exact "Available fees (...) below minimum transfer amount
  (...):" message;
- error cases: fail with the expected code and log fragment, roll
  back every account except the fee payer's 5,000 fee, and emit no
  event. The 2023 failure is program-level (associated-token
  program) and carries no "caused by account" site; the
  6007/2006/3012 failures carry Anchor constraint fragments.
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
    assert report["case_count"] == len(report["cases"]) == 19
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

    cursor = 0
    for index, row in enumerate(report["cases"]):
        case = row["case"]
        kind = case["expected"][0]
        n_per_image = 2 if kind == "repeat" else 1
        observed_set = set()
        for image in IMAGES:
            prev_after = None
            for stage in range(n_per_image):
                rec = receipts[cursor]
                cursor += 1
                assert rec["sequence"] == rec["vm"] == cursor - 1
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
                if kind == "repeat":
                    assert rec["metadata"]["logs"] == row[image]["stage_logs"][stage]
                    assert rec["error"] is None
                else:
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
                # v1 order: mint, token_program, system, ata, creator,
                # authority, vault_ata, pump_vault, event, program.
                ix_accounts = tx.message.instructions[0].accounts
                auth_key = str(tx.message.account_keys[ix_accounts[5]])
                vault_key = str(tx.message.account_keys[ix_accounts[6]])
                pump_key = str(tx.message.account_keys[ix_accounts[7]])
                if prev_after is not None:
                    assert before == prev_after, (case["label"], image, "repeat chaining")
                prev_after = after
                if kind in ("success", "repeat"):
                    pump_delta = case["expected"][1] if stage == 0 else 0
                    assert rec["error"] is None
                    assert events == [], (case["label"], image, events)
                    assert rec["payer_delta_lamports"] == 5000
                    assert after[payer_key]["lamports"] - before[payer_key]["lamports"] == -5000
                    assert after[auth_key] is None, (case["label"], image, "authority must drain")
                    vafter = after[vault_key]
                    assert vafter is not None, (case["label"], image, "vault ATA recreated")
                    assert vafter["lamports"] == 2039280, (case["label"], image)
                    assert tok_amount(after, vault_key) == 0, (case["label"], image)
                    assert len(bytes.fromhex(vafter["data_hex"])) == 165
                    pb = before[pump_key]
                    pa = after[pump_key]
                    assert pa is not None, (case["label"], image, "pump vault exists after")
                    assert pa["lamports"] - (pb["lamports"] if pb else 0) == pump_delta, \
                        (case["label"], image, stage)
                    if pb is None:
                        assert pa["data_hex"] == "", (case["label"], image)
                    else:
                        assert pa["data_hex"] == pb["data_hex"], (case["label"], image)
                    if stage == 0 and kind == "success":
                        assert before[vault_key]["lamports"] == case["mode"][1]
                        assert tok_amount(before, vault_key) == case["mode"][2]
                elif kind == "noop":
                    _, minimum = case["expected"]
                    assert rec["error"] is None
                    assert events == [], (case["label"], image, events)
                    assert rec["payer_delta_lamports"] == 5000
                    assert all(before[k] == after[k] for k in before if k != payer_key)
                    msg = (f"Available fees ({case['mode'][1]}) below minimum transfer "
                           f"amount ({minimum}):")
                    assert any(msg in l for l in logs), (case["label"], image)
                    assert before[vault_key]["lamports"] == case["mode"][1]
                    assert tok_amount(before, vault_key) == case["mode"][2]
                else:
                    code = case["expected"][1]
                    fragment = case["expected"][2]
                    assert rec["error"] is not None and code in rec["error"]
                    assert fragment in "\n".join(logs)
                    assert events == [], (case["label"], image, events)
                    assert rec["payer_delta_lamports"] == 5000
                    assert all(before[k] == after[k] for k in before if k != payer_key)
                assert rec["observed"] == row[image]["observed"]
        assert len(observed_set) == 1, (case["label"], "images disagree")
    assert cursor == len(receipts) == 60
    print("verify PASS: 19 cases x 3 images = 60 receipts, all checks passed")


if __name__ == "__main__":
    main()
