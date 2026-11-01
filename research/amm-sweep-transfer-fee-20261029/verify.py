"""Verify the retained sweep transfer-fee receipts (no build claimed).

Checks, independently of the producer:
- packet manifest lists exactly the files present, with matching hashes;
- repository inputs (images, harness scripts, fixture) hash to the
  recorded values;
- 21 cases x 3 images = 63 receipts, ordered, with contexts matching
  the report, stored as 7 parts (10 x 6 + 3), each under 25MB;
- every transaction verifies (all signatures valid, 1 signature
  field each);
- all three images agree on every case (identical error and observed
  values), and the recorded logs match the receipts' logs;
- success cases: the recipient ATA amount, vault spend, pool fee
  field, withheld amount, payer delta, event amount/bucket, and ATA
  length match the case's expected values; the event amount is the
  gross accrued amount even when the net gain is smaller;
- no-op cases: no ATA is created, no event is emitted, only the
  5,000 payer fee is charged, everything else rolls back;
- error cases: fail with the expected code and log fragment, roll
  back every account except the fee payer's 5,000 fee, and emit no
  event. These two errors are program-level failures (associated-
  token program / Token-2022 program) with no Anchor site marker,
  so no "thrown in" / "caused by account" site is required for them.
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
    assert [p["receipts"] for p in parts] == [10] * 6 + [3]
    receipts = []
    for part in parts:
        part_data = (HERE / part["path"]).read_bytes()
        assert sha(part_data) == part["sha256"], part["path"]
        assert len(part_data) < 25 * 1024 * 1024, part["path"]
        receipts += [json.loads(line) for line in gzip.decompress(part_data).splitlines()]
    assert report["case_count"] == len(report["cases"]) == 21
    assert len(receipts) == 63
    assert report["counts"]["vms"] == 63
    assert report["counts"]["transactions"] == 63
    assert report["counts"]["signature_fields"] == sum(
        r["signature_fields"] for r in receipts) == 63
    assert report["mismatches"] == []
    assert report["image_sha256"] == {
        "original": sha((ROOT / "evidence/original/pump_amm/deployed.so").read_bytes()),
        "control": sha(gzip.decompress(CONTROL.read_bytes())),
        "candidate": sha(gzip.decompress(CANDIDATE.read_bytes())),
    }
    for name, digest in report["input_sha256"].items():
        assert sha((ROOT / name).read_bytes()) == digest, name

    fixture = json.loads((ROOT / "research/imported-lab/analysis/pump_fun/amm-v2-trade-fixture.json").read_text())
    vaultquote = Pubkey.from_string(fixture["keys"]["pool_quote_token_account"])

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
            # The sweep event is the single 185-byte "Program data:"
            # line (8 disc + 8 timestamp + 5x32 keys + 8 amount +
            # 1 bucket); decode it independently of the producer.
            events = []
            for line in logs:
                if line.startswith("Program data: "):
                    blob = base64.b64decode(line[len("Program data: "):])
                    if len(blob) == 185:
                        events.append({"amount": struct.unpack_from("<Q", blob, 176)[0],
                                       "bucket": blob[184]})
            if kind == "sweep":
                _, ata_amount, vault_spent, fee_left, withheld, payer_delta, \
                    ev_amount, ev_bucket, ata_len = case["expected"]
                assert rec["error"] is None
                # Message account_keys are deduplicated/sorted, so
                # resolve accounts through the compiled instruction's
                # account indices, which preserve metas order:
                # [payer, config, pool, quote, program, vault,
                #  recipient, ata, ...].
                ix_accounts = tx.message.instructions[0].accounts
                ata_key = str(tx.message.account_keys[ix_accounts[7]])
                pool_key = str(tx.message.account_keys[ix_accounts[2]])
                assert after[ata_key] is not None
                assert len(bytes.fromhex(after[ata_key]["data_hex"])) == ata_len
                assert tok_amount(after, ata_key) == ata_amount, \
                    (case["label"], image, tok_amount(after, ata_key))
                assert tok_amount(before, vaultquote) - tok_amount(after, vaultquote) \
                    == vault_spent, (case["label"], image)
                fee_after = struct.unpack_from(
                    "<Q", bytes.fromhex(after[pool_key]["data_hex"]),
                    271 if case["instruction"] == "sweep_protocol_fee" else 279)[0]
                assert fee_after == fee_left, (case["label"], image, fee_after)
                if withheld is None:
                    assert ata_len == 165, (case["label"], image, ata_len)
                elif ata_len >= 182:
                    got = struct.unpack_from(
                        "<Q", bytes.fromhex(after[ata_key]["data_hex"]), 174)[0]
                    assert got == withheld, (case["label"], image, got)
                else:
                    assert withheld == 0, (case["label"], image, withheld)
                assert rec["payer_delta_lamports"] == payer_delta, \
                    (case["label"], image, rec["payer_delta_lamports"])
                assert after[payer_key]["lamports"] - before[payer_key]["lamports"] \
                    == -payer_delta, (case["label"], image)
                assert events == [{"amount": ev_amount, "bucket": ev_bucket}], \
                    (case["label"], image, events)
                obs = rec["observed"]
                assert (obs["ata_amount"], obs["vault_spent"], obs["fee_left"],
                        obs["withheld"], obs["payer_delta"], obs["event_amount"],
                        obs["event_bucket"], obs["ata_len"]) == \
                    (ata_amount, vault_spent, fee_left, withheld, payer_delta,
                     ev_amount, ev_bucket, ata_len), (case["label"], obs)
            elif kind == "noop":
                assert rec["error"] is None
                ix_accounts = tx.message.instructions[0].accounts
                ata_key = str(tx.message.account_keys[ix_accounts[7]])
                assert after[ata_key] is None, (case["label"], image)
                assert events == [], (case["label"], image, events)
                assert rec["payer_delta_lamports"] == case["expected"][1]
                assert all(before[k] == after[k] for k in before if k != payer_key)
                assert rec["observed"] == {"ata_exists": False, "vault_spent": 0,
                                           "payer_delta": case["expected"][1],
                                           "events": 0}
            else:
                code = case["expected"][1]
                fragment = case["expected"][2]
                assert rec["error"] is not None and code in rec["error"]
                assert fragment in "\n".join(logs)
                assert events == [], (case["label"], image, events)
                assert rec["payer_delta_lamports"] == 5000
                assert all(before[k] == after[k] for k in before if k != payer_key)
        assert len(observed_set) == 1, (case["label"], "images disagree")
    print("verify PASS: 21 cases x 3 images = 63 receipts, all checks passed")


if __name__ == "__main__":
    main()
